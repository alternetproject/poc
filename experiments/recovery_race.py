from contextlib import ExitStack
from dataclasses import replace
import json
import logging
from pathlib import Path
import threading
import time

from alternet.client import fetch
from alternet.config import Address
from alternet.lab import Lab
from .entry_resilience import DOWNLOAD, PAGE, attempt, probe, session
from .wire_filter import WireFilter

HOSTS = ("127.0.2.11", "127.0.2.12", "127.0.3.13", "127.0.3.14",
         "127.0.2.21", "127.0.3.22")
MODES = {"unfiltered": None, "frozen": None,
         "continuous_slow": 0.6, "continuous_fast": 0.02}


class PersistentBlocks:
    def __init__(self, wires):
        self.hosts = frozenset()
        self.wires = wires
        self.lock = threading.Lock()
        self.disconnected_sockets = 0
        for wire in wires:
            wire.rule = lambda hello, host=wire.address.host: host in self.hosts

    def learn(self, urls):
        from urllib.parse import urlsplit
        with self.lock:
            added = frozenset(urlsplit(url).hostname for url in urls) - self.hosts
            self.hosts = self.hosts | added
            for wire in self.wires:
                if wire.address.host in added:
                    self.disconnected_sockets += wire.disconnect_active()
            return sorted(added)


def window_summary(samples, start, end):
    started = [s for s in samples if start <= s["start"] < end]
    completed = [s for s in samples if s["completed"] and start <= s["end"] <= end]
    times = [start, *sorted(s["end"] for s in completed), end]
    latencies = sorted(s["elapsed_seconds"] for s in started if s["end"] <= end)
    return {"window_seconds": end - start, "attempts_started": len(started),
            "successful_completions": len(completed),
            "failures_completed": sum(not s["completed"] and s["end"] <= end for s in started),
            "in_flight_at_end": sum(s["end"] > end for s in started),
            "completed_body_bytes": sum(s["completed_body_bytes"] for s in completed),
            "useful_bytes_per_wall_second": sum(s["completed_body_bytes"] for s in completed) / (end - start),
            "longest_completion_gap_seconds": max(b - a for a, b in zip(times, times[1:])),
            "attempt_latency_p95_seconds": latencies[min(len(latencies) - 1, int(len(latencies) * .95))]
            if latencies else None}


def assess(row):
    tail = row["summaries"]["alternet"]["tail"]["successful_completions"]
    if not row["uncensored_diagnostic"]["completed"]:
        return "invalid_origin_or_relay_control"
    if tail:
        return "useful_traffic_observed_in_final_window"
    if not row["final_unblocked_active_ips"]:
        return "all_remaining_active_addresses_blocked"
    return "unblocked_active_peer_exists_but_no_final_window_completion"


def _get(url, ca):
    with session(ca) as client:
        response = client.get(url + "/download.bin", timeout=2, allow_redirects=False)
        try:
            if response.status_code != 200:
                raise ValueError(f"ordinary HTTPS status {response.status_code}")
            return response.content
        finally:
            response.close()


def scenario(mode, *, step_seconds=2.0, rounds=6, tail_seconds=5.0, peer_count=4,
             client_policy="supplied"):
    if mode not in MODES:
        raise ValueError("unknown censor mode")
    if not 0.5 <= step_seconds <= 10 or type(rounds) is not int or not 4 <= rounds <= 12:
        raise ValueError("require step_seconds in [0.5, 10] and rounds in [4, 12]")
    if not 2 <= tail_seconds <= 15:
        raise ValueError("tail_seconds must be in [2, 15]")
    if type(peer_count) is not int or not 4 <= peer_count <= 16:
        raise ValueError("peer_count must be an integer in [4, 16]")
    if client_policy not in ("supplied", "advertised"):
        raise ValueError("client_policy must be supplied or advertised")
    hosts = (HOSTS[:4] + tuple(f"127.0.{4 + i // 8}.{30 + i % 8}" for i in range(peer_count - 4))
             + HOSTS[4:])
    with ExitStack() as stack:
        lab = stack.enter_context(Lab(body=DOWNLOAD, cert_extra_hosts=hosts))
        wires, roots = [], []
        enabled = {0, 1}
        for i, host in enumerate(hosts):
            root = lab.directory / f"ordinary-{i}"
            root.mkdir()
            (root / "index.html").write_bytes(PAGE)
            (root / "download.bin").write_bytes(DOWNLOAD)
            roots.append(root)
            child, _ = lab.start_discovery(f"peer-{i}", (), relay=i in enabled, site_root=str(root))
            wires.append(stack.enter_context(WireFilter(child.address, listen=Address(host, 0))))
        urls = tuple(w.url for w in wires)
        initial = probe(urls, lab.ca)
        if len(initial["entries"]) != 2 or initial["errors"]:
            raise RuntimeError("initial public discovery failed")

        def config(candidates, name):
            return replace(lab.discovery_client(tuple(candidates), name=name),
                           gateway_only=True, gateway_transport="curl")

        baseline = attempt(lambda: fetch(config(initial["entries"], "baseline"), lab.url,
                                         ca_file=str(lab.ca)).body, DOWNLOAD)
        ordinary_baseline = [attempt(lambda url=url: _get(url, lab.ca), DOWNLOAD) for url in urls]
        if not baseline["completed"] or not all(s["completed"] for s in ordinary_baseline):
            raise RuntimeError("unblocked control failed")

        policy = PersistentBlocks(wires)
        stop = threading.Event()
        lock = threading.Lock()
        workers, errors, events, samples, discoveries = [], [], [], [], []
        known = set(initial["entries"])
        started = time.monotonic()

        def now():
            return time.monotonic() - started

        def record(kind, **values):
            with lock:
                events.append({"time": now(), "kind": kind, **values})

        def worker(name, action):
            def guarded():
                try:
                    action()
                except BaseException as exc:
                    with lock:
                        errors.append(f"{name}: {type(exc).__name__}: {exc}")
                    stop.set()
            thread = threading.Thread(target=guarded, name=name, daemon=True)
            workers.append(thread)
            thread.start()

        def discovery():
            cursor = 0
            while not stop.is_set():
                url = urls[cursor % len(urls)]
                cursor += 1
                result = probe((url,), lab.ca)
                with lock:
                    known.update(result["entries"])
                    known.difference_update(result["non_relays"])
                    discoveries.append({"time": now(), **result})
                stop.wait(.08)

        def workload(client_id):
            cursor = client_id
            while not stop.is_set():
                with lock:
                    candidates = sorted(known)
                if candidates:
                    offset = cursor % len(candidates)
                    candidates = candidates[offset:] + candidates[:offset]
                if client_policy == "supplied":
                    hints = [url for url in urls if url not in candidates]
                    offset = cursor % max(1, len(hints))
                    candidates += hints[offset:] + hints[:offset]
                cursor += 1
                route = []
                def get():
                    if not candidates:
                        raise ConnectionError("no discovered relay candidates")
                    result = fetch(config(candidates, f"client-{client_id}"), lab.url, ca_file=str(lab.ca))
                    route.extend(result.route)
                    if result.status != 200:
                        raise ValueError(f"origin HTTPS status {result.status}")
                    return result.body
                beginning = now()
                result = attempt(get, DOWNLOAD)
                with lock:
                    samples.append({"kind": "alternet", "client": client_id, "start": beginning,
                                    "end": now(), "route": route, **result})
                stop.wait(.1)

        def ordinary(index):
            while not stop.is_set():
                beginning = now()
                result = attempt(lambda: _get(urls[index], lab.ca), DOWNLOAD)
                with lock:
                    samples.append({"kind": "peer_site" if index < peer_count else "independent_site",
                                    "site": index, "start": beginning, "end": now(), **result})
                stop.wait(.25)

        def attack():
            cursor = 0
            while not stop.is_set():
                index = cursor % len(urls)
                cursor += 1

                if hosts[index] not in policy.hosts:
                    result = probe((urls[index],), lab.ca)
                    added = policy.learn(result["entries"])
                    record("censor_probe", result=result, added_ips=added,
                           blocked_ips=sorted(policy.hosts))
                stop.wait(MODES[mode])

        if mode != "unfiltered":
            added = policy.learn(initial["entries"])
            record("initial_blocks", added_ips=added, blocked_ips=sorted(policy.hosts))
        worker("client-discovery", discovery)
        for i in range(2):
            worker(f"client-{i}", lambda i=i: workload(i))
        for i in range(len(urls)):
            worker(f"ordinary-{i}", lambda i=i: ordinary(i))
        if MODES[mode] is not None:
            worker("censor", attack)
        tail_start = None
        try:
            for step in range(rounds):
                if stop.wait(step_seconds):
                    break
                desired = {(step + 1) % peer_count, (step + 2) % peer_count}

                for index in sorted(desired - enabled):
                    lab.start_discovery(f"peer-{index}", (), relay=True, site_root=str(roots[index]))
                    record("relay_enabled", site=index, url=urls[index],
                           already_blocked=hosts[index] in policy.hosts)
                for index in sorted(enabled - desired):
                    lab.start_discovery(f"peer-{index}", (), relay=False, site_root=str(roots[index]))
                    record("relay_disabled", site=index, url=urls[index])
                enabled = desired
            tail_start = now()
            record("participation_changes_finished")
            stop.wait(tail_seconds)
        finally:
            ended = now()
            stop.set()

            deadline = time.monotonic() + 40
            for thread in workers:
                thread.join(max(0, deadline - time.monotonic()))
            if any(thread.is_alive() for thread in workers):
                for wire in wires:
                    wire.disconnect_active()
                for thread in workers:
                    thread.join(2)
                raise RuntimeError("recovery experiment worker exceeded shutdown budget")
        if errors:
            raise RuntimeError("; ".join(errors))

        summaries = {}
        for kind in ("alternet", "peer_site", "independent_site", "ordinary_all"):
            values = [s for s in samples if s["kind"] == kind
                      or (kind == "ordinary_all" and s["kind"] != "alternet")]
            summaries[kind] = {"whole": window_summary(values, 0, ended),
                               "tail": window_summary(values, tail_start, ended)}
        clients = {str(i): {**window_summary([s for s in samples if s.get("client") == i], 0, ended),
                           "tail": window_summary([s for s in samples if s.get("client") == i], tail_start, ended)}
                   for i in range(2)}

        index = min(enabled)
        diagnostic_url = f"https://localhost:{lab.services[f'peer-{index}'].address.port}"
        diagnostic = attempt(lambda: fetch(config((diagnostic_url,), "diagnostic"), lab.url,
                                           ca_file=str(lab.ca)).body, DOWNLOAD)
        if not diagnostic["completed"]:
            raise RuntimeError("uncensored diagnostic failed")
        final_active = sorted(hosts[i] for i in enabled)
        final_unblocked = sorted(set(final_active) - policy.hosts)
        return {"mode": mode, "probe_interval_seconds": MODES[mode], "peer_count": peer_count,
                "client_policy": client_policy,
                "elapsed_seconds": ended, "tail_start_seconds": tail_start,
                "step_seconds": step_seconds, "rounds": rounds,
                "candidate_urls": urls, "initial_discovery": initial,
                "baseline": baseline, "ordinary_baseline": ordinary_baseline,
                "blocked_ips": sorted(policy.hosts), "events": sorted(events, key=lambda e: e["time"]),
                "summaries": summaries, "clients": clients, "samples": samples,
                "client_discovery": discoveries, "uncensored_diagnostic": diagnostic,
                "final_active_ips": final_active, "final_unblocked_active_ips": final_unblocked,
                "final_known_client_urls": sorted(known),
                "active_sockets_disconnected": policy.disconnected_sockets,
                "wire_rejections": sum(sum(blocked for _, blocked in w.observations) for w in wires)}


def experiment(*, modes=tuple(MODES), step_seconds=2.0, rounds=6, tail_seconds=5.0, peer_count=4,
               client_policy="supplied"):
    reports = []
    for mode in modes:
        row = scenario(mode, step_seconds=step_seconds, rounds=rounds, tail_seconds=tail_seconds,
                       peer_count=peer_count, client_policy=client_policy)
        row["finding"] = assess(row)
        reports.append(row)
    return {"version": 1, "scenarios": reports}


def run(*, output=None, as_json=False, modes=tuple(MODES), step_seconds=2.0, rounds=6, tail_seconds=5.0,
        peer_count=4, client_policy="supplied"):
    logger = logging.getLogger("alternet")
    previous = logger.level
    logger.setLevel(logging.WARNING)
    try:
        report = experiment(modes=modes, step_seconds=step_seconds, rounds=rounds, tail_seconds=tail_seconds,
                            peer_count=peer_count, client_policy=client_policy)
    finally:
        logger.setLevel(previous)
    serialized = json.dumps(report, indent=2)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(serialized + "\n", encoding="utf-8")
    if as_json:
        print(serialized)
    else:
        print("Mode                 Total bodies  Tail bodies  Peer-site tail  Independent tail  Blocked IPs")
        for row in report["scenarios"]:
            sums = row["summaries"]
            print(f"{row['mode']:21} {sums['alternet']['whole']['successful_completions']:12} "
                  f"{sums['alternet']['tail']['successful_completions']:12} "
                  f"{sums['peer_site']['tail']['successful_completions']:14} "
                  f"{sums['independent_site']['tail']['successful_completions']:17} {len(row['blocked_ips']):12}")
            print("  " + row["finding"])

    return report
