from contextlib import ExitStack
from dataclasses import dataclass, field, replace
import ipaddress
import json
import logging
from pathlib import Path
import time
from urllib.parse import urlsplit

from alternet.client import fetch
from alternet.config import Address
from alternet.http_carrier import MAX_POST_ATTEMPTS, PROFILE
from alternet.lab import Lab
from .wire_filter import WireFilter

HOSTS = ("127.0.0.11", "127.0.0.12", "127.0.0.13",
         "127.0.1.21", "127.0.1.22", "127.0.1.23")
DOWNLOAD = bytes(range(256)) * 256
PAGE = b"<!doctype html><title>Ordinary fixture</title><p>Ordinary page.</p>\n"


@dataclass
class Censor:
    blocked_ips: set[str] = field(default_factory=set)
    prefix: str | None = None
    all_tls: bool = False
    rate: int | None = None
    lifetime: float | None = None

    def blocks(self, host, hello):
        return (host in self.blocked_ips
                or (self.prefix is not None and ipaddress.ip_address(host) in ipaddress.ip_network(self.prefix))
                or (self.all_tls and hello.tls))

    def learn(self, probe_result):
        for url in probe_result["entries"]:
            self.blocked_ips.add(urlsplit(url).hostname)

    def install(self, filters):
        for wire in filters:
            wire.rule = lambda hello, host=wire.address.host: self.blocks(host, hello)
            wire.rate_bytes_per_second = self.rate
            wire.next_byte_at = 0.0
            wire.connection_lifetime = self.lifetime

    def describe(self):
        return {"blocked_ips": sorted(self.blocked_ips), "blocked_prefix": self.prefix,
                "block_all_tls": self.all_tls, "aggregate_bytes_per_second_per_endpoint": self.rate,
                "connection_lifetime_seconds": self.lifetime}


def session(ca):
    from curl_cffi.requests import Session
    return Session(impersonate=PROFILE, verify=str(ca), trust_env=False, default_headers=False)


def probe(urls, ca):
    started = time.monotonic()
    entries, non_relays, errors = [], [], []
    with session(ca) as client:
        for url in urls:
            try:
                response = client.get(url + "/v1/peers", timeout=2, allow_redirects=False)
                try:
                    if response.status_code != 200 or len(response.content) > 16384:
                        raise ValueError("invalid discovery response")
                    data = response.json()
                    if (not isinstance(data, dict) or type(data.get("version")) is not int
                            or data["version"] != 1 or type(data.get("gateway")) is not bool):
                        raise ValueError("invalid relay advertisement")
                    (entries if data["gateway"] else non_relays).append(url)
                finally:
                    response.close()
            except Exception as exc:
                from curl_cffi.requests.exceptions import RequestException
                if not isinstance(exc, (RequestException, OSError, ValueError)):
                    raise
                errors.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
    return {"attempts": len(urls), "entries": entries, "non_relays": non_relays,
            "errors": errors, "elapsed_seconds": time.monotonic() - started}


def attempt(operation, expected):
    started = time.monotonic()
    error = None
    try:
        body = operation()
        if body != expected:
            raise ValueError("response body differs from expected origin content")
        completed = True
    except Exception as exc:
        import http.client
        from curl_cffi.requests.exceptions import RequestException
        if not isinstance(exc, (RequestException, OSError, ValueError, http.client.HTTPException)):
            raise
        completed = False
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.monotonic() - started
    useful = len(expected) if completed else 0
    return {"completed": completed, "elapsed_seconds": elapsed, "completed_body_bytes": useful,
            "completed_body_bytes_per_second": useful / max(elapsed, 0.000001), "error": error}


def summarize(samples):
    elapsed = sum(item["elapsed_seconds"] for item in samples)
    useful = sum(item["completed_body_bytes"] for item in samples)
    return {"attempts": len(samples), "completed": sum(item["completed"] for item in samples),
            "elapsed_seconds": elapsed, "completed_body_bytes": useful,
            "completed_body_bytes_per_second": useful / max(elapsed, 0.000001)}


def settle(filters, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        active = False
        for wire in filters:
            with wire.lock:
                active |= bool(wire.active)
        if not active:
            return
        time.sleep(0.02)
    raise RuntimeError("experiment still has active connections between phases")


def verdict(rows):
    by_name = {row["name"]: row for row in rows}
    frozen = by_name["replacement_before_rescan"]
    updated = by_name["replacement_after_rescan"]
    independent = updated["ordinary"]["independent"]
    if (frozen["alternet"]["completed"] > 0 and updated["alternet"]["completed"] == 0
            and independent["completed"] == independent["attempts"]
            and updated["wire"]["rejected_connections"] > 0):
        return {"hypothesis": "rejected_in_this_experiment", "witness": updated["name"]}
    return {"hypothesis": "inconclusive", "witness": None}


def experiment(*, trials=2):
    if type(trials) is not int or not 1 <= trials <= 5:
        raise ValueError("trials must be an integer from one to five")
    report = {
        "version": 1,
        "trials_per_phase": trials, "download_bytes": len(DOWNLOAD), "page_bytes": len(PAGE),
        "carrier_max_post_attempts": MAX_POST_ATTEMPTS,
        "rows": [], "endpoints": [],
    }
    with ExitStack() as stack:
        lab = stack.enter_context(Lab(body=DOWNLOAD, cert_extra_hosts=HOSTS))
        roots, filters = [], []
        enabled = [True, True, False, False, False, False]
        for index, host in enumerate(HOSTS):
            root = lab.directory / f"site-{index}"
            root.mkdir()
            (root / "index.html").write_bytes(PAGE)
            (root / "download.bin").write_bytes(DOWNLOAD)
            roots.append(root)
            backend, _ = lab.start_discovery(f"site-{index}", (), relay=enabled[index], site_root=str(root))
            wire = stack.enter_context(WireFilter(backend.address, listen=Address(host, 0)))
            filters.append(wire)
            report["endpoints"].append({"url": wire.url, "ip": host,
                                         "ordinary_group": "peer_sites" if index < 3 else "independent"})
        urls = tuple(wire.url for wire in filters)
        known = set()

        def phase(name, policy, *, attacker_probe=None, activation=None):
            settle(filters)
            policy.install(filters)
            before = [(len(w.observations), w.lifetime_blocks, w.volume_blocks) for w in filters]
            discovery = probe(urls, lab.ca)
            known.update(discovery["entries"])
            known.difference_update(discovery["non_relays"])
            if not known:
                raise RuntimeError("no entry was discovered even in the initial control")
            config = replace(lab.discovery_client(tuple(sorted(known))), gateway_only=True, gateway_transport="curl")
            samples, ordinary = [], []
            recovery = None
            for _ in range(trials):
                sample = attempt(lambda: fetch(config, lab.url, ca_file=str(lab.ca)).body, DOWNLOAD)
                samples.append(sample)
                if activation is not None and sample["completed"] and recovery is None:
                    recovery = time.monotonic() - activation

                with session(lab.ca) as client:
                    for index, url in enumerate(urls):
                        for path, body, kind in (("/", PAGE, "page"), ("/download.bin", DOWNLOAD, "download")):
                            def ordinary_get(url=url, path=path):
                                response = client.get(url + path, timeout=5, allow_redirects=False)
                                try:
                                    if response.status_code != 200:
                                        raise ValueError(f"ordinary HTTPS status {response.status_code}")
                                    return response.content
                                finally:
                                    response.close()
                            ordinary.append({"url": url, "kind": kind,
                                             "group": "peer_sites" if index < 3 else "independent",
                                             **attempt(ordinary_get, body)})
            settle(filters)
            rejected = lifetimes = volume = 0
            for wire, (position, old_life, old_volume) in zip(filters, before):
                rejected += sum(blocked for _, blocked in wire.observations[position:])
                lifetimes += wire.lifetime_blocks - old_life
                volume += wire.volume_blocks - old_volume
            row = {"name": name, "policy": policy.describe(), "client_discovery": discovery,
                   "attacker_probe": attacker_probe, "client_cached_entries": sorted(known),
                   "alternet": summarize(samples), "alternet_samples": samples,
                   "ordinary": {group: summarize([s for s in ordinary if s["group"] == group])
                                for group in ("peer_sites", "independent")},
                   "ordinary_by_size": {kind: summarize([s for s in ordinary if s["kind"] == kind])
                                        for kind in ("page", "download")},
                   "ordinary_samples": ordinary, "recovery_seconds_from_activation": recovery,
                   "wire": {"rejected_connections": rejected, "timed_disconnects": lifetimes,
                            "byte_budget_disconnects": volume}}
            report["rows"].append(row)
            return row

        baseline = phase("baseline", Censor())
        if (baseline["alternet"]["completed"] != trials
                or any(item["completed"] != item["attempts"] for item in baseline["ordinary"].values())):
            raise RuntimeError("baseline failed; blocking results would not be interpretable")
        attacker = probe(urls, lab.ca)
        snapshot = Censor()
        snapshot.learn(attacker)
        if len(snapshot.blocked_ips) != 2:
            raise RuntimeError("public probing did not identify the two initially enabled entries")
        phase("known_entries_blocked", snapshot, attacker_probe=attacker)

        activated = time.monotonic()
        lab.start_discovery("site-2", (), relay=True, site_root=str(roots[2]))
        lab.start_discovery("site-0", (), relay=False, site_root=str(roots[0]))
        phase("replacement_before_rescan", snapshot, activation=activated)

        refreshed = probe(urls, lab.ca)
        snapshot.learn(refreshed)
        phase("replacement_after_rescan", snapshot, attacker_probe=refreshed)

        backend_urls = tuple(f"https://localhost:{lab.services[f'site-{i}'].address.port}" for i in (1, 2))
        diagnostic = replace(lab.discovery_client(backend_urls, name="diagnostic"),
                             gateway_only=True, gateway_transport="curl")
        health = attempt(lambda: fetch(diagnostic, lab.url, ca_file=str(lab.ca)).body, DOWNLOAD)
        if not health["completed"]:
            raise RuntimeError("relay/origin health check failed; cannot attribute failure to entry blocking")
        report["uncensored_diagnostic"] = health

        phase("peer_prefix_blocked", Censor(prefix="127.0.0.0/24"))
        phase("all_tls_blocked", Censor(all_tls=True))
        phase("aggregate_rate_64_KiB_s", Censor(rate=64 * 1024))
        phase("connections_cut_at_200_ms", Censor(lifetime=0.2))
        phase("restored", Censor())
        report["result"] = verdict(report["rows"])
    return report


def run(*, as_json=False, output=None, trials=2):
    logger = logging.getLogger("alternet")
    previous = logger.level
    logger.setLevel(logging.WARNING)
    try:
        report = experiment(trials=trials)
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
        print("Phase                           Alternet  Peer sites  Independent sites")
        for row in report["rows"]:
            values = [row["alternet"], row["ordinary"]["peer_sites"], row["ordinary"]["independent"]]
            counts = [f"{value['completed']}/{value['attempts']}" for value in values]
            print(f"{row['name']:31} {counts[0]:>8}  {counts[1]:>10}  {counts[2]:>17}")
        print("RESULT: " + report["result"]["hypothesis"])

        if output:
            print(f"output={Path(output).resolve()}")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Measure route replacement under address and transport filtering.')
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--trials", type=int, default=2)
    args = parser.parse_args()
    run(as_json=args.json, output=args.output, trials=args.trials)
