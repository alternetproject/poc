import time

from .client import fetch
from .discovery import request_contacts
from .lab import DEMO_BODY, Lab


def run() -> None:
    with Lab() as lab:
        nodes = [lab.start_node(lab.config(f"R{index}")) for index in range(8)]
        _, first_url = lab.start_discovery("entry-1", tuple(node.address for node in nodes[:4]))
        _, second_url = lab.start_discovery("entry-2", tuple(node.address for node in nodes[4:]))
        client = lab.discovery_client((first_url, second_url))

        def check(label, config=client):
            result = fetch(config, lab.url, ca_file=str(lab.ca))
            if result.status != 200 or result.body != DEMO_BODY:
                raise RuntimeError(f"{label} failed")
            print(f"PASS {label}: route={' -> '.join(result.route)}", flush=True)
            return result

        check("initial_discovery")
        disclosed = set()
        for url in (first_url, second_url):
            learned = set()
            for _ in range(20):
                learned.update(request_contacts(url, str(lab.ca), time.monotonic() + 2)["peers"])
            if len(learned) != 3:
                raise RuntimeError("repeated queries changed a fixed contact assignment")
            disclosed.update(learned)
        print("PASS disclosure_limit: queries=40 contacts_per_service=3", flush=True)

        stopped = []
        for index, node in enumerate(nodes):
            if str(node.address) in disclosed:
                node.stop()
                stopped.append(f"R{index}")
        result = check("relay_failover")
        if "entry-1" not in result.route:
            raise RuntimeError("expected fallback through a public HTTPS entry")
        lab.services["entry-1"].stop()
        result = check("service_failover")
        if "entry-2" not in result.route:
            raise RuntimeError("expected independent second entry")

        lab.start_node(lab.configs[stopped[0]])
        lab.services["entry-2"].stop()
        result = check("cached_relay")
        if not any(name.startswith("R") for name in result.route):
            raise RuntimeError("expected recovery through a cached relay")
