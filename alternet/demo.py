from .client import fetch
from .lab import DEMO_BODY, Lab


def run() -> None:
    with Lab() as lab:
        c = lab.start_node(lab.config("C"))
        b = lab.start_node(lab.config("B", peers=(c.address,), blocked=True))
        scenarios = [
            ("direct", lab.config("A", peers=(b.address, c.address)), ("A",)),
            ("one relay", lab.config("A", peers=(c.address,), blocked=True), ("A", "C")),
            ("two relays", lab.config("A", peers=(b.address, c.address), blocked=True), ("A", "B", "C")),
        ]
        for label, config, expected_route in scenarios:
            lab.start_node(config)
            result = fetch(lab.configs["A"], lab.url, ca_file=str(lab.ca))
            if result.status != 200 or result.body != DEMO_BODY or result.route != expected_route:
                raise RuntimeError(f"{label} failed: status={result.status}, route={result.route}")
            print(f"PASS {label}: route={' -> '.join(result.route)} bytes={len(result.body)}", flush=True)
