from dataclasses import replace
import time

from .client import fetch
from .lab import DEMO_BODY, Lab
from .peer_discovery import PeerDiscovery, query


def wait_for(address, name: str, *, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = query(address, deadline)
        for peer in data["peers"]:
            try:
                if query(peer, deadline)["name"] == name:
                    return peer
            except (OSError, ValueError):
                pass
        time.sleep(0.05)
    raise AssertionError(f"{name} did not join via {address}")


def run():
    with Lab() as lab:
        seed = lab.start_node(lab.config("seed", relay=False))
        relay = lab.start_node(replace(lab.config("R"), bootstrap=(seed.address,)))
        wait_for(seed.address, "R")
        client = replace(lab.config("A", blocked=True), bootstrap=(seed.address,),
                         peer_cache=str(lab.directory / "A.peers.sqlite"))

        first = fetch(client, lab.url, ca_file=str(lab.ca))
        assert first.route == ("A", "R") and first.body == DEMO_BODY
        print("PASS peer_discovery", flush=True)

        seed.stop()
        cached = fetch(client, lab.url, ca_file=str(lab.ca))
        assert cached.route == ("A", "R") and cached.body == first.body
        print("PASS cached_contacts", flush=True)

        late = lab.start_node(replace(lab.config("late"), bootstrap=(relay.address,)))
        wait_for(relay.address, "late")
        manager = PeerDiscovery(client)
        try:
            manager.refresh(time.monotonic() + 8, force=True)
            assert any(p["name"] == "late" for p in manager.book.live())
        finally:
            manager.close()
        relay.stop()
        recovered = fetch(client, lab.url, ca_file=str(lab.ca))
        assert recovered.route == ("A", "late") and recovered.body == first.body
        print("PASS late_join", flush=True)

        newcomer = replace(lab.config("newcomer", blocked=True, relay=False), bootstrap=(late.address,))
        result = fetch(newcomer, lab.url, ca_file=str(lab.ca))
        assert result.route == ("newcomer", "late") and result.body == first.body
        print("PASS relay_opt_out", flush=True)
