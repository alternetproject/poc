from dataclasses import replace
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import pytest
from unittest.mock import patch

from alternet.client import fetch
from alternet.config import Address, Config
from alternet.lab import DEMO_BODY, Lab
from alternet.node import RelayServer
from alternet.peer_demo import wait_for
from alternet.peer_discovery import (BUNDLE, CAPACITY, LEASE, PATH, PeerBook, PeerDiscovery,
                                    query, validate_payload)
from alternet.routing import RouteError, read_headers, send_headers


class TestPeerBook:
    def test_gossip_cannot_admit_or_renew_a_contact(self):
        with PeerBook() as book:
            peer = Address("127.0.0.1", 8080)
            book.hint(peer)
            assert book.live() == []
            book.success(peer, "R", True, now=100)
            assert len(book.live(now=101, relays_only=True)) == 1
            book.hint(peer)
            assert book.live(now=100 + LEASE) == []

    def test_failed_probe_removes_contact_but_allows_later_recovery(self):
        with PeerBook() as book:
            peer = Address("127.0.0.1", 8080)
            book.hint(peer)
            book.success(peer, "R", True, now=100)
            book.failure(peer, now=101)
            book.hint(peer)
            assert book.live(now=102) == []
            assert book.due(now=102, force=True) == []
            assert book.due(now=104) == [peer]
            book.success(peer, "R", False, now=104)
            assert len(book.live(now=105)) == 1
            assert book.live(now=105, relays_only=True) == []

    def test_bounded_cache_preserves_live_contacts_and_seeds(self):
        with PeerBook() as book:
            seed, relay = Address("127.0.0.1", 1), Address("127.0.0.1", 2)
            book.hint(seed, seed=True)
            book.hint(relay)
            book.success(relay, "R", True)
            for port in range(3, CAPACITY * 3):
                book.hint(Address("127.0.0.1", port))
            assert len(book.due(force=True)) <= CAPACITY
            assert seed in book.due(force=True)
            assert book.live()[0]['address'] == str(relay)

    def test_persistence_is_shared_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "peers.sqlite")
            with PeerBook(path) as first, PeerBook(path) as second:
                peer = Address("127.0.0.1", 8080)
                first.hint(peer)
                first.success(peer, "R", True)
                assert second.live()[0]['address'] == str(peer)
            with PeerBook(path) as restarted:
                assert restarted.live()[0]['name'] == 'R'

    def test_full_live_cache_still_accepts_new_joiners(self):
        with PeerBook() as book:
            for port in range(1, CAPACITY + 1):
                peer = Address("127.0.0.1", port)
                book.hint(peer)
                book.success(peer, f"r{port}", True)
            newcomer = Address("127.0.0.1", CAPACITY + 1)
            book.hint(newcomer)
            assert newcomer in book.due()
            assert len(book.due(force=True)) <= CAPACITY

    def test_config_paths_and_gateway_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.json"
            data = {"name": "A", "bootstrap": ["localhost:8080"], "allowed_destinations": []}
            path.write_text(json.dumps(data), encoding="utf-8")
            config = Config.load(path)
            assert config.peer_cache == str(path.with_suffix('.peers.sqlite'))
            assert Config.from_dict(config.to_dict()) == config
            data.update(gateway_only=True, discovery=["https://example.com"])
            with pytest.raises(ValueError):
                Config.from_dict(data)

    @pytest.mark.parametrize("update", [
        {"version": True}, {"name": "bad\r\nname"}, {"relay": "true"},
        {"peers": ["127.0.0.1:0"]}, {"peers": ["127.0.0.1:1"] * (BUNDLE + 1)},
    ])
    def test_malformed_payloads_rejected(self, update):
        valid = {"version": 1, "name": "R", "relay": True, "peers": []}
        with pytest.raises(ValueError):
            validate_payload({**valid, **update})


class TestOrdinaryDiscovery:
    @pytest.fixture(autouse=True)
    def setup(self, lab):
        self.lab = lab

    def client(self, bootstrap, name="A"):
        return replace(self.lab.config(name, blocked=True), bootstrap=tuple(bootstrap),
                       peer_cache=str(self.lab.directory / f"{name}.peers.sqlite"))

    def get(self, config):
        return fetch(config, self.lab.url, ca_file=str(self.lab.ca))

    def refresh(self, config):
        manager = PeerDiscovery(config)
        try:
            manager.refresh(time.monotonic() + 8, force=True)
            return manager.book.live()
        finally:
            manager.close()

    def joined(self):
        seed = self.lab.start_node(self.lab.config("seed", relay=False))
        relay = self.lab.start_node(replace(self.lab.config("R"), bootstrap=(seed.address,)))
        wait_for(seed.address, "R")
        return seed, relay

    def test_open_join_without_inventory_and_direct_first(self):
        seed, relay = self.joined()
        client = self.client((seed.address,))
        assert client.peers == ()
        with patch("alternet.peer_discovery.query", side_effect=AssertionError("direct must skip discovery")):
            direct = self.get(replace(client, blocked_direct=frozenset()))
        result = self.get(client)
        assert result.route == ('A', 'R')
        assert result.body == direct.body
        contacts = self.refresh(client)
        assert {p['name'] for p in contacts} == {'seed', 'R'}
        assert not next((p for p in contacts if p['name'] == 'seed'))['relay']

    def test_cached_restart_and_late_join_after_original_bootstrap_loss(self):
        seed, relay = self.joined()
        client = self.client((seed.address,))
        assert self.get(client).route == ('A', 'R')
        seed.stop()
        assert self.get(client).body == DEMO_BODY
        late = self.lab.start_node(replace(self.lab.config("late"), bootstrap=(relay.address,)))
        wait_for(relay.address, "late")
        assert 'late' in {p['name'] for p in self.refresh(client)}
        relay.stop()
        assert self.get(client).route == ('A', 'late')

        assert self.get(self.client((late.address,), 'fresh')).route == ('fresh', 'late')

    def test_dead_seed_is_skipped_and_dead_relay_removed(self):
        dead = self.lab.start_node(self.lab.config("dead"))
        seed, relay = self.joined()
        dead.stop()
        client = self.client((dead.address, seed.address))
        assert self.get(client).route == ('A', 'R')
        relay.stop()
        contacts = self.refresh(client)
        assert [p['name'] for p in contacts] == ['seed']
        started = time.monotonic()
        with pytest.raises(RouteError):
            self.get(client)
        assert time.monotonic() - started < 11

    def test_expired_cached_contact_is_revalidated_after_bootstrap_loss(self):
        seed, _ = self.joined()
        client = self.client((seed.address,))
        assert self.get(client).route == ('A', 'R')
        seed.stop()
        with PeerBook(client.peer_cache) as book:
            with book.transaction() as db:
                db.execute("UPDATE peers SET expires=0")
            assert book.live() == []
        assert self.get(client).route == ('A', 'R')

    def test_relay_uses_its_discovered_exit_for_forwarding(self):
        seed, _ = self.joined()
        middle = self.lab.start_node(replace(self.lab.config("B", blocked=True), bootstrap=(seed.address,)))
        wait_for(middle.address, "R")
        source = self.lab.config("A", blocked=True, peers=(middle.address,))
        assert self.get(source).route == ('A', 'B', 'R')

    def test_outbound_only_client_can_join_without_claiming_a_listener(self):
        seed, _ = self.joined()
        client = replace(self.client((seed.address,)), relay=False)
        assert self.get(client).route == ('A', 'R')
        data = query(seed.address, time.monotonic() + 2)
        assert client.listen not in data['peers']

    def test_opt_out_node_refuses_transit_but_fetches_using_its_discovery_cache(self):
        seed, _ = self.joined()
        node = self.lab.start_node(replace(self.client((seed.address,), "optout"), relay=False))
        wait_for(seed.address, "optout")
        assert not query(node.address, time.monotonic() + 2)['relay']
        assert self.get(self.lab.configs['optout']).route == ('optout', 'R')

        with pytest.raises(RouteError):
            self.get(self.lab.config("manual", peers=(node.address,), blocked=True))

    def test_no_bootstrap_or_cache_reports_no_route_within_limits(self):
        started = time.monotonic()
        with pytest.raises(RouteError):
            self.get(self.client(()))
        assert time.monotonic() - started < 1

    def test_node_background_refresh_renews_and_retires_contacts(self):
        seed = self.lab.start_node(self.lab.config("seed"))
        config = self.client((seed.address,), "watcher")
        with RelayServer(config) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.peer_discovery.book.live() and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert server.peer_discovery.book.live()
                seed.stop()
                with server.peer_discovery.book.transaction() as db:
                    db.execute("UPDATE peers SET retry=0")
                server.peer_discovery.wake.set()
                while server.peer_discovery.book.live() and time.monotonic() < deadline:
                    time.sleep(0.02)
                assert server.peer_discovery.book.live() == []
            finally:
                server.shutdown()
                thread.join(timeout=3)
        assert not server.peer_discovery.worker.is_alive()


class TestExchangeProtocol:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.config = Config("test", Address("127.0.0.1", 0), (), frozenset())

    def test_announcements_are_unverified_and_host_comes_from_connection(self):
        manager = PeerDiscovery(self.config)
        try:
            body = manager.response("127.0.0.1", {"x-alternet-listen-port": "8080",
                                                "x-forwarded-for": "192.0.2.99"})
            assert json.loads(body)['peers'] == []
            assert manager.book.due() == [Address('127.0.0.1', 8080)]
        finally:
            manager.close()

    def test_exchange_rotates_bounded_batches_without_renewing_expired_entries(self):
        manager = PeerDiscovery(self.config)
        try:
            for port in range(1, BUNDLE * 2 + 1):
                address = Address("127.0.0.1", port)
                manager.book.hint(address)
                manager.book.success(address, f"n{port}", True)
            batches = [json.loads(manager.response("127.0.0.1", {}))["peers"] for _ in range(2)]
            assert all((len(batch) == BUNDLE for batch in batches))
            assert len(set(batches[0] + batches[1])) == BUNDLE * 2
        finally:
            manager.close()

    def test_foreground_refresh_waits_for_in_progress_initial_discovery(self):
        config = replace(self.config, bootstrap=(Address("127.0.0.1", 8080),))
        manager = PeerDiscovery(config)
        entered = threading.Event()
        release = threading.Event()

        def slow_query(*_args, **_kwargs):
            entered.set()
            release.wait(1)
            return {"name": "R", "relay": True, "peers": ()}

        try:
            with patch("alternet.peer_discovery.query", side_effect=slow_query):
                manager.start()
                assert entered.wait(2)
                timer = threading.Timer(0.1, release.set)
                timer.start()
                try:
                    manager.refresh(time.monotonic() + 2)
                    assert manager.book.live()[0]['name'] == 'R'
                finally:
                    release.set()
                    timer.join()
        finally:
            release.set()
            manager.close()

    def test_slow_response_body_obeys_absolute_deadline(self):
        stop = threading.Event()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)

            def drip():
                try:
                    sock, _ = listener.accept()
                    with sock:
                        deadline = time.monotonic() + 2
                        first, _ = read_headers(sock, deadline)
                        assert first == f'GET {PATH} HTTP/1.1'
                        send_headers(sock, "HTTP/1.1 200 OK", {"Content-Length": "100"}, deadline)
                        while not stop.wait(0.04):
                            sock.sendall(b" ")
                except OSError:
                    pass
            thread = threading.Thread(target=drip)
            thread.start()
            started = time.monotonic()
            try:
                with pytest.raises(OSError):
                    query(Address(*listener.getsockname()), started + 0.25)
                assert time.monotonic() - started < 1
            finally:
                stop.set()
                thread.join(timeout=3)
