from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import pytest
from unittest.mock import patch

from alternet.client import fetch
from alternet.config import Address, Config
from alternet.discovery import (cached_contacts, gateway_socket, request_contacts,
                               save_contacts)
from alternet.discovery_store import DiscoveryStore, source_prefix
from alternet.lab import DEMO_BODY, Lab
from alternet.routing import RouteError, connect_tcp, read_headers, send_headers


class TestDisclosurePolicy:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.directory = tmp_path
        self.path = self.directory / "state.sqlite"
        self.pool = tuple(Address(f"192.0.2.{index}", 443) for index in range(1, 31))
        self.store = DiscoveryStore(self.path, bundle_size=3, budget=6, window_seconds=100)

    def test_sticky_assignment_survives_restart_and_inventory_reordering(self):
        initial = self.store.contacts("198.51.100.1", self.pool, now=100)
        assert len(initial) == 3
        restarted = DiscoveryStore(self.path, bundle_size=3, budget=6, window_seconds=100)
        for index in range(1, 30):
            assert restarted.contacts(f'198.51.100.{index}', self.pool[::-1], now=101) == initial

    def test_actual_source_prefix_grouping(self):
        assert source_prefix('198.51.100.2') == '198.51.100.0/24'
        assert source_prefix('::ffff:198.51.100.2') == '198.51.100.0/24'
        assert source_prefix('2001:db8:1234:5600::1') == source_prefix('2001:db8:1234:56ff::2')
        assert source_prefix('2001:db8:1234:5600::1') != source_prefix('2001:db8:1234:5700::1')

    def test_inventory_replacement_cannot_exceed_rolling_budget(self):
        first = self.store.contacts("198.51.100.1", self.pool[:3], now=100)
        second = self.store.contacts("198.51.100.1", self.pool[3:6], now=110)
        assert len(set(first + second)) == 6
        assert self.store.contacts('198.51.100.1', self.pool[6:], now=150) == ()

        third = self.store.contacts("198.51.100.1", self.pool[6:9], now=201)
        assert len(third) == 3
        assert self.store.contacts('198.51.100.1', self.pool[9:], now=205) == ()

    def test_repeated_disclosure_extends_rolling_window(self):
        self.store.contacts("198.51.100.1", self.pool[:3], now=100)
        self.store.contacts("198.51.100.1", self.pool[:3], now=190)
        self.store.contacts("198.51.100.1", self.pool[3:6], now=200)

        assert self.store.contacts('198.51.100.1', self.pool[6:], now=210) == ()

    def test_reintroduced_historical_contact_consumes_a_current_slot(self):
        self.store.contacts("198.51.100.1", self.pool[:3], now=100)
        self.store.contacts("198.51.100.1", self.pool[3:6], now=201)
        self.store.contacts("198.51.100.1", self.pool[6:9], now=202)
        assert self.store.contacts('198.51.100.1', self.pool[:3], now=203) == ()

    def test_concurrent_inventory_changes_cannot_bypass_budget(self):
        def query(index):
            return self.store.contacts("198.51.100.1", self.pool[index:index + 3], now=100)
        with ThreadPoolExecutor(max_workers=8) as executor:
            observed = set().union(*executor.map(query, range(24)))
        assert len(observed) == 6

    def test_rolling_bound_over_many_inventory_changes(self):
        history = []
        for instant in range(1, 650, 7):
            offset = (instant * 11) % len(self.pool)
            rotated = self.pool[offset:] + self.pool[:offset]
            contacts = self.store.contacts("198.51.100.1", rotated[:5], now=instant)
            history.append((instant, contacts))
            observed = {address for timestamp, entries in history if timestamp > instant - 100
                        for address in entries}
            assert len(observed) <= 6


class TestDiscoveryNetwork:
    @pytest.fixture(autouse=True)
    def setup(self, lab):
        self.lab = lab

    def get(self, config):
        return fetch(config, self.lab.url, ca_file=str(self.lab.ca))

    def query(self, url):
        return request_contacts(url, str(self.lab.ca), time.monotonic() + 2)

    def test_fresh_client_discovers_relay_and_direct_access_skips_discovery(self, caplog):
        relay = self.lab.start_node(self.lab.config("R"))
        _, url = self.lab.start_discovery("entry", (relay.address,))
        client = self.lab.discovery_client((url,))
        assert client.peers == ()
        with caplog.at_level("INFO", logger="alternet"):
            direct = self.get(replace(client, blocked_direct=frozenset()))
        assert caplog.messages
        assert direct.route == ('A',)
        assert not any(('discovery' in line or 'trying peer' in line for line in caplog.messages))
        result = self.get(client)
        assert result.route == ('A', 'R')
        assert result.body == direct.body
        assert cached_contacts(client)[url]['peers'] == [str(relay.address)]

    def test_forwarding_headers_and_failure_claims_do_not_rotate_contacts(self):
        pool = tuple(Address(f"192.0.2.{index}", 443) for index in range(1, 15))
        child, url = self.lab.start_discovery("entry", pool)
        expected = self.query(url)["peers"]
        context = ssl.create_default_context(cafile=str(self.lab.ca))
        for index in range(5):
            connection = http.client.HTTPSConnection("localhost", child.address.port, context=context, timeout=2)
            try:
                connection.request("GET", "/v1/peers", headers={
                    "X-Forwarded-For": f"203.0.{index}.1", "X-Alternet-Name": f"sybil-{index}",
                    "X-Failed-Relays": ",".join(expected), "Cookie": f"identity={index}"})
                response = connection.getresponse()
                assert response.status == 200
                assert json.loads(response.read())['peers'] == expected
            finally:
                connection.close()
        for method, path in (("GET", "/v1/peers?rotate=1"), ("GET", "/all"), ("POST", "/v1/peers")):
            connection = http.client.HTTPSConnection("localhost", child.address.port, context=context, timeout=2)
            try:
                connection.request(method, path)
                response = connection.getresponse()
                assert response.status in (404, 501)
                response.read()
            finally:
                connection.close()
        _, restarted_url = self.lab.start_discovery("entry", pool[::-1])
        assert url == restarted_url
        assert self.query(url)['peers'] == expected

    def test_shared_cohort_recovers_after_every_disclosed_relay_stops(self):
        relays = [self.lab.start_node(self.lab.config(f"R{index}")) for index in range(3)]
        _, url = self.lab.start_discovery("entry", tuple(relay.address for relay in relays))
        attacker_contacts = self.query(url)["peers"]
        assert len(attacker_contacts) == 3
        for relay in relays:
            relay.stop()
        result = self.get(self.lab.discovery_client((url,), name="honest-same-NAT"))
        assert result.route == ('honest-same-NAT', 'entry')
        assert result.body == DEMO_BODY
        assert self.query(url)['peers'] == attacker_contacts

    def test_exhausted_disclosure_budget_still_allows_gateway(self):
        old = (Address("192.0.2.1", 443),)
        _, url = self.lab.start_discovery("entry", old, bundle_size=1, disclosure_budget=1)
        assert len(self.query(url)['peers']) == 1
        _, url = self.lab.start_discovery("entry", (Address("192.0.2.2", 443),),
                                          bundle_size=1, disclosure_budget=1)
        assert self.query(url)['peers'] == []
        result = self.get(self.lab.discovery_client((url,)))
        assert result.route == ('A', 'entry')
        assert result.body == DEMO_BODY

    def test_gateway_can_use_assigned_relay_but_cannot_sample_hidden_inventory(self):
        relays = [self.lab.start_node(self.lab.config(f"R{index}")) for index in range(2)]
        _, url = self.lab.start_discovery("entry", tuple(relay.address for relay in relays),
                                          bundle_size=1, disclosure_budget=1, blocked=True)
        assigned = Address.parse(self.query(url)["peers"][0])
        assigned_child = next(relay for relay in relays if relay.address == assigned)
        assigned_name = next(name for name, relay in self.lab.nodes.items() if relay is assigned_child)
        client = self.lab.discovery_client((url,))

        def block_client_to_relay(address, deadline):
            if address in {relay.address for relay in relays}:
                raise ConnectionError("SIMULATED BLOCK: client cannot dial advertised relay")
            return connect_tcp(address, deadline)

        with patch("alternet.routing.connect_tcp", side_effect=block_client_to_relay):
            result = self.get(client)
            assert result.route == ('A', 'entry', assigned_name)
            assert result.body == DEMO_BODY
            assigned_child.stop()

            with pytest.raises(RouteError):
                self.get(client)
        assert self.query(url)['peers'] == [str(assigned)]

    def test_second_entry_works_when_first_service_is_down(self):
        first, first_url = self.lab.start_discovery("entry-1", ())
        _, second_url = self.lab.start_discovery("entry-2", ())
        first.stop()
        result = self.get(self.lab.discovery_client((first_url, second_url)))
        assert result.route == ('A', 'entry-2')
        assert result.body == DEMO_BODY

    def test_cached_contact_works_with_all_services_down_and_expires(self):
        relay = self.lab.start_node(self.lab.config("R"))
        entry, url = self.lab.start_discovery("entry", (relay.address,))
        client = self.lab.discovery_client((url,))
        assert self.get(client).route == ('A', 'R')
        entry.stop()
        assert self.get(client).route == ('A', 'R')
        cached = cached_contacts(client)
        cached[url]["expires"] = time.time() - 1
        save_contacts(client, cached)
        assert cached_contacts(client) == {}
        start = time.monotonic()
        with pytest.raises(RouteError):
            self.get(client)
        assert time.monotonic() - start < 11

    def test_gateway_opt_out_and_destination_allowlist_are_enforced(self):
        _, url = self.lab.start_discovery("entry", (), relay=False)
        assert not self.query(url)['gateway']

        def attempt(target):
            deadline = time.monotonic() + 2
            with gateway_socket(url, str(self.lab.ca), deadline) as sock:
                send_headers(sock, f"CONNECT {target} HTTP/1.1", {
                    "X-Alternet-Visited": '["A"]', "X-Alternet-Hops": "2",
                    "X-Alternet-Budget": "2"}, deadline)
                return read_headers(sock, deadline)[0]

        assert '502' in attempt(self.lab.target)
        _, url = self.lab.start_discovery("entry", ())
        assert '502' in attempt(Address('not-allowed.example', 443))

    def test_discovery_certificate_and_hostname_must_verify(self):
        entry, url = self.lab.start_discovery("entry", ())
        with pytest.raises(ssl.SSLCertVerificationError):
            request_contacts(url, None, time.monotonic() + 3)
        with pytest.raises(ssl.SSLCertVerificationError):
            self.query(f"https://127.0.0.1:{entry.address.port}")

    def test_origin_certificate_still_verifies_inside_gateway_tls(self):
        target = Address("127.0.0.1", self.lab.target.port)
        self.lab.target = target
        _, url = self.lab.start_discovery("entry", ())
        with pytest.raises(ssl.SSLCertVerificationError):
            fetch(self.lab.discovery_client((url,)), f"https://{target}/", ca_file=str(self.lab.ca))

    def test_slow_discovery_headers_respect_total_deadline(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.lab.directory / "server.pem", self.lab.directory / "server-key.pem")
        stop = threading.Event()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(3)

            def drip():
                try:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(3)
                        with context.wrap_socket(raw, server_side=True) as tls:
                            read_headers(tls, time.monotonic() + 3)
                            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n":
                                tls.sendall(bytes([byte]))
                                if stop.wait(0.1):
                                    break
                except OSError:
                    pass

            thread = threading.Thread(target=drip, daemon=True)
            thread.start()
            start = time.monotonic()
            try:
                with pytest.raises(OSError):
                    self.query(f"https://localhost:{listener.getsockname()[1]}")
                assert time.monotonic() - start < 2.8
            finally:
                stop.set()
                thread.join(timeout=4)
            assert not thread.is_alive()


class TestDiscoveryTransfer:
    def test_large_binary_response_survives_nested_tls(self):
        body = bytes(range(256)) * 8192
        with Lab(body=body) as lab:
            _, url = lab.start_discovery("entry", ())
            result = fetch(lab.discovery_client((url,)), lab.url, ca_file=str(lab.ca))
            assert result.route == ('A', 'entry')
            assert result.body == body

    def test_config_paths_are_relative_and_default_cache_is_persistent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "client.json"
            path.write_text(json.dumps({"name": "A", "allowed_destinations": ["example.com:443"],
                                        "discovery": ["https://entry.example"],
                                        "discovery_ca": "ca.pem"}), encoding="utf-8")
            config = Config.load(path)
            assert config.discovery == ('https://entry.example:443',)
            assert config.discovery_ca == str(path.parent / 'ca.pem')
            assert config.discovery_cache == str(path.with_suffix('.contacts.json'))
