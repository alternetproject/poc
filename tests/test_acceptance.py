from dataclasses import replace
import http.client
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
import pytest
from unittest.mock import patch

from alternet.client import fetch
from alternet.config import Address, Config
from alternet.lab import DEMO_BODY, Lab
from alternet.node import forward
from alternet.routing import RouteError, open_route


class TestRoutingAcceptance:
    @pytest.fixture(autouse=True)
    def setup(self, lab):
        self.lab = lab

    def get(self, config):
        return fetch(config, self.lab.url, ca_file=str(self.lab.ca))

    def test_direct_does_not_contact_peers(self, caplog):
        c = self.lab.start_node(self.lab.config("C"))
        a = self.lab.config("A", peers=(c.address,))
        with caplog.at_level("INFO", logger="alternet"):
            result = self.get(a)
        assert caplog.messages
        assert result.route == ('A',)
        assert result.status == 200
        assert result.body == DEMO_BODY
        assert not any(('trying peer' in line for line in caplog.messages))
        assert not any(('selected route' in line for line in c.lines))

    def test_one_relay_returns_the_same_body(self):
        c = self.lab.start_node(self.lab.config("C"))
        direct = self.get(self.lab.config("A"))
        relayed = self.get(self.lab.config("A", peers=(c.address,), blocked=True))
        assert relayed.route == ('A', 'C')
        assert relayed.status == 200
        assert direct.body == relayed.body

    def test_two_relays(self):
        c = self.lab.start_node(self.lab.config("C"))
        b = self.lab.start_node(self.lab.config("B", peers=(c.address,), blocked=True))
        self.lab.start_node(self.lab.config("A", peers=(b.address,), blocked=True))
        result = self.get(self.lab.configs["A"])
        assert result.route == ('A', 'B', 'C')
        assert result.body == DEMO_BODY

    def test_unavailable_preferred_peer_is_skipped(self):
        c = self.lab.start_node(self.lab.config("C"))

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            dead = Address("127.0.0.1", reservation.getsockname()[1])
            a = self.lab.config("A", peers=(dead, c.address), blocked=True)
            result = self.get(a)
        assert result.route == ('A', 'C')
        assert result.body == DEMO_BODY

    def test_disabled_relay_refuses_transit_but_can_fetch(self):
        c = self.lab.start_node(self.lab.config("C"))
        b = self.lab.start_node(self.lab.config("B", peers=(c.address,), blocked=True, relay=False))
        with pytest.raises(RouteError):
            self.get(self.lab.config("A", peers=(b.address,), blocked=True))
        own_request = self.get(self.lab.configs["B"])
        assert own_request.route == ('B', 'C')
        assert own_request.body == DEMO_BODY
        b.stop()
        assert 'relaying disabled at B' in ''.join(b.lines)

    def test_peer_cycle_terminates(self):
        a = self.lab.start_node(self.lab.config("A", blocked=True))
        b = self.lab.start_node(self.lab.config("B", peers=(a.address,), blocked=True))
        a = self.lab.start_node(replace(self.lab.configs["A"], peers=(b.address,)))
        start = time.monotonic()
        with pytest.raises(RouteError):
            self.get(self.lab.config("source", peers=(a.address,), blocked=True))
        assert time.monotonic() - start < 11
        a.stop()
        assert 'routing loop at A' in ''.join(a.lines)

    def test_unreachable_origin_terminates(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            target = Address("127.0.0.1", reservation.getsockname()[1])
            c = self.lab.start_node(self.lab.config("C", target=target))
            a = self.lab.config("A", peers=(c.address,), target=target)
            start = time.monotonic()
            with pytest.raises(RouteError):
                fetch(a, f"https://{target}/", ca_file=str(self.lab.ca))
        assert time.monotonic() - start < 11

    def test_three_relay_limit_prevents_fourth_relay(self):
        e = self.lab.start_node(self.lab.config("E"))
        d = self.lab.start_node(self.lab.config("D", peers=(e.address,), blocked=True))
        c = self.lab.start_node(self.lab.config("C", peers=(d.address,), blocked=True))
        b = self.lab.start_node(self.lab.config("B", peers=(c.address,), blocked=True))
        with pytest.raises(RouteError):
            self.get(self.lab.config("A", peers=(b.address,), blocked=True))
        d.stop()
        e.stop()
        assert 'relay hop limit reached at D' in ''.join(d.lines)
        assert 'trying direct TCP' not in ''.join(e.lines)

    def test_allowlist_enforced_before_any_connection(self):
        a = replace(self.lab.config("A"), allowed_destinations=frozenset())
        with patch("alternet.routing.connect_tcp") as dial:
            with pytest.raises(RouteError, match='not allowed'):
                self.get(a)
        dial.assert_not_called()

    def test_relay_also_enforces_its_allowlist(self):
        c = self.lab.start_node(replace(self.lab.config("C"), allowed_destinations=frozenset()))
        with pytest.raises(RouteError):
            self.get(self.lab.config("A", peers=(c.address,), blocked=True))
        c.stop()
        assert 'not allowed by C' in ''.join(c.lines)

    def test_fetch_cli_uses_standard_library_only(self):
        c = self.lab.start_node(self.lab.config("C"))
        a = self.lab.config("A", peers=(c.address,), blocked=True)
        path = self.lab.directory / "fetch.json"
        path.write_text(json.dumps(a.to_dict()), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-S", "-m", "alternet", "fetch", "--config", str(path),
             "--ca", str(self.lab.ca), self.lab.url], capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == DEMO_BODY
        assert b'route=A -> C' in result.stderr

    def test_interrupted_https_response_fails_without_replay(self, caplog):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.lab.directory / "server.pem", self.lab.directory / "server-key.pem")
        errors = []
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(5)
            target = Address("localhost", listener.getsockname()[1])

            def truncated_origin():
                try:
                    raw, _ = listener.accept()
                    with raw:
                        raw.settimeout(5)
                        with context.wrap_socket(raw, server_side=True) as tls:
                            request = bytearray()
                            while not request.endswith(b"\r\n\r\n"):
                                chunk = tls.recv(1)
                                if not chunk:
                                    raise ConnectionError("client closed before sending a request")
                                request.extend(chunk)
                            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial")
                except Exception as exc:
                    errors.append(exc)

            thread = threading.Thread(target=truncated_origin, daemon=True)
            thread.start()
            c = self.lab.start_node(self.lab.config("C", target=target))
            a = self.lab.config("A", target=target, peers=(c.address,), blocked=True)
            try:
                with caplog.at_level("INFO", logger="alternet"):
                    with pytest.raises(http.client.IncompleteRead):
                        fetch(a, f"https://{target}/", ca_file=str(self.lab.ca))
                assert sum(('trying peer' in line for line in caplog.messages)) == 1
            finally:
                thread.join(timeout=6)
            assert not thread.is_alive()
            assert errors == []


class TestTLSAndLifecycle:
    def test_forwarding_preserves_tcp_half_close(self):
        client, relay_client = socket.socketpair()
        relay_upstream, origin = socket.socketpair()
        errors = []

        def bridge():
            try:
                with relay_client, relay_upstream:
                    forward(relay_client, relay_upstream, "test")
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=bridge, daemon=True)
        thread.start()
        try:
            with client, origin:
                client.settimeout(3)
                origin.settimeout(3)
                client.sendall(b"request")
                client.shutdown(socket.SHUT_WR)
                with origin.makefile("rb") as incoming:
                    assert incoming.read() == b'request'
                origin.sendall(b"response after request EOF")
                origin.shutdown(socket.SHUT_WR)
                with client.makefile("rb") as incoming:
                    assert incoming.read() == b'response after request EOF'
        finally:
            thread.join(timeout=4)
        assert not thread.is_alive()
        assert errors == []

    def test_wrong_hostname_certificate_is_rejected_through_relay(self):
        with Lab(cert_hostname="wrong.example") as lab:
            c = lab.start_node(lab.config("C"))
            a = lab.config("A", peers=(c.address,), blocked=True)
            with pytest.raises(ssl.SSLCertVerificationError):
                fetch(a, lab.url, ca_file=str(lab.ca))

    def test_large_binary_body_survives_two_relays(self):
        body = bytes(range(256)) * 8192
        with Lab(body=body) as lab:
            c = lab.start_node(lab.config("C"))
            b = lab.start_node(lab.config("B", peers=(c.address,), blocked=True))
            result = fetch(lab.config("A", peers=(b.address,), blocked=True), lab.url, ca_file=str(lab.ca))
            assert result.body == body

    def test_child_processes_and_files_cleaned_up_on_error(self):
        lab = Lab()
        with pytest.raises(RuntimeError, match='deliberate'):
            with lab:
                lab.start_node(lab.config("A"))
                raise RuntimeError("deliberate fixture error")
        assert not lab.directory.exists()
        assert all((child.process.poll() is not None for child in lab.children))

    def test_unresponsive_peer_respects_ten_second_setup_budget(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(12)
            stop = threading.Event()

            def stall():
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                with connection:
                    stop.wait(12)

            thread = threading.Thread(target=stall, daemon=True)
            thread.start()
            peer = Address("127.0.0.1", listener.getsockname()[1])
            target = Address("localhost", 443)
            config = Config("A", Address("127.0.0.1", 0), (peer,), frozenset({target}),
                            blocked_direct=frozenset({target}))
            start = time.monotonic()
            try:
                with pytest.raises(OSError):
                    open_route(config, target)
                elapsed = time.monotonic() - start
                assert elapsed >= 9
                assert elapsed < 11
            finally:
                stop.set()
                thread.join(timeout=3)
