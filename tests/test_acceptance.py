from dataclasses import replace
import http.client
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from alternet.client import fetch
from alternet.config import Address, Config
from alternet.lab import DEMO_BODY, Lab
from alternet.node import forward
from alternet.routing import RouteError, open_route


class RoutingAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.lab = self.enterContext(Lab())

    def get(self, config):
        return fetch(config, self.lab.url, ca_file=str(self.lab.ca))

    def test_direct_does_not_contact_peers(self):
        c = self.lab.start_node(self.lab.config("C"))
        a = self.lab.config("A", peers=(c.address,))
        with self.assertLogs("alternet", level="INFO") as logs:
            result = self.get(a)
        self.assertEqual(result.route, ("A",))
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, DEMO_BODY)
        self.assertFalse(any("trying peer" in line for line in logs.output))
        self.assertFalse(any("selected route" in line for line in c.lines))

    def test_one_relay_returns_the_same_body(self):
        c = self.lab.start_node(self.lab.config("C"))
        direct = self.get(self.lab.config("A"))
        relayed = self.get(self.lab.config("A", peers=(c.address,), blocked=True))
        self.assertEqual(relayed.route, ("A", "C"))
        self.assertEqual(relayed.status, 200)
        self.assertEqual(direct.body, relayed.body)

    def test_two_relays(self):
        c = self.lab.start_node(self.lab.config("C"))
        b = self.lab.start_node(self.lab.config("B", peers=(c.address,), blocked=True))
        self.lab.start_node(self.lab.config("A", peers=(b.address,), blocked=True))
        result = self.get(self.lab.configs["A"])
        self.assertEqual(result.route, ("A", "B", "C"))
        self.assertEqual(result.body, DEMO_BODY)

    def test_unavailable_preferred_peer_is_skipped(self):
        c = self.lab.start_node(self.lab.config("C"))

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            dead = Address("127.0.0.1", reservation.getsockname()[1])
            a = self.lab.config("A", peers=(dead, c.address), blocked=True)
            result = self.get(a)
        self.assertEqual(result.route, ("A", "C"))
        self.assertEqual(result.body, DEMO_BODY)

    def test_disabled_relay_refuses_transit_but_can_fetch(self):
        c = self.lab.start_node(self.lab.config("C"))
        b = self.lab.start_node(self.lab.config("B", peers=(c.address,), blocked=True, relay=False))
        with self.assertRaises(RouteError):
            self.get(self.lab.config("A", peers=(b.address,), blocked=True))
        own_request = self.get(self.lab.configs["B"])
        self.assertEqual(own_request.route, ("B", "C"))
        self.assertEqual(own_request.body, DEMO_BODY)
        b.stop()
        self.assertIn("relaying disabled at B", "".join(b.lines))

    def test_peer_cycle_terminates(self):
        a = self.lab.start_node(self.lab.config("A", blocked=True))
        b = self.lab.start_node(self.lab.config("B", peers=(a.address,), blocked=True))
        a = self.lab.start_node(replace(self.lab.configs["A"], peers=(b.address,)))
        start = time.monotonic()
        with self.assertRaises(RouteError):
            self.get(self.lab.config("source", peers=(a.address,), blocked=True))
        self.assertLess(time.monotonic() - start, 11)
        a.stop()
        self.assertIn("routing loop at A", "".join(a.lines))

    def test_unreachable_origin_terminates(self):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            target = Address("127.0.0.1", reservation.getsockname()[1])
            c = self.lab.start_node(self.lab.config("C", target=target))
            a = self.lab.config("A", peers=(c.address,), target=target)
            start = time.monotonic()
            with self.assertRaises(RouteError):
                fetch(a, f"https://{target}/", ca_file=str(self.lab.ca))
        self.assertLess(time.monotonic() - start, 11)

    def test_three_relay_limit_prevents_fourth_relay(self):
        e = self.lab.start_node(self.lab.config("E"))
        d = self.lab.start_node(self.lab.config("D", peers=(e.address,), blocked=True))
        c = self.lab.start_node(self.lab.config("C", peers=(d.address,), blocked=True))
        b = self.lab.start_node(self.lab.config("B", peers=(c.address,), blocked=True))
        with self.assertRaises(RouteError):
            self.get(self.lab.config("A", peers=(b.address,), blocked=True))
        d.stop()
        e.stop()
        self.assertIn("relay hop limit reached at D", "".join(d.lines))
        self.assertNotIn("trying direct TCP", "".join(e.lines))

    def test_allowlist_enforced_before_any_connection(self):
        a = replace(self.lab.config("A"), allowed_destinations=frozenset())
        with patch("alternet.routing.connect_tcp") as dial:
            with self.assertRaisesRegex(RouteError, "not allowed"):
                self.get(a)
        dial.assert_not_called()

    def test_relay_also_enforces_its_allowlist(self):
        c = self.lab.start_node(replace(self.lab.config("C"), allowed_destinations=frozenset()))
        with self.assertRaises(RouteError):
            self.get(self.lab.config("A", peers=(c.address,), blocked=True))
        c.stop()
        self.assertIn("not allowed by C", "".join(c.lines))

    def test_fetch_cli_uses_standard_library_only(self):
        c = self.lab.start_node(self.lab.config("C"))
        a = self.lab.config("A", peers=(c.address,), blocked=True)
        path = self.lab.directory / "fetch.json"
        path.write_text(json.dumps(a.to_dict()), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, "-S", "-m", "alternet", "fetch", "--config", str(path),
             "--ca", str(self.lab.ca), self.lab.url], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, DEMO_BODY)
        self.assertIn(b"route=A -> C", result.stderr)

    def test_interrupted_https_response_fails_without_replay(self):
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
                with self.assertLogs("alternet", level="INFO") as logs:
                    with self.assertRaises(http.client.IncompleteRead):
                        fetch(a, f"https://{target}/", ca_file=str(self.lab.ca))
                self.assertEqual(sum("trying peer" in line for line in logs.output), 1)
            finally:
                thread.join(timeout=6)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])


class TLSAndLifecycleTests(unittest.TestCase):
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
                    self.assertEqual(incoming.read(), b"request")
                origin.sendall(b"response after request EOF")
                origin.shutdown(socket.SHUT_WR)
                with client.makefile("rb") as incoming:
                    self.assertEqual(incoming.read(), b"response after request EOF")
        finally:
            thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_wrong_hostname_certificate_is_rejected_through_relay(self):
        with Lab(cert_hostname="wrong.example") as lab:
            c = lab.start_node(lab.config("C"))
            a = lab.config("A", peers=(c.address,), blocked=True)
            with self.assertRaises(ssl.SSLCertVerificationError):
                fetch(a, lab.url, ca_file=str(lab.ca))

    def test_large_binary_body_survives_two_relays(self):
        body = bytes(range(256)) * 8192
        with Lab(body=body) as lab:
            c = lab.start_node(lab.config("C"))
            b = lab.start_node(lab.config("B", peers=(c.address,), blocked=True))
            result = fetch(lab.config("A", peers=(b.address,), blocked=True), lab.url, ca_file=str(lab.ca))
            self.assertEqual(result.body, body)

    def test_child_processes_and_files_cleaned_up_on_error(self):
        lab = Lab()
        with self.assertRaisesRegex(RuntimeError, "deliberate"):
            with lab:
                lab.start_node(lab.config("A"))
                raise RuntimeError("deliberate fixture error")
        self.assertFalse(lab.directory.exists())
        self.assertTrue(all(child.process.poll() is not None for child in lab.children))

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
                with self.assertRaises(OSError):
                    open_route(config, target)
                elapsed = time.monotonic() - start
                self.assertGreaterEqual(elapsed, 9)
                self.assertLess(elapsed, 11)
            finally:
                stop.set()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
