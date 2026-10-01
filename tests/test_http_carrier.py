from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import importlib.util
import secrets
import socket
import ssl
import threading
import time
import unittest

from alternet.client import fetch
from alternet.http_carrier import CHUNK, PATH, PROFILE
from alternet.lab import DEMO_BODY, Lab
from alternet.routing import RouteError
from experiments.shared_endpoint import SITE_BODY, ordinary_get
from experiments.wire_filter import WireFilter

AVAILABLE = importlib.util.find_spec("curl_cffi") is not None


@unittest.skipUnless(AVAILABLE, "requires curl_cffi")
class HttpCarrierTests(unittest.TestCase):
    def setUp(self):
        from curl_cffi.requests import Session
        self.Session = Session
        self.lab = self.enterContext(Lab())
        site = self.lab.directory / "site"
        site.mkdir()
        (site / "index.html").write_bytes(SITE_BODY)
        self.child, _ = self.lab.start_discovery("entry", (), site_root=str(site))
        self.proxy = self.enterContext(WireFilter(self.child.address))
        self.client = replace(self.lab.discovery_client((self.proxy.url,)),
                              gateway_only=True, gateway_transport="curl")

    def get(self, client=None):
        return fetch(client or self.client, self.lab.url, ca_file=str(self.lab.ca))

    def session(self):
        return self.Session(impersonate=PROFILE, verify=str(self.lab.ca), trust_env=False)

    def test_old_alpn_rule_blocks_stdlib_but_carrier_succeeds(self):
        self.proxy.rule = lambda hello: hello.alpn == ("http/1.1",)
        with self.assertRaises(RouteError):
            self.get(replace(self.client, gateway_transport="stdlib"))
        result = self.get()
        self.assertEqual(result.body, DEMO_BODY)
        self.assertEqual(result.route, ("A", "entry"))
        self.assertIn(("h2", "http/1.1"), [hello.alpn for hello, _ in self.proxy.observations])

    def test_old_python_profile_rule_blocks_stdlib_but_carrier_succeeds(self):
        ordinary_get(self.proxy.url, self.lab.ca)
        profile = self.proxy.observations[-1][0].profile
        self.proxy.rule = lambda hello: hello.profile == profile
        with self.assertRaises(RouteError):
            self.get(replace(self.client, gateway_transport="stdlib"))
        self.assertEqual(self.get().body, DEMO_BODY)

    def test_carrier_reuses_outer_tls_connection(self):
        self.assertEqual(self.get().body, DEMO_BODY)

        self.assertEqual(len(self.proxy.observations), 1)

    def test_small_exchanges_survive_per_connection_byte_budget(self):
        self.proxy.client_byte_limit = 1024
        with self.session() as ordinary:
            self.assertEqual(ordinary.get(self.proxy.url, timeout=2).content, SITE_BODY)
        self.assertEqual(self.get().body, DEMO_BODY)
        self.assertGreater(self.proxy.volume_blocks, 0)

    def test_timed_disconnects_preserve_origin_tls_and_response(self):
        self.proxy.connection_lifetime = 0.2
        self.assertEqual(self.get().body, DEMO_BODY)
        self.assertGreater(self.proxy.lifetime_blocks, 0)

    def test_blocking_endpoint_blocks_ordinary_curl_and_carrier(self):
        self.proxy.rule = lambda hello: True
        from curl_cffi.requests.exceptions import RequestException
        with self.session() as session:
            with self.assertRaises(RequestException):
                session.get(self.proxy.url, timeout=2)
        with self.assertRaises(RouteError):
            self.get()

    def test_outer_certificate_and_hostname_errors_cannot_downgrade(self):
        with self.assertRaises(RouteError):
            self.get(replace(self.client, discovery_ca=None))
        with self.assertRaises(RouteError):
            self.get(replace(self.client, discovery=(f"https://127.0.0.1:{self.proxy.address.port}",)))

    def test_inner_origin_certificate_still_verified(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            fetch(self.client, self.lab.url)

    def test_three_concurrent_sessions_preserve_routes(self):
        def request(index):
            return self.get(replace(self.client, name=f"A{index}"))
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(request, range(3)))
        self.assertEqual([result.route for result in results],
                         [(f"A{index}", "entry") for index in range(3)])
        self.assertTrue(all(result.body == DEMO_BODY for result in results))

    def test_relay_opt_out_refuses_carrier(self):
        child, url = self.lab.start_discovery("disabled", (), relay=False)
        with self.assertRaises(RouteError):
            self.get(replace(self.client, discovery=(url,)))

    def test_relay_allowlist_applies_to_carrier(self):
        target = replace(self.lab.target, port=self.lab.target.port + 1)
        with self.assertRaises(RouteError):
            fetch(replace(self.client, allowed_destinations=frozenset({target}),
                          blocked_direct=frozenset({target})), f"https://{target}/", ca_file=str(self.lab.ca))

    def test_duplicate_post_is_not_delivered_twice_and_conflict_is_rejected(self):
        import threading
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(4)
            from alternet.config import Address
            target = Address("localhost", listener.getsockname()[1])
            saved_target = self.lab.target
            self.lab.target = target
            _, url = self.lab.start_discovery("echo-entry", ())
            self.lab.target = saved_target

            def echo():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(4)
                        while data := connection.recv(CHUNK):
                            connection.sendall(data)
                except OSError:
                    pass

            worker = threading.Thread(target=echo, daemon=True)
            worker.start()
            token = secrets.token_bytes(32)
            sequence = 0
            with self.session() as session:
                def exchange(op, seq, payload=b""):
                    return session.post(url + PATH, data=bytes([op]) + token + seq.to_bytes(8, "big") + payload,
                                        timeout=2)
                try:
                    initial = exchange(1, 0)
                    self.assertEqual(initial.status_code, 200)
                    self.assertEqual(exchange(1, 0).content, initial.content)
                    connect = (f"CONNECT {target} HTTP/1.1\r\nX-Alternet-Visited: [\"A\"]\r\n"
                               "X-Alternet-Hops: 2\r\nX-Alternet-Budget: 2\r\n\r\n").encode()
                    sequence = 1
                    response = exchange(2, sequence, connect)
                    connected = response.content[1:]

                    for _ in range(10):
                        if connected.endswith(b"\r\n\r\n"):
                            break
                        sequence += 1
                        connected += exchange(2, sequence).content[1:]
                    self.assertIn(b"200 Connection Established", connected)
                    self.assertTrue(connected.endswith(b"\r\n\r\n"))
                    payload = b"exactly-once"
                    sequence += 1
                    response = exchange(2, sequence, payload)
                    duplicate = exchange(2, sequence, payload)
                    self.assertEqual(duplicate.content, response.content)

                    received = response.content[1:]
                    for _ in range(3):
                        sequence += 1
                        received += exchange(2, sequence).content[1:]
                    self.assertEqual(received, payload)
                    self.assertEqual(exchange(2, sequence, b"conflicting payload").status_code, 400)
                finally:
                    exchange(3, sequence + 1)
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())

    def test_truncated_and_oversized_carrier_requests_fail(self):
        with self.session() as session:
            for body in (b"short", bytes(CHUNK + 42), bytes([9]) + bytes(40)):
                response = session.post(self.proxy.url + PATH, data=body, timeout=2)
                self.assertEqual(response.status_code, 400)


@unittest.skipUnless(AVAILABLE, "requires curl_cffi")
class CarrierLargeTransferTests(unittest.TestCase):
    def test_large_binary_body(self):
        body = bytes(range(256)) * 8192
        with Lab(body=body) as lab:
            _, url = lab.start_discovery("entry", ())
            client = replace(lab.discovery_client((url,)), gateway_only=True, gateway_transport="curl")
            result = fetch(client, lab.url, ca_file=str(lab.ca))
            self.assertEqual(result.body, body)


@unittest.skipUnless(AVAILABLE, "requires curl_cffi")
class CarrierRetryTests(unittest.TestCase):
    def test_lost_reply_retries_identical_exchange_without_duplicate_origin_bytes(self):
        from alternet.config import Address
        from alternet.discovery import DiscoveryHandler, DiscoveryServer, ServiceConfig
        from alternet.http_carrier import carrier_socket
        from alternet.routing import read_headers, send_headers

        message = b"this payload must arrive exactly once"
        received = bytearray()
        with Lab() as lab, socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(4)
            target = Address("localhost", listener.getsockname()[1])

            def echo():
                try:
                    sock, _ = listener.accept()
                    with sock:
                        sock.settimeout(4)
                        while part := sock.recv(CHUNK):
                            received.extend(part)
                            sock.sendall(part)
                except OSError:
                    pass

            worker = threading.Thread(target=echo, daemon=True)
            worker.start()
            config = ServiceConfig(lab.config("retry-entry", target=target),
                                   str(lab.directory / "server.pem"), str(lab.directory / "server-key.pem"),
                                   str(lab.directory / "retry.sqlite"), ())

            class DropReplyOnce(DiscoveryHandler):
                def do_POST(self):
                    self.close_connection = True
                    wire = self.rfile.read(int(self.headers["Content-Length"]))
                    op, token, payload = wire[0], wire[1:33], wire[41:]
                    sequence = int.from_bytes(wire[33:41], "big")
                    data, eof = self.server.carriers.exchange(op, token, sequence, payload,
                                                              self.client_address[0])
                    if op == 2 and payload == message:
                        self.server.payload_requests.append((token, sequence, payload))
                        if len(self.server.payload_requests) == 1:
                            self.request.shutdown(socket.SHUT_RDWR)
                            return
                    body = bytes([int(eof)]) + data
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            with DiscoveryServer(config) as server:
                server.RequestHandlerClass = DropReplyOnce
                server.payload_requests = []
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
                thread.start()
                try:
                    deadline = time.monotonic() + 3
                    with carrier_socket(f"https://localhost:{server.server_address[1]}", str(lab.ca), deadline) as sock:
                        send_headers(sock, f"CONNECT {target} HTTP/1.1", {
                            "X-Alternet-Visited": '["A"]', "X-Alternet-Hops": "2",
                            "X-Alternet-Budget": "2"}, deadline)
                        self.assertIn("200", read_headers(sock, deadline)[0])
                        sock.sendall(message)
                        sock.settimeout(3)
                        body = bytearray()
                        while len(body) < len(message):
                            part = sock.recv(CHUNK)
                            self.assertTrue(part)
                            body.extend(part)
                        self.assertEqual(body, message)
                    worker.join(timeout=3)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(received, message)
                    self.assertGreaterEqual(len(server.payload_requests), 2)
                    self.assertTrue(all(item == server.payload_requests[0] for item in server.payload_requests))
                finally:
                    server.shutdown()
                    thread.join(timeout=3)
                    worker.join(timeout=4)


if __name__ == "__main__":
    unittest.main()
