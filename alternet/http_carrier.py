from dataclasses import replace
import hashlib
import logging
import secrets
import select
import socket
import threading
import time
from types import SimpleNamespace

from .node import RelayHandler
from .routing import IDLE_TIMEOUT, RouteError, remaining

LOG = logging.getLogger("alternet")
CHUNK = 32 * 1024
UPLOAD_CHUNK = 512
MAX_SESSIONS = 128
POLL_SECONDS = 0.1
PATH = "/v1/stream"

HEADER = 41
PROFILE = "chrome"
MAX_POST_ATTEMPTS = 3


class CarrierSession:
    def __init__(self, server, config):
        self.server = server
        self.transport, app = socket.socketpair()
        self.transport.settimeout(2)
        self.lock = threading.Lock()
        self.touched = time.monotonic()
        self.sequence = -1
        self.digest = None
        self.response = None
        server.track(self.transport)
        owner = SimpleNamespace(config=config, track=server.track, untrack=server.untrack)

        def run():
            with app:
                RelayHandler(app, ("local HTTPS carrier", 0), owner)

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()

    def close(self):
        try:
            self.transport.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.transport.close()
        self.server.untrack(self.transport)

    def exchange(self, operation, sequence, payload):
        if not self.lock.acquire(timeout=1):
            raise RouteError("concurrent exchange for one carrier session")
        try:
            self.touched = time.monotonic()
            digest = hashlib.sha256(bytes([operation]) + payload).digest()
            if sequence == self.sequence and digest == self.digest:
                return self.response
            if sequence != self.sequence + 1:
                raise RouteError("out-of-order or conflicting carrier exchange")
            if payload:
                self.transport.sendall(payload)
            response = (b"", False)

            wait = POLL_SECONDS if operation == 2 and not payload else 0
            if select.select([self.transport], [], [], wait)[0]:
                data = self.transport.recv(CHUNK)
                response = data, not data
            self.sequence, self.digest, self.response = sequence, digest, response
            return response
        finally:
            self.touched = time.monotonic()
            self.lock.release()


class CarrierSessions:
    def __init__(self, server):
        self.server = server
        self.lock = threading.Lock()
        self.entries = {}
        self.closed = False
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self._reap, daemon=True)
        self.worker.start()

    def _reap(self):
        while not self.stop.wait(1):
            with self.lock:
                expired = [key for key, value in self.entries.items()
                           if time.monotonic() - value.touched > IDLE_TIMEOUT and not value.lock.locked()]
                for key in expired:
                    self.entries.pop(key).close()

    def close(self):
        self.stop.set()
        self.worker.join(timeout=2)
        with self.lock:
            self.closed = True
            for session in self.entries.values():
                session.close()
            self.entries.clear()

    def exchange(self, operation, key, sequence, payload, source):
        with self.lock:
            if self.closed:
                raise RouteError("carrier service closing")
            if operation == 1:
                if sequence != 0 or payload:
                    raise RouteError("invalid session creation")
            if operation == 1 and key not in self.entries:
                if len(self.entries) >= MAX_SESSIONS:
                    raise RouteError("carrier session cannot be created")
                config = self.server.config
                if not config.node.relay:
                    raise RouteError("relaying disabled")
                peers = self.server.store.contacts(source, config.contacts)
                self.entries[key] = CarrierSession(self.server, replace(config.node, peers=peers))
            session = self.entries.get(key)
            if session is None:
                raise RouteError("unknown or expired carrier session")
            if operation == 3:
                self.entries.pop(key).close()
                return b"", True
        try:
            response, eof = session.exchange(operation, sequence, payload)
        except OSError:
            self.remove(key)
            raise

        return response, eof

    def remove(self, key):
        with self.lock:
            session = self.entries.pop(key, None)
            if session is not None:
                session.close()


def handle_post(handler):
    handler.close_connection = True
    if handler.path != PATH:
        handler.send_error(404)
        return
    try:
        lengths = handler.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdecimal() or "Transfer-Encoding" in handler.headers:
            raise ValueError("invalid carrier framing")
        length = int(lengths[0])
        if not HEADER <= length <= HEADER + CHUNK:
            raise ValueError("carrier request too large or short")
        deadline = time.monotonic() + 2
        body = bytearray()
        while len(body) < length:
            handler.connection.settimeout(remaining(deadline))
            block = handler.rfile.read1(length - len(body))
            if not block:
                raise ValueError("truncated carrier request")
            body.extend(block)
        operation, key, payload = body[0], bytes(body[1:33]), bytes(body[HEADER:])
        sequence = int.from_bytes(body[33:HEADER], "big")
        if operation not in (1, 2, 3) or (operation == 3 and payload):
            raise ValueError("invalid carrier operation")
        response, eof = handler.server.carriers.exchange(operation, key, sequence, payload, handler.client_address[0])
        wire = bytes([int(eof)]) + response
        handler.send_response(200)
        handler.send_header("Content-Type", "application/octet-stream")
        handler.send_header("Content-Length", str(len(wire)))
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        handler.wfile.write(wire)
        handler.close_connection = False
        handler.connection.settimeout(IDLE_TIMEOUT)
    except (OSError, ValueError):
        try:
            handler.send_error(400)
        except OSError:
            pass


def carrier_socket(url, ca_file, deadline):
    try:
        from curl_cffi import CurlECode
        from curl_cffi.requests import Session
        from curl_cffi.requests.exceptions import RequestException
    except ImportError as exc:
        raise RouteError("Install curl_cffi for the curl transport: python -m pip install curl_cffi==0.16.3") from exc

    session = Session(impersonate=PROFILE, default_headers=False, verify=ca_file or True, trust_env=False,
                      use_thread_local_curl=False)
    key = secrets.token_bytes(32)
    sequence = 0

    def exchange(operation, payload, timeout):
        nonlocal sequence
        try:
            exchange_deadline = time.monotonic() + timeout
            wire = bytes([operation]) + key + sequence.to_bytes(8, "big") + payload
            for attempt in range(MAX_POST_ATTEMPTS):
                body = bytearray()

                def receive(part):
                    if len(body) + len(part) > CHUNK + 1:
                        raise RouteError("oversized carrier response")
                    body.extend(part)

                try:
                    response = session.post(url + PATH, data=wire,
                                            headers={"Content-Type": "application/octet-stream"},
                                            timeout=remaining(exchange_deadline), allow_redirects=False,
                                            content_callback=receive)
                    break
                except RequestException as exc:
                    if exc.response is not None:
                        exc.response.close()

                    retryable = exc.code in (CurlECode.SEND_ERROR, CurlECode.RECV_ERROR,
                                             CurlECode.GOT_NOTHING, CurlECode.PARTIAL_FILE)
                    if not retryable or attempt + 1 == MAX_POST_ATTEMPTS:
                        raise
                    LOG.info("HTTPS carrier retrying interrupted exchange sequence=%d", sequence)
                    time.sleep(min(0.02, remaining(exchange_deadline)))
            try:
                if response.status_code != 200:
                    raise RouteError(f"HTTPS carrier returned status {response.status_code}")
                length = response.headers.get("Content-Length", "")
                if not length.isdecimal() or not 1 <= int(length) <= CHUNK + 1:
                    raise RouteError("invalid carrier response length")
                if "Transfer-Encoding" in response.headers:
                    raise RouteError("unsupported carrier response framing")
                if len(body) != int(length) or body[0] not in (0, 1):
                    raise RouteError("invalid carrier response")
                sequence += 1
                return bytes(body[1:]), bool(body[0])
            finally:
                response.close()
        except Exception as exc:
            if isinstance(exc, OSError):
                raise
            raise RouteError(f"HTTPS carrier failed: {exc}") from exc

    try:
        _, eof = exchange(1, b"", remaining(deadline))
        if eof:
            raise RouteError("HTTPS carrier closed at creation")
        client, bridge = socket.socketpair()
    except BaseException:
        session.close()
        raise

    def run():
        last_activity = time.monotonic()
        with bridge:
            bridge.settimeout(IDLE_TIMEOUT)
            try:
                select.select([bridge], [], [], POLL_SECONDS)
                while time.monotonic() - last_activity < IDLE_TIMEOUT:
                    outbound = b""
                    if select.select([bridge], [], [], 0)[0]:
                        outbound = bridge.recv(UPLOAD_CHUNK)
                        if not outbound:
                            break
                    incoming, eof = exchange(2, outbound, 2)
                    if incoming:
                        bridge.sendall(incoming)
                    if incoming or outbound:
                        last_activity = time.monotonic()
                    if eof:
                        break
            except OSError as exc:
                LOG.info("HTTPS carrier closed: %s", exc)
            finally:
                try:
                    exchange(3, b"", 1)
                except OSError:
                    pass
                session.close()

    threading.Thread(target=run, daemon=True).start()
    return client
