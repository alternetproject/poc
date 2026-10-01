from dataclasses import dataclass
import hashlib
import json
import socket
import socketserver
import threading
import time

from alternet.config import Address
from alternet.node import forward


@dataclass(frozen=True)
class Hello:
    tls: bool
    server_name: str | None = None
    alpn: tuple[str, ...] = ()
    profile: str | None = None


class Cursor:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def take(self, length):
        if self.offset + length > len(self.data):
            raise ValueError("truncated ClientHello")
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def vector(self, width):
        return self.take(int.from_bytes(self.take(width), "big"))


def parse_hello(body: bytes) -> Hello:
    cursor = Cursor(body)
    version = cursor.take(2).hex()
    if version not in ("0301", "0302", "0303"):
        raise ValueError("unsupported ClientHello legacy version")
    cursor.take(32)
    cursor.vector(1)
    ciphers = cursor.vector(2).hex()
    compression = cursor.vector(1).hex()
    if not ciphers or len(ciphers) % 4 or not compression:
        raise ValueError("invalid ClientHello cipher or compression list")
    extensions = Cursor(cursor.vector(2))
    if cursor.offset != len(cursor.data):
        raise ValueError("trailing ClientHello bytes")
    types = []
    stable = {}
    name = None
    alpn = ()
    while extensions.offset < len(extensions.data):
        kind = int.from_bytes(extensions.take(2), "big")
        value = extensions.vector(2)
        if kind in types:
            raise ValueError("duplicate TLS extension")
        types.append(kind)
        if kind == 0:
            names = Cursor(Cursor(value).vector(2))
            while names.offset < len(names.data):
                name_kind = names.take(1)[0]
                candidate = names.vector(2)
                if name_kind == 0:
                    name = candidate.decode("ascii")
        elif kind == 16:
            protocols = Cursor(Cursor(value).vector(2))
            offered = []
            while protocols.offset < len(protocols.data):
                offered.append(protocols.vector(1).decode("ascii"))
            alpn = tuple(offered)
        if kind in (10, 11, 13, 43, 45):
            stable[kind] = value.hex()

    profile = hashlib.sha256(json.dumps([version, ciphers, compression, types, stable, alpn],
                                       sort_keys=True).encode()).hexdigest()
    return Hello(True, name, alpn, profile)


def inspect_connection(sock: socket.socket) -> tuple[bytes, Hello]:
    deadline = time.monotonic() + 4

    def exact(count):
        result = bytearray()
        while len(result) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("ClientHello deadline")
            sock.settimeout(remaining)
            chunk = sock.recv(count - len(result))
            if not chunk:
                raise ConnectionError("connection closed before ClientHello")
            result.extend(chunk)
        return bytes(result)

    header = exact(5)
    if header[0] != 22 or header[1] != 3:
        return header, Hello(False)
    wire = bytearray()
    handshake = bytearray()
    while True:
        size = int.from_bytes(header[3:5], "big")
        if header[0] != 22 or not 0 < size <= 16384 or len(wire) + size + 5 > 65536:
            raise ValueError("unsupported ClientHello framing")
        record = exact(size)
        wire.extend(header + record)
        handshake.extend(record)
        if len(handshake) >= 4:
            if handshake[0] != 1:
                raise ValueError("expected TLS ClientHello")
            length = int.from_bytes(handshake[1:4], "big")
            if len(handshake) >= length + 4:
                return bytes(wire), parse_hello(bytes(handshake[4:4 + length]))
        header = exact(5)


class MeteredSocket:
    def __init__(self, sock, server, *, direction="up"):
        self.sock = sock
        self.server = server
        self.count = 0
        self.direction = direction

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def recv(self, size):
        data = self.sock.recv(size)
        self.count += len(data)
        limit = self.server.client_byte_limit if self.direction == "up" else None
        if limit is not None and self.count > limit:
            with self.server.lock:
                self.server.volume_blocks += 1
            raise ConnectionError("censor's encrypted client-byte budget exceeded")
        self.server.pace(len(data))
        return data


class FilterHandler(socketserver.BaseRequestHandler):
    def handle(self):
        upstream = None
        expiry = None
        try:
            self.server.track(self.request)
            initial, hello = inspect_connection(self.request)

            blocked = bool(self.server.rule(hello))
            with self.server.lock:
                self.server.observations.append((hello, blocked))
            if blocked:
                return
            upstream = socket.create_connection((self.server.backend.host, self.server.backend.port), timeout=2)
            self.server.track(upstream)
            if self.server.connection_lifetime is not None:
                def expire():
                    with self.server.lock:
                        self.server.lifetime_blocks += 1
                    for sock in (self.request, upstream):
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                expiry = threading.Timer(self.server.connection_lifetime, expire)
                expiry.daemon = True
                expiry.start()
            upstream.sendall(initial)
            forward(MeteredSocket(self.request, self.server),
                    MeteredSocket(upstream, self.server, direction="down"), "test wire filter")
        except (OSError, ValueError):
            pass
        finally:
            if expiry is not None:
                expiry.cancel()
            if upstream is not None:
                self.server.untrack(upstream)
                upstream.close()
            self.server.untrack(self.request)


class WireFilter(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, backend: Address, *, listen: Address | None = None):
        self.backend = backend
        self.rule = lambda hello: False
        self.client_byte_limit = None
        self.volume_blocks = 0
        self.connection_lifetime = None
        self.lifetime_blocks = 0
        self.rate_bytes_per_second = None
        self.next_byte_at = 0.0
        self.stopping = threading.Event()
        self.observations = []
        self.lock = threading.Lock()
        self.active = set()
        self.closing = False
        listen = listen or Address("127.0.0.1", 0)
        super().__init__((listen.host, listen.port), FilterHandler)
        self.address = Address(*self.server_address[:2])
        host = "localhost" if listen.host == "127.0.0.1" else listen.host
        self.url = f"https://{host}:{self.address.port}"

    def pace(self, count):
        with self.lock:
            rate = self.rate_bytes_per_second
            if rate is None or not count:
                return
            now = time.monotonic()
            self.next_byte_at = max(now, self.next_byte_at) + count / rate
            delay = self.next_byte_at - now
        if self.stopping.wait(delay):
            raise ConnectionError("filter closing")

    def track(self, sock):
        with self.lock:
            if self.closing:
                raise ConnectionError("filter closing")
            self.active.add(sock)

    def untrack(self, sock):
        with self.lock:
            self.active.discard(sock)

    def disconnect_active(self):
        with self.lock:
            connections = tuple(self.active)
            for sock in connections:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        return len(connections)

    def __enter__(self):
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.stopping.set()
        self.shutdown()
        with self.lock:
            self.closing = True
            for sock in self.active:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        self.server_close()
        self.thread.join(timeout=3)
