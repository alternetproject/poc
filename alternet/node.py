import json
import logging
import select
import socket
import socketserver
import ssl
import threading
import time

from .config import Address, Config
from .routing import (IDLE_TIMEOUT, SETUP_TIMEOUT, RouteError, open_route,
                      parse_request, read_headers, send_headers)

LOG = logging.getLogger("alternet")
BUFFER_LIMIT = 64 * 1024


def forward(client: socket.socket, upstream: socket.socket, name: str) -> None:
    sockets = (client, upstream)
    other = {client: upstream, upstream: client}
    buffers = {sock: bytearray() for sock in sockets}
    reading = set(sockets)
    write_closed = set()
    counts = {sock: 0 for sock in sockets}
    read_wants = {sock: "read" for sock in sockets}
    write_wants = {sock: "write" for sock in sockets}
    pending_writes = {sock: None for sock in sockets}
    tls_tunnel = any(isinstance(sock, ssl.SSLSocket) for sock in sockets)
    last_activity = time.monotonic()
    for sock in sockets:
        sock.setblocking(False)
    try:
        while reading or any(buffers.values()):
            if tls_tunnel and len(reading) != 2 and not any(buffers.values()):
                return
            for source in sockets:
                destination = other[source]
                if source not in reading and not buffers[destination] and destination not in write_closed:
                    if not tls_tunnel:
                        destination.shutdown(socket.SHUT_WR)
                    write_closed.add(destination)
            timeout = IDLE_TIMEOUT - (time.monotonic() - last_activity)
            if timeout <= 0:
                raise TimeoutError("tunnel idle timeout")
            can_read = {sock for sock in reading if len(buffers[other[sock]]) < BUFFER_LIMIT}
            can_write = {sock for sock in sockets if buffers[sock]}
            buffered = {sock for sock in can_read if isinstance(sock, ssl.SSLSocket) and sock.pending()}
            readable, writable, _ = select.select(
                list({sock for sock in can_read if read_wants[sock] == "read"}
                     | {sock for sock in can_write if write_wants[sock] == "read"}),
                list({sock for sock in can_read if read_wants[sock] == "write"}
                     | {sock for sock in can_write if write_wants[sock] == "write"}),
                [], 0 if buffered else timeout)
            ready = {"read": set(readable), "write": set(writable)}
            for sock in can_read:
                if sock not in buffered and sock not in ready[read_wants[sock]]:
                    continue
                try:
                    data = sock.recv(BUFFER_LIMIT - len(buffers[other[sock]]))
                except (BlockingIOError, ssl.SSLWantReadError):
                    read_wants[sock] = "read"
                    continue
                except ssl.SSLWantWriteError:
                    read_wants[sock] = "write"
                    continue
                read_wants[sock] = "read"
                if not data:
                    reading.remove(sock)
                else:
                    buffers[other[sock]].extend(data)
                    counts[sock] += len(data)
                    last_activity = time.monotonic()
            for sock in can_write:
                if sock not in ready[write_wants[sock]]:
                    continue
                if pending_writes[sock] is None:
                    pending_writes[sock] = bytes(buffers[sock])
                try:
                    sent = sock.send(pending_writes[sock])
                except (BlockingIOError, ssl.SSLWantWriteError):
                    write_wants[sock] = "write"
                    continue
                except ssl.SSLWantReadError:
                    write_wants[sock] = "read"
                    continue
                if sent == 0:
                    raise ConnectionError("tunnel write closed")
                del buffers[sock][:sent]
                pending_writes[sock] = None
                write_wants[sock] = "write"
                last_activity = time.monotonic()
    finally:
        LOG.info("[%s] tunnel payload bytes: upstream=%d downstream=%d",
                 name, counts[client], counts[upstream])


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        config = server.config
        upstream = None
        established = False

        started = time.monotonic()
        deadline = started + SETUP_TIMEOUT
        try:
            server.track(self.request)
            first, headers = read_headers(self.request, deadline)
            discovery = getattr(server, "peer_discovery", None)
            if (first == "GET /v1/node-peers HTTP/1.1" and discovery is not None
                    and not config.gateway_only):
                body = discovery.response(self.client_address[0], headers)
                send_headers(self.request, "HTTP/1.1 200 OK", {
                    "Content-Type": "application/json", "Content-Length": str(len(body)),
                    "Connection": "close", "Cache-Control": "no-store"}, deadline)
                self.request.sendall(body)
                return
            target, visited, hops, budget = parse_request(first, headers)
            deadline = min(deadline, started + budget)
            if not config.relay:
                raise RouteError(f"relaying disabled at {config.name}")
            route = open_route(config, target, visited=visited, hops=hops, deadline=deadline,
                               peer_discovery=discovery)
            upstream = route.socket
            server.track(upstream)
            send_headers(self.request, "HTTP/1.1 200 Connection Established",
                         {"X-Alternet-Route": json.dumps(route.nodes)}, deadline)
            established = True
            forward(self.request, upstream, config.name)
        except (OSError, ValueError) as exc:
            LOG.info("[%s] %s: %s", config.name, "tunnel closed" if established else "CONNECT rejected", exc)
            if not established:
                try:
                    send_headers(self.request, "HTTP/1.1 502 Route Unavailable",
                                 {"X-Alternet-Error": json.dumps(str(exc)), "Content-Length": "0"}, deadline)
                except OSError:
                    pass
        finally:
            if upstream is not None:
                server.untrack(upstream)
                upstream.close()
            server.untrack(self.request)


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config: Config):
        self.config = config
        self._active = set()
        self._lock = threading.Lock()
        self._closing = False
        if ":" in config.listen.host:
            self.address_family = socket.AF_INET6
        super().__init__((config.listen.host, config.listen.port), RelayHandler)
        from .peer_discovery import PeerDiscovery
        try:
            self.peer_discovery = PeerDiscovery(config, listen=Address(*self.server_address[:2]),
                                                track=self.track, untrack=self.untrack)
        except BaseException:
            super().server_close()
            raise

    def serve_forever(self, poll_interval=0.5):
        self.peer_discovery.start()
        super().serve_forever(poll_interval)

    def track(self, sock: socket.socket) -> None:
        with self._lock:
            if self._closing:
                sock.close()
                raise ConnectionError("node is shutting down")
            self._active.add(sock)

    def untrack(self, sock: socket.socket) -> None:
        with self._lock:
            self._active.discard(sock)

    def server_close(self) -> None:
        discovery = getattr(self, "peer_discovery", None)
        if discovery is not None:
            discovery.stop.set()
            discovery.wake.set()
        with self._lock:
            self._closing = True
            for sock in self._active:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        super().server_close()
        if discovery is not None:
            discovery.close()
