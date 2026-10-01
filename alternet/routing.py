from dataclasses import dataclass
from contextlib import closing
import json
import itertools
import logging
import math
import queue
import re
import socket
import threading
import time

from .config import Address, Config

LOG = logging.getLogger("alternet")
CONNECT_TIMEOUT = 2.0
SETUP_TIMEOUT = 10.0
IDLE_TIMEOUT = 30.0
MAX_HOPS = 3
MAX_HEADER = 16 * 1024


class RouteError(OSError):
    pass


def remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("route establishment deadline expired")
    return value


def connect_tcp(address: Address, deadline: float) -> socket.socket:
    deadline = min(deadline, time.monotonic() + CONNECT_TIMEOUT)
    results = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            results.put((socket.getaddrinfo(address.host, address.port, type=socket.SOCK_STREAM), None))
        except OSError as exc:
            results.put((None, exc))

    threading.Thread(target=resolve, daemon=True).start()
    try:
        addresses, error = results.get(timeout=remaining(deadline))
    except queue.Empty as exc:
        raise TimeoutError(f"DNS timeout for {address.host}") from exc
    if error:
        raise error
    last_error = None
    for family, kind, protocol, _, sockaddr in addresses:
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(remaining(deadline))
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise RouteError(f"cannot connect to {address}: {last_error}")


def read_headers(sock: socket.socket, deadline: float) -> tuple[str, dict[str, str]]:
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        sock.settimeout(remaining(deadline))
        part = sock.recv(1)
        if not part:
            raise RouteError("connection closed during CONNECT handshake")
        data.extend(part)
        if len(data) > MAX_HEADER:
            raise RouteError("CONNECT header too large")
    try:
        lines = data.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise RouteError("CONNECT headers must be ASCII") from exc
    headers = {}
    for line in lines[1:-2]:
        key, separator, value = line.partition(":")
        key = key.lower()
        if not separator or not re.fullmatch(r"[a-z0-9-]+", key) or key in headers:
            raise RouteError("malformed or duplicate CONNECT header")
        headers[key] = value.strip()
    return lines[0], headers


def send_headers(sock: socket.socket, first: str, headers: dict[str, str], deadline: float) -> None:
    message = first + "\r\n" + "".join(f"{key}: {value}\r\n" for key, value in headers.items()) + "\r\n"
    sock.settimeout(remaining(deadline))
    sock.sendall(message.encode("ascii"))


def parse_request(first: str, headers: dict[str, str]) -> tuple[Address, tuple[str, ...], int, float]:
    try:
        method, target, version = first.split(" ")
        if method != "CONNECT" or version != "HTTP/1.1":
            raise ValueError("expected HTTP/1.1 CONNECT")
        visited = json.loads(headers["x-alternet-visited"])
        if (not isinstance(visited, list) or not 1 <= len(visited) <= MAX_HOPS
                or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
                       for name in visited) or len(set(visited)) != len(visited)):
            raise ValueError("invalid visited nodes")
        hops = int(headers["x-alternet-hops"])
        budget = float(headers["x-alternet-budget"])
        if not 0 <= hops < MAX_HOPS or len(visited) + hops > MAX_HOPS:
            raise ValueError("invalid hop budget")
        if not math.isfinite(budget) or not 0 < budget <= SETUP_TIMEOUT:
            raise ValueError("invalid time budget")
        if "transfer-encoding" in headers or headers.get("content-length", "0") != "0":
            raise ValueError("CONNECT must not carry an HTTP body")
        return Address.parse(target), tuple(visited), hops, budget
    except (ValueError, KeyError, TypeError) as exc:
        raise RouteError(f"invalid CONNECT request: {exc}") from exc


@dataclass
class Route:
    socket: socket.socket
    nodes: tuple[str, ...]


def open_route(config: Config, target: Address, *, visited: tuple[str, ...] = (),
               hops: int = MAX_HOPS, deadline: float | None = None, peer_discovery=None) -> Route:
    deadline = deadline if deadline is not None else time.monotonic() + SETUP_TIMEOUT
    remaining(deadline)
    if config.name in visited:
        raise RouteError(f"routing loop at {config.name}")
    if target not in config.allowed_destinations:
        raise RouteError(f"destination {target} is not allowed by {config.name}")
    path = (*visited, config.name)
    if target in config.blocked_direct:
        LOG.info("[%s] SIMULATED BLOCK: direct TCP to %s", config.name, target)
    else:
        LOG.info("[%s] trying direct TCP to %s", config.name, target)
        try:
            sock = connect_tcp(target, deadline)
        except OSError as exc:
            LOG.info("[%s] direct connection failed: %s", config.name, exc)
        else:
            LOG.info("[%s] selected route: %s -> %s", config.name, " -> ".join(path), target)
            return Route(sock, path)

    if hops <= 0:
        raise RouteError(f"relay hop limit reached at {config.name}")
    if config.discovery:
        from .discovery import candidates
        peers = candidates(config, deadline)
    else:
        peers = ((peer, None) for peer in config.peers)
    if not config.gateway_only:
        from .peer_discovery import discovered_candidates
        with closing(discovered_candidates(config, deadline, peer_discovery)) as discovered:
            return _connect_peers(config, target, path, hops, deadline, itertools.chain(peers, discovered))
    return _connect_peers(config, target, path, hops, deadline, peers)


def _connect_peers(config, target, path, hops, deadline, peers) -> Route:
    if config.discovery:
        from .discovery import gateway_socket, GATEWAY_RESERVE
    for peer, gateway in peers:
        remaining(deadline)
        if config.discovery and gateway is None and deadline - time.monotonic() <= GATEWAY_RESERVE:
            continue
        attempt_deadline = deadline
        if config.discovery:
            attempt_deadline = min(deadline, time.monotonic() + CONNECT_TIMEOUT)
            if gateway is None:
                attempt_deadline = min(attempt_deadline, deadline - GATEWAY_RESERVE)
        LOG.info("[%s] trying %s %s for %s", config.name, "gateway" if gateway else "peer", peer, target)
        sock = None
        try:
            if gateway and config.gateway_transport == "curl":
                from .http_carrier import carrier_socket
                sock = carrier_socket(gateway, config.discovery_ca, attempt_deadline)
            else:
                sock = (gateway_socket(gateway, config.discovery_ca, attempt_deadline) if gateway
                        else connect_tcp(peer, attempt_deadline))
            send_headers(sock, f"CONNECT {target} HTTP/1.1", {
                "Host": str(target),
                "X-Alternet-Visited": json.dumps(path),
                "X-Alternet-Hops": str(hops - 1),
                "X-Alternet-Budget": str(remaining(attempt_deadline)),
            }, attempt_deadline)
            first, headers = read_headers(sock, attempt_deadline)
            if first != "HTTP/1.1 200 Connection Established":
                raise RouteError(f"peer refused: {first}; {headers.get('x-alternet-error', '')}")
            nodes = json.loads(headers.get("x-alternet-route", "null"))
            if (not isinstance(nodes, list) or not all(isinstance(node, str) for node in nodes)
                    or tuple(nodes[:len(path)]) != path or not len(path) < len(nodes) <= MAX_HOPS + 1
                    or len(set(nodes)) != len(nodes)):
                raise RouteError("invalid route in peer response")
            LOG.info("[%s] selected route: %s -> %s", config.name, " -> ".join(nodes), target)
            return Route(sock, tuple(nodes))
        except (OSError, ValueError) as exc:
            LOG.info("[%s] peer %s failed: %s", config.name, peer, exc)
            if sock is not None:
                sock.close()
    raise RouteError(f"no route from {config.name} to {target}")
