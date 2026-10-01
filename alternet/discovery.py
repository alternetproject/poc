from dataclasses import dataclass, replace
import http.server
import json
import logging
import mimetypes
import os
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.parse import unquote, urlsplit
import uuid

from .config import Address, Config, discovery_url
from .discovery_store import DiscoveryStore
from .node import forward
from .routing import (RouteError, SETUP_TIMEOUT, connect_tcp, open_route,
                      parse_request, read_headers, remaining, send_headers)

LOG = logging.getLogger("alternet")
MAX_RESPONSE = 16 * 1024
DISCOVERY_TIMEOUT = 2.0
GATEWAY_RESERVE = 3.0


@dataclass(frozen=True)
class ServiceConfig:
    node: Config
    cert: str
    key: str
    state: str
    contacts: tuple[Address, ...]
    bundle_size: int = 3
    disclosure_budget: int = 6
    window_seconds: int = 86400
    lease_seconds: int = 3600
    site_root: str | None = None

    @classmethod
    def load(cls, filename: str | Path) -> "ServiceConfig":
        path = Path(filename).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        allowed = {"node", "cert", "key", "state", "contacts", "bundle_size",
                   "disclosure_budget", "window_seconds", "lease_seconds", "site_root"}
        if not isinstance(data, dict) or set(data) - allowed:
            raise ValueError("invalid discovery service configuration")
        try:
            node = Config.from_dict(data["node"])
            if node.discovery or node.peers or node.bootstrap or node.peer_cache:
                raise ValueError("gateway upstream peers come only from the caller's disclosed contacts")
            files = []
            for field in ("cert", "key", "state"):
                if not isinstance(data[field], str) or not data[field]:
                    raise ValueError(f"{field} must be a file path")
                files.append(str(path.parent / data[field]))
            if not isinstance(data["contacts"], list) or len(data["contacts"]) > 100000:
                raise ValueError("contacts must be an array of at most 100,000 relay addresses")
            contacts = tuple(dict.fromkeys(Address.parse(value) for value in data["contacts"]))
            numbers = []
            for field, default in (("bundle_size", 3), ("disclosure_budget", 6),
                                   ("window_seconds", 86400), ("lease_seconds", 3600)):
                value = data.get(field, default)
                if type(value) is not int:
                    raise ValueError(f"{field} must be an integer")
                numbers.append(value)
            if not 1 <= numbers[0] <= numbers[1] <= 64:
                raise ValueError("require 1 <= bundle_size <= disclosure_budget <= 64")
            if not 1 <= numbers[2] <= 365 * 86400 or not 1 <= numbers[3] <= 86400:
                raise ValueError("invalid budget window or contact lease duration")
            site_root = data.get("site_root")
            if site_root is not None:
                if not isinstance(site_root, str) or not site_root:
                    raise ValueError("site_root must be a directory path")
                site_root = str((path.parent / site_root).resolve())
                if not Path(site_root).is_dir():
                    raise ValueError("site_root must name an existing directory")
            return cls(node, *files, contacts, *numbers, site_root)
        except KeyError as exc:
            raise ValueError(f"missing discovery configuration field: {exc}") from exc


class DiscoveryHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        self.request.settimeout(DISCOVERY_TIMEOUT)
        self.request.do_handshake()
        super().setup()

    def _contacts(self) -> tuple[Address, ...]:
        return self.server.store.contacts(self.client_address[0], self.server.config.contacts)

    def do_GET(self) -> None:
        if self.path != "/v1/peers":
            self._site()
            return
        config = self.server.config
        try:
            contacts = self._contacts()
        except Exception:
            LOG.exception("discovery database error")
            self.send_error(503)
            return
        body = json.dumps({"version": 1, "peers": list(map(str, contacts)),
                           "lease_seconds": config.lease_seconds,
                           "gateway": config.node.relay}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_HEAD(self) -> None:
        self._site(head=True)

    def do_POST(self) -> None:
        from .http_carrier import handle_post
        handle_post(self)

    def _site(self, *, head: bool = False) -> None:
        root = self.server.config.site_root
        if root is None:
            self.send_error(404)
            return
        root = Path(root).resolve()
        try:
            name = unquote(urlsplit(self.path).path, errors="strict")

            if "\\" in name or ":" in name or "\x00" in name:
                raise ValueError("invalid site path")
            path = (root / name.lstrip("/")).resolve()
            if path.is_dir():
                path = (path / "index.html").resolve()
            if not path.is_relative_to(root) or not path.is_file():
                raise ValueError("site path not found")
            source = path.open("rb")
        except (OSError, ValueError):
            self.send_error(404)
            return
        with source:
            self.connection.settimeout(30)
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(path.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(os.fstat(source.fileno()).st_size))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if not head:
                while block := source.read(64 * 1024):
                    self.wfile.write(block)

    def do_CONNECT(self) -> None:
        started = time.monotonic()
        deadline = started + SETUP_TIMEOUT
        config = self.server.config.node
        upstream = None
        established = False
        self.close_connection = True
        try:
            headers = {key.lower(): value for key, value in self.headers.items()}
            if len(headers) != len(self.headers):
                raise RouteError("duplicate CONNECT headers")
            target, visited, hops, budget = parse_request(self.requestline, headers)
            deadline = min(deadline, started + budget)
            if not config.relay:
                raise RouteError("gateway forwarding disabled")

            gateway_config = replace(config, peers=self._contacts())
            route = open_route(gateway_config, target, visited=visited, hops=hops, deadline=deadline)
            upstream = route.socket
            send_headers(self.connection, "HTTP/1.1 200 Connection Established",
                         {"X-Alternet-Route": json.dumps(route.nodes)}, deadline)
            established = True
            LOG.info("[%s] gateway tunnel established", config.name)
            forward(self.connection, upstream, config.name)
        except (OSError, ValueError) as exc:
            LOG.info("[%s] gateway request failed: %s", config.name, exc)
            if not established:
                try:
                    send_headers(self.connection, "HTTP/1.1 502 Route Unavailable",
                                 {"Content-Length": "0"}, deadline)
                except OSError:
                    pass
        finally:
            if upstream is not None:
                upstream.close()

    def log_message(self, format: str, *args) -> None:
        pass


class DiscoveryServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, config: ServiceConfig):
        self.config = config
        self.store = DiscoveryStore(config.state, bundle_size=config.bundle_size,
                                    budget=config.disclosure_budget, window_seconds=config.window_seconds)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(config.cert, config.key)
        self.context.set_alpn_protocols(["http/1.1"])
        self._active = set()
        self._lock = threading.Lock()
        self._closing = False
        if ":" in config.node.listen.host:
            self.address_family = socket.AF_INET6
        super().__init__((config.node.listen.host, config.node.listen.port), DiscoveryHandler)
        from .http_carrier import CarrierSessions
        self.carriers = CarrierSessions(self)

    def get_request(self):
        connection, address = super().get_request()
        try:
            secured = self.context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
        except BaseException:
            connection.close()
            raise
        self.track(secured)
        return secured, address

    def track(self, connection):
        with self._lock:
            if self._closing:
                connection.close()
                raise ConnectionError("discovery service closing")
            self._active.add(connection)

    def untrack(self, connection):
        with self._lock:
            self._active.discard(connection)

    def close_request(self, request):
        with self._lock:
            self._active.discard(request)
        super().close_request(request)

    def handle_error(self, request, client_address):
        LOG.debug("discovery connection ended during TLS or request handling", exc_info=True)

    def server_close(self):
        if hasattr(self, "carriers"):
            self.carriers.close()
        with self._lock:
            self._closing = True
            for connection in self._active:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        super().server_close()


def service_address(url: str) -> Address:
    parsed = urlsplit(discovery_url(url))
    return Address(parsed.hostname, parsed.port)


def _tls_connect(url: str, ca_file: str | None, deadline: float) -> ssl.SSLSocket:
    address = service_address(url)
    context = ssl.create_default_context(cafile=ca_file)
    context.set_alpn_protocols(["http/1.1"])
    raw = connect_tcp(address, deadline)
    try:
        raw.settimeout(remaining(deadline))
        return context.wrap_socket(raw, server_hostname=address.host)
    except BaseException:
        raw.close()
        raise


def request_contacts(url: str, ca_file: str | None, deadline: float) -> dict:
    deadline = min(deadline, time.monotonic() + DISCOVERY_TIMEOUT)
    address = service_address(url)
    with _tls_connect(url, ca_file, deadline) as wire:
        send_headers(wire, "GET /v1/peers HTTP/1.1",
                     {"Host": str(address), "Connection": "close"}, deadline)
        first, headers = read_headers(wire, deadline)
        if first.split(" ")[:2] != ["HTTP/1.1", "200"]:
            raise RouteError(f"discovery returned {first}")

        length = headers.get("content-length")
        if length is None or not length.isdecimal() or not 0 < int(length) <= MAX_RESPONSE:
            raise RouteError("invalid discovery response length")
        if "transfer-encoding" in headers:
            raise RouteError("unsupported discovery response framing")
        payload = bytearray()
        while len(payload) < int(length):
            wire.settimeout(remaining(deadline))
            part = wire.recv(int(length) - len(payload))
            if not part:
                raise RouteError("truncated discovery response")
            payload.extend(part)
        data = json.loads(payload)
        if not isinstance(data, dict) or data.get("version") != 1:
            raise RouteError("unsupported discovery response")
        peers = data.get("peers")
        lease = data.get("lease_seconds")
        if not isinstance(peers, list) or len(peers) > 64 or type(data.get("gateway")) is not bool:
            raise RouteError("invalid discovery contacts")
        if type(lease) is not int or not 1 <= lease <= 86400:
            raise RouteError("invalid contact lease")
        return {"peers": list(dict.fromkeys(str(Address.parse(peer)) for peer in peers)),
                "expires": time.time() + lease, "gateway": data["gateway"]}


def cached_contacts(config: Config) -> dict:
    if not config.discovery_cache:
        return {}
    try:
        data = json.loads(Path(config.discovery_cache).read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("services"), dict):
            return {}
        result = {}
        for url in config.discovery:
            entry = data["services"].get(url)
            if not isinstance(entry, dict) or not isinstance(entry.get("expires"), (int, float)):
                continue
            if not time.time() < entry["expires"] <= time.time() + 86401:
                continue
            if (not isinstance(entry.get("peers"), list) or len(entry["peers"]) > 64
                    or type(entry.get("gateway")) is not bool):
                continue
            result[url] = {**entry, "peers": list(map(str, (Address.parse(peer) for peer in entry["peers"])))}
        return result
    except (OSError, ValueError, TypeError):
        return {}


def save_contacts(config: Config, services: dict) -> None:
    if not config.discovery_cache:
        return
    path = Path(config.discovery_cache)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps({"version": 1, "services": services}, indent=2), encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        LOG.warning("[%s] could not save contact cache: %s", config.name, exc)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def candidates(config: Config, deadline: float):
    if config.gateway_only:
        for url in config.discovery:
            yield service_address(url), url
        return
    seen = set()
    services = cached_contacts(config)
    for peer in config.peers:
        seen.add(peer)
        yield peer, None
    for entry in services.values():
        for value in entry["peers"]:
            peer = Address.parse(value)
            if peer not in seen and deadline - time.monotonic() > GATEWAY_RESERVE:
                seen.add(peer)
                yield peer, None
    for url in config.discovery:
        if deadline - time.monotonic() <= GATEWAY_RESERVE:
            break
        try:
            entry = request_contacts(url, config.discovery_ca, deadline - GATEWAY_RESERVE)
            services[url] = entry
            save_contacts(config, services)
            LOG.info("[%s] discovery %s supplied %d contacts", config.name, url, len(entry["peers"]))
            for value in entry["peers"]:
                peer = Address.parse(value)
                if peer not in seen and deadline - time.monotonic() > GATEWAY_RESERVE:
                    seen.add(peer)
                    yield peer, None
        except (OSError, ValueError) as exc:
            LOG.info("[%s] discovery %s unavailable: %s", config.name, url, exc)

    for url in config.discovery:
        if services.get(url, {}).get("gateway", True):
            yield service_address(url), url


def gateway_socket(url: str, ca_file: str | None, deadline: float) -> socket.socket:
    secured = _tls_connect(url, ca_file, deadline)
    try:
        client, bridge = socket.socketpair()
    except BaseException:
        secured.close()
        raise

    def run():
        with bridge, secured:
            try:
                forward(bridge, secured, "gateway transport")
            except (OSError, ValueError) as exc:
                LOG.debug("gateway transport closed: %s", exc)

    threading.Thread(target=run, daemon=True).start()
    return client
