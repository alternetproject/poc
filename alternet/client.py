from dataclasses import dataclass
import http.client
import logging
import ssl
from urllib.parse import quote, urlsplit

from .config import Address, Config
from .routing import IDLE_TIMEOUT, SETUP_TIMEOUT, open_route

LOG = logging.getLogger("alternet")


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    route: tuple[str, ...]


def fetch(config: Config, url: str, *, ca_file: str | None = None) -> FetchResult:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None):
        raise ValueError("fetch requires an https:// URL without embedded credentials")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = 443 if parsed.port is None else parsed.port
    target = Address.parse(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
    context = ssl.create_default_context(cafile=ca_file)
    context.set_alpn_protocols(["http/1.1"])
    route = open_route(config, target)
    connection = http.client.HTTPConnection(host, port, timeout=IDLE_TIMEOUT)
    try:
        route.socket.settimeout(SETUP_TIMEOUT)
        tls = context.wrap_socket(route.socket, server_hostname=host)
        connection.sock = tls
        tls.settimeout(IDLE_TIMEOUT)
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parsed.query:
            path += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
        LOG.info("[%s] HTTPS status=%d body_bytes=%d route=%s -> %s",
                 config.name, response.status, len(body), " -> ".join(route.nodes), target)
        return FetchResult(response.status, body, route.nodes)
    finally:
        connection.close()
        route.socket.close()
