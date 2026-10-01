from dataclasses import dataclass
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Address:
    host: str
    port: int

    @classmethod
    def parse(cls, value: str, *, allow_zero: bool = False) -> "Address":
        if not isinstance(value, str) or any(c.isspace() for c in value):
            raise ValueError("addresses must be host:port strings without whitespace")
        parsed = urlsplit("//" + value)
        if (not parsed.hostname or parsed.port is None or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query or parsed.fragment):
            raise ValueError(f"invalid host:port address: {value!r}")
        if not (0 if allow_zero else 1) <= parsed.port <= 65535:
            raise ValueError(f"invalid port: {parsed.port}")
        return cls(parsed.hostname.encode("idna").decode("ascii").lower(), parsed.port)

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Config:
    name: str
    listen: Address
    peers: tuple[Address, ...]
    allowed_destinations: frozenset[Address]
    relay: bool = True
    blocked_direct: frozenset[Address] = frozenset()
    discovery: tuple[str, ...] = ()
    discovery_ca: str | None = None
    discovery_cache: str | None = None
    gateway_only: bool = False
    gateway_transport: str = "stdlib"
    bootstrap: tuple[Address, ...] = ()
    peer_cache: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        if not isinstance(data, dict):
            raise ValueError("configuration must be a JSON object")
        fields = {"name", "listen", "peers", "allowed_destinations", "relay", "blocked_direct",
                  "discovery", "discovery_ca", "discovery_cache", "gateway_only", "gateway_transport",
                  "bootstrap", "peer_cache"}
        if set(data) - fields:
            raise ValueError(f"unknown configuration fields: {sorted(set(data) - fields)}")
        name = data.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise ValueError("name must contain 1-64 letters, digits, dots, underscores, or hyphens")
        relay = data.get("relay", True)
        if not isinstance(relay, bool):
            raise ValueError("relay must be true or false")
        discovery = data.get("discovery", [])
        if not isinstance(discovery, list) or len(discovery) > 8:
            raise ValueError("discovery must be an array of at most eight HTTPS service URLs")
        discovery = tuple(discovery_url(value) for value in discovery)
        gateway_only = data.get("gateway_only", False)
        if type(gateway_only) is not bool or (gateway_only and not discovery):
            raise ValueError("gateway_only must be a boolean and requires discovery URLs when enabled")
        transport = data.get("gateway_transport", "stdlib")
        if transport not in ("stdlib", "curl"):
            raise ValueError("gateway_transport must be stdlib or curl")
        if transport == "curl" and not gateway_only:
            raise ValueError("curl transport requires gateway_only to avoid an identifiable fallback")
        for key in ("discovery_ca", "discovery_cache", "peer_cache"):
            if data.get(key) is not None and (not isinstance(data[key], str) or not data[key]):
                raise ValueError(f"{key} must be a nonempty file path")

        def addresses(key: str, *, required: bool = False) -> tuple[Address, ...]:
            values = data.get(key, None if required else [])
            if not isinstance(values, list):
                raise ValueError(f"{key} must be an explicit JSON array")
            return tuple(Address.parse(value) for value in values)

        bootstrap = addresses("bootstrap")
        if len(bootstrap) > 16:
            raise ValueError("bootstrap must contain at most sixteen ordinary peer addresses")
        if gateway_only and bootstrap:
            raise ValueError("bootstrap uses raw peer connections and cannot be combined with gateway_only")
        return cls(name, Address.parse(data.get("listen", "127.0.0.1:0"), allow_zero=True),
                   addresses("peers"), frozenset(addresses("allowed_destinations", required=True)),
                   relay, frozenset(addresses("blocked_direct")), discovery,
                   data.get("discovery_ca"), data.get("discovery_cache"), gateway_only, transport,
                   bootstrap, data.get("peer_cache"))

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        path = Path(path).resolve()
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            if data.get("discovery") and "discovery_cache" not in data:
                data["discovery_cache"] = str(path.with_suffix(".contacts.json"))
            if "peer_cache" not in data:
                data["peer_cache"] = str(path.with_suffix(".peers.sqlite"))
            for key in ("discovery_ca", "discovery_cache", "peer_cache"):
                if isinstance(data.get(key), str):
                    data[key] = str(path.parent / data[key])
        return cls.from_dict(data)

    def to_dict(self) -> dict:
        return {"name": self.name, "listen": str(self.listen),
                "peers": [str(peer) for peer in self.peers], "relay": self.relay,
                "allowed_destinations": sorted(map(str, self.allowed_destinations)),
                "blocked_direct": sorted(map(str, self.blocked_direct)),
                "discovery": list(self.discovery), "discovery_ca": self.discovery_ca,
                "discovery_cache": self.discovery_cache, "gateway_only": self.gateway_only,
                "gateway_transport": self.gateway_transport,
                "bootstrap": list(map(str, self.bootstrap)), "peer_cache": self.peer_cache}


def discovery_url(value: str) -> str:
    if not isinstance(value, str) or any(char.isspace() for char in value):
        raise ValueError("discovery URLs must be HTTPS service origins")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("discovery URLs must be HTTPS service origins without paths or credentials")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = 443 if parsed.port is None else parsed.port
    address = Address.parse(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
    return f"https://{address}"
