from contextlib import contextmanager
import ipaddress
import json
import logging
import re
import sqlite3
import threading
import time

from .config import Address, Config
from .routing import connect_tcp, read_headers, remaining, send_headers

LOG = logging.getLogger("alternet")
LEASE = 120.0
REFRESH = 30.0
CAPACITY = 128
BUNDLE = 16
MAX_BODY = 16384
PATH = "/v1/node-peers"


class PeerBook:
    def __init__(self, path: str | None = None):
        self.lock = threading.RLock()
        self.closed = False
        self.db = sqlite3.connect(path or ":memory:", timeout=1, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""CREATE TABLE IF NOT EXISTS peers (
            address TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '',
            relay INTEGER NOT NULL DEFAULT 0, expires REAL NOT NULL DEFAULT 0,
            checked REAL NOT NULL DEFAULT 0, retry REAL NOT NULL DEFAULT 0,
            failures INTEGER NOT NULL DEFAULT 0, seed INTEGER NOT NULL DEFAULT 0)""")
        self.db.commit()

    @contextmanager
    def transaction(self):
        with self.lock:
            if self.closed:
                raise ConnectionError("peer discovery is shutting down")
            with self.db:
                yield self.db

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def hint(self, address: Address, *, seed=False):
        with self.transaction() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM peers WHERE address=?", (str(address),)).fetchone():
                if seed:
                    db.execute("UPDATE peers SET seed=1 WHERE address=?", (str(address),))
                return
            if db.execute("SELECT count(*) FROM peers").fetchone()[0] >= CAPACITY:
                row = db.execute("SELECT address FROM peers WHERE seed=0 "
                                 "ORDER BY (expires>?), checked LIMIT 1", (time.time(),)).fetchone()
                if row is None:
                    return
                db.execute("DELETE FROM peers WHERE address=?", (row[0],))
            db.execute("INSERT INTO peers(address, seed) VALUES (?, ?)", (str(address), int(seed)))

    def success(self, address: Address, name: str, relay: bool, *, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            db.execute("UPDATE peers SET name=?, relay=?, expires=?, checked=?, retry=?, failures=0 "
                       "WHERE address=?", (name, int(relay), now + LEASE, now, now + REFRESH, str(address)))

    def failure(self, address: Address, *, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            row = db.execute("SELECT failures FROM peers WHERE address=?", (str(address),)).fetchone()
            if row:
                count = min(row[0] + 1, 5)
                db.execute("UPDATE peers SET expires=0, checked=?, retry=?, failures=? WHERE address=?",
                           (now, now + min(60, 2 ** count), count, str(address)))

    def live(self, *, relays_only=False, now=None) -> list[dict]:
        now = time.time() if now is None else now
        with self.transaction() as db:
            rows = db.execute("SELECT address, name, relay, expires FROM peers WHERE expires>? "
                              "AND (?=0 OR relay=1) ORDER BY address", (now, int(relays_only))).fetchall()
        return [{**dict(row), "relay": bool(row["relay"])} for row in rows]

    def due(self, *, force=False, now=None) -> list[Address]:
        now = time.time() if now is None else now
        with self.transaction() as db:
            rows = db.execute("SELECT address FROM peers WHERE retry<=? OR (? AND failures=0) "
                              "ORDER BY checked, address", (now, int(force))).fetchall()
        return [Address.parse(row[0]) for row in rows]


def validate_payload(data) -> dict:
    if (not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1
            or not isinstance(data.get("name"), str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", data["name"])
            or type(data.get("relay")) is not bool
            or not isinstance(data.get("peers"), list) or len(data["peers"]) > BUNDLE):
        raise ValueError("invalid peer discovery response")
    return {**data, "peers": tuple(dict.fromkeys(Address.parse(value) for value in data["peers"]))}


def query(address: Address, deadline: float, *, announce_port=0, track=None, untrack=None,
          observe_local=None) -> dict:
    deadline = min(deadline, time.monotonic() + 2)
    with connect_tcp(address, deadline) as sock:
        if track:
            track(sock)
        try:
            if observe_local:
                observe_local(sock.getsockname()[0])
            headers = {"Host": str(address), "Connection": "close"}
            if announce_port:
                headers["X-Alternet-Listen-Port"] = str(announce_port)
            send_headers(sock, f"GET {PATH} HTTP/1.1", headers, deadline)
            first, headers = read_headers(sock, deadline)
            length = int(headers.get("content-length", "-1"))
            if first != "HTTP/1.1 200 OK" or "transfer-encoding" in headers or not 0 <= length <= MAX_BODY:
                raise ValueError("invalid peer discovery HTTP response")
            body = bytearray()
            while len(body) < length:
                sock.settimeout(remaining(deadline))
                part = sock.recv(length - len(body))
                if not part:
                    raise ConnectionError("truncated peer discovery response")
                body.extend(part)
            return validate_payload(json.loads(body))
        finally:
            if untrack:
                untrack(sock)


class PeerDiscovery:
    def __init__(self, config: Config, *, listen: Address | None = None, track=None, untrack=None):
        self.config = config
        self.listen = listen
        self.book = PeerBook(config.peer_cache)
        self.track, self.untrack = track, untrack
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.worker = None
        self.cursor = 0
        self.exchange_lock = threading.Lock()
        self.refresh_lock = threading.Lock()
        self.self_hosts = {listen.host} if listen else set()
        with self.book.transaction() as db:
            db.execute("UPDATE peers SET seed=0")
        for address in config.bootstrap:
            self.book.hint(address, seed=True)

    def is_self(self, address: Address) -> bool:
        with self.exchange_lock:
            return (self.listen is not None and address.port == self.listen.port
                    and address.host in self.self_hosts)

    def observe_local(self, host):
        with self.exchange_lock:
            self.self_hosts.add(host)

    def response(self, source_host: str, headers: dict) -> bytes:
        if "transfer-encoding" in headers or headers.get("content-length", "0") != "0":
            raise ValueError("peer discovery GET must not have a body")
        if "x-alternet-listen-port" in headers:
            port = int(headers["x-alternet-listen-port"])
            if not 1 <= port <= 65535:
                raise ValueError("invalid advertised listening port")

            host = ipaddress.ip_address(source_host)
            host = str(getattr(host, "ipv4_mapped", None) or host)
            address = Address(host, port)
            if not self.is_self(address):
                self.book.hint(address)
                self.wake.set()
        with self.exchange_lock:
            live = self.book.live()
            start = self.cursor % max(1, len(live))
            batch = (live[start:] + live[:start])[:BUNDLE]
            self.cursor += BUNDLE
        return json.dumps({"version": 1, "name": self.config.name, "relay": self.config.relay,
                           "peers": [entry["address"] for entry in batch]}).encode("utf-8")

    def refresh(self, deadline: float, *, force=False, max_queries=16):
        if not self.refresh_lock.acquire(timeout=max(0, deadline - time.monotonic())):
            return
        try:
            tried = set()
            while not self.stop.is_set() and time.monotonic() < deadline and len(tried) < max_queries:
                pending = [p for p in self.book.due(force=force) if p not in tried and not self.is_self(p)]
                if not pending:
                    break
                address = pending[0]
                tried.add(address)
                LOG.info("[%s] discovery probing %s", self.config.name, address)
                try:
                    data = query(address, deadline, announce_port=self.listen.port if self.listen else 0,
                                 track=self.track, untrack=self.untrack, observe_local=self.observe_local)
                except (OSError, ValueError) as exc:
                    self.book.failure(address)
                    LOG.info("[%s] discovery contact %s unavailable: %s", self.config.name, address, exc)
                    continue
                self.book.success(address, data["name"], data["relay"])
                for peer in data["peers"]:
                    if not self.is_self(peer):
                        self.book.hint(peer)
                LOG.info("[%s] discovered %s at %s; relay=%s", self.config.name,
                         data["name"], address, data["relay"])
        finally:
            self.refresh_lock.release()

    def start(self):
        if self.config.gateway_only:
            return
        def run():
            while not self.stop.is_set():
                self.wake.clear()
                try:
                    self.refresh(time.monotonic() + 2, max_queries=8)
                except (OSError, sqlite3.Error) as exc:
                    LOG.warning("[%s] discovery refresh failed: %s", self.config.name, exc)
                self.wake.wait(1)
        self.worker = threading.Thread(target=run, name=f"discovery-{self.config.name}", daemon=True)
        self.worker.start()

    def close(self):
        self.stop.set()
        self.wake.set()
        if self.worker:
            self.worker.join(timeout=3)
        self.book.close()


def discovered_candidates(config: Config, deadline: float, manager: PeerDiscovery | None = None):
    if config.gateway_only:
        return
    owned = manager is None
    if owned:
        manager = PeerDiscovery(config)
    seen = set(config.peers)
    try:
        for entry in manager.book.live(relays_only=True):
            peer = Address.parse(entry["address"])
            if peer not in seen and not manager.is_self(peer):
                seen.add(peer)
                yield peer, None

        manager.refresh(min(deadline - 3, time.monotonic() + 4), force=True)
        for entry in manager.book.live(relays_only=True):
            peer = Address.parse(entry["address"])
            if peer not in seen and not manager.is_self(peer):
                seen.add(peer)
                yield peer, None
    finally:
        if owned:
            manager.close()
