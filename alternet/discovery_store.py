from contextlib import closing
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import secrets
import sqlite3
import time

from .config import Address


def source_prefix(source: str) -> str:
    address = ipaddress.ip_address(source.split("%", 1)[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(ipaddress.ip_network(f"{address}/{24 if address.version == 4 else 56}", strict=False))


class DiscoveryStore:
    def __init__(self, path: str | Path, *, bundle_size: int = 3, budget: int = 6,
                 window_seconds: int = 86400):
        if not 1 <= bundle_size <= budget <= 64 or not 1 <= window_seconds <= 365 * 86400:
            raise ValueError("require 1 <= bundle_size <= budget <= 64 and a 1s..1y budget window")
        self.path = str(path)
        self.bundle_size = bundle_size
        self.budget = budget
        self.window_seconds = window_seconds
        with closing(self._connect()) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            db.execute("INSERT OR IGNORE INTO meta VALUES ('secret', ?)", (secrets.token_bytes(32),))
            self.secret = db.execute("SELECT value FROM meta WHERE key = 'secret'").fetchone()[0]
            db.execute("CREATE TABLE IF NOT EXISTS cohorts (id TEXT PRIMARY KEY, active TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS disclosures (cohort TEXT, address TEXT, issued REAL, "
                       "PRIMARY KEY(cohort,address))")
            db.execute("CREATE INDEX IF NOT EXISTS recent_disclosures ON disclosures(cohort,issued)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=2)

    def contacts(self, source_ip: str, inventory: tuple[Address, ...], *, now: float | None = None) -> tuple[Address, ...]:
        now = time.time() if now is None else now
        cohort = hmac.new(self.secret, source_prefix(source_ip).encode(), hashlib.sha256).hexdigest()
        available = set(map(str, inventory))

        with closing(self._connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT active FROM cohorts WHERE id=?", (cohort,)).fetchone()
            active = [entry for entry in json.loads(row[0]) if entry in available] if row else []
            issued = dict(db.execute("SELECT address,issued FROM disclosures WHERE cohort=?", (cohort,)))
            count = sum(timestamp > now - self.window_seconds for timestamp in issued.values())
            candidates = active + sorted(available - set(active), key=lambda value: hmac.new(
                self.secret, f"{cohort}:{value}".encode(), hashlib.sha256).digest())
            active = []
            for candidate in candidates:
                if len(active) >= self.bundle_size:
                    break
                if issued.get(candidate, float("-inf")) <= now - self.window_seconds:
                    if count >= self.budget:
                        continue
                    count += 1

                db.execute("INSERT INTO disclosures VALUES (?,?,?) ON CONFLICT(cohort,address) "
                           "DO UPDATE SET issued=excluded.issued", (cohort, candidate, now))
                active.append(candidate)
            db.execute("INSERT INTO cohorts VALUES (?,?) ON CONFLICT(id) DO UPDATE SET active=excluded.active",
                       (cohort, json.dumps(active)))
        return tuple(Address.parse(address) for address in active)
