from dataclasses import replace
from datetime import datetime, timedelta, timezone
import http.server
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from .config import Address, Config

DEMO_BODY = b"Hello from an ordinary HTTPS server, reached with Alternet.\n"


def make_certificates(directory: Path, hostname: str = "localhost", *,
                      extra_hosts: tuple[str, ...] = ()) -> tuple[Path, Path, Path]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError as exc:
        raise RuntimeError("Install cryptography to run demos and tests: python -m pip install cryptography") from exc

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Alternet temporary demo CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=None, decipher_only=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = []
    for host in dict.fromkeys((hostname, *extra_hosts)):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
          .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = (directory / filename for filename in ("ca.pem", "server.pem", "server-key.pem"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return ca_path, cert_path, key_path


def write_ready(path: str | Path | None, address: tuple) -> None:
    if path is not None:
        Path(path).write_text(json.dumps({"host": address[0], "port": address[1]}), encoding="utf-8")


def serve_origin(cert: str, key: str, body_path: str, ready_file: str) -> None:
    body = Path(body_path).read_bytes()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, format: str, *args) -> None:
            print("[origin] " + format % args, file=sys.stderr, flush=True)

    class Origin(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            try:
                return context.wrap_socket(connection, server_side=True), address
            except BaseException:
                connection.close()
                raise

    with Origin(("127.0.0.1", 0), Handler) as server:
        write_ready(ready_file, server.server_address)
        server.serve_forever(poll_interval=0.1)


class Child:
    def __init__(self, arguments: list[str], ready: Path, *, echo: bool):
        self.lines: list[str] = []
        self.process = subprocess.Popen(
            [sys.executable, "-u", "-m", "alternet", *arguments, "--ready-file", str(ready)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

        def drain() -> None:
            for line in self.process.stdout:
                self.lines.append(line)
                if echo:
                    print(line, end="", file=sys.stderr, flush=True)

        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("child exited during startup: " + "".join(self.lines))
                try:
                    data = json.loads(ready.read_text(encoding="utf-8"))
                    self.address = Address(data["host"], data["port"])
                    return
                except (FileNotFoundError, json.JSONDecodeError):
                    time.sleep(0.02)
            raise TimeoutError("child startup timed out: " + "".join(self.lines))
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=3)
        self.process.stdout.close()


class Lab:
    def __init__(self, *, echo: bool = False, cert_hostname: str = "localhost", body: bytes = DEMO_BODY,
                 cert_extra_hosts: tuple[str, ...] = ()):
        self.echo = echo
        self.cert_hostname = cert_hostname
        self.cert_extra_hosts = cert_extra_hosts
        self.body = body
        self.children: list[Child] = []
        self.nodes: dict[str, Child] = {}
        self.configs: dict[str, Config] = {}
        self.services: dict[str, Child] = {}
        self._sequence = 0

    def __enter__(self) -> "Lab":
        self._temp = tempfile.TemporaryDirectory(prefix="alternet-")
        self.directory = Path(self._temp.name)
        try:
            self.ca, cert, key = make_certificates(self.directory, self.cert_hostname,
                                                 extra_hosts=self.cert_extra_hosts)
            body = self.directory / "body.bin"
            body.write_bytes(self.body)
            self.origin = self._start(["_origin", "--cert", str(cert), "--key", str(key), "--body", str(body)])
            self.target = Address("localhost", self.origin.address.port)
            self.url = f"https://{self.target}/"
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _start(self, arguments: list[str]) -> Child:
        self._sequence += 1
        child = Child(arguments, self.directory / f"ready-{self._sequence}.json", echo=self.echo)
        self.children.append(child)
        return child

    def config(self, name: str, *, peers: tuple[Address, ...] = (), blocked: bool = False,
               relay: bool = True, target: Address | None = None) -> Config:
        target = self.target if target is None else target
        return Config(name, Address("127.0.0.1", 0), tuple(peers), frozenset({target}), relay,
                      frozenset({target}) if blocked else frozenset())

    def start_node(self, config: Config) -> Child:
        if config.name in self.nodes:
            self.nodes[config.name].stop()
        path = self.directory / f"{config.name}.json"
        if config.peer_cache is None:
            config = replace(config, peer_cache=str(path.with_suffix(".peers.sqlite")))
        path.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")
        child = self._start(["node", "--config", str(path)])
        self.nodes[config.name] = child
        self.configs[config.name] = replace(config, listen=child.address)
        path.write_text(json.dumps(self.configs[config.name].to_dict(), indent=2), encoding="utf-8")
        return child

    def start_discovery(self, name: str, contacts: tuple[Address, ...], *, relay: bool = True,
                        bundle_size: int = 3, disclosure_budget: int = 6,
                        blocked: bool = False, site_root: str | None = None) -> tuple[Child, str]:
        listen = Address("127.0.0.1", 0)
        if name in self.services:
            listen = self.services[name].address
            self.services[name].stop()
        config = replace(self.config(name, relay=relay, blocked=blocked), listen=listen)
        path = self.directory / f"{name}-discovery.json"
        path.write_text(json.dumps({"node": config.to_dict(),
                                    "cert": str(self.directory / "server.pem"),
                                    "key": str(self.directory / "server-key.pem"),
                                    "state": str(self.directory / f"{name}.sqlite"),
                                    "contacts": list(map(str, contacts)), "bundle_size": bundle_size,
                                    "disclosure_budget": disclosure_budget,
                                    "site_root": site_root}, indent=2), encoding="utf-8")
        child = self._start(["discovery", "--config", str(path)])
        self.services[name] = child
        return child, f"https://localhost:{child.address.port}"

    def discovery_client(self, urls: tuple[str, ...], name: str = "A") -> Config:
        return replace(self.config(name, blocked=True), discovery=urls, discovery_ca=str(self.ca),
                       discovery_cache=str(self.directory / f"{name}.contacts.json"))

    def __exit__(self, *_args) -> None:
        try:
            for child in reversed(self.children):
                child.stop()
        finally:
            self._temp.cleanup()
