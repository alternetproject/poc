import base64
import ipaddress
import json

from alternet.config import Address
from experiments.wire_filter import WireFilter

HOST = "crypto.cloudflare.com"
RESOLVER = "https://cloudflare-dns.com/dns-query"


def configuration(document):
    if document.get("Status") != 0:
        raise ValueError("DNS query failed")
    for answer in document.get("Answer", []):
        if answer.get("type") != 65 or answer.get("name", "").rstrip(".") != HOST:
            continue
        fields = answer.get("data", "").split()
        if len(fields) < 3 or fields[:2] != ["1", "."]:
            continue
        options = dict(field.split("=", 1) for field in fields[2:] if "=" in field)
        if "ech" not in options or "ipv4hint" not in options:
            continue
        ech = options["ech"]
        raw = base64.b64decode(ech, validate=True)
        if len(raw) < 4 or int.from_bytes(raw[:2], "big") != len(raw) - 2:
            raise ValueError("invalid ECHConfigList framing")
        address = str(ipaddress.IPv4Address(options["ipv4hint"].split(",")[0]))
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("public probe requires a public edge address")
        return ech, address
    raise ValueError("test hostname has no supported HTTPS record with ECH and IPv4 hints")


def run():
    try:
        from curl_cffi import CurlOpt
        from curl_cffi.requests import Session
        from curl_cffi.requests.exceptions import RequestException
    except ImportError as exc:
        raise RuntimeError("Install curl_cffi: python -m pip install curl_cffi==0.16.3") from exc

    with Session(impersonate="chrome", trust_env=False) as session:
        response = session.get(RESOLVER, params={"name": HOST, "type": "HTTPS"},
                               headers={"accept": "application/dns-json"},
                               timeout=10, allow_redirects=False)
        response.raise_for_status()
        ech, address = configuration(response.json())

    results = []
    with WireFilter(Address(address, 443)) as wire:
        def request(label, *, use_ech, blocked=False):
            wire.observations.clear()

            options = {CurlOpt.ECH: "ecl:" + ech if use_ech else "false",
                       CurlOpt.RESOLVE: [f"{HOST}:{wire.address.port}:127.0.0.1"]}
            failure = None
            reply = None
            with Session(impersonate="chrome", trust_env=False, curl_options=options) as session:
                try:
                    reply = session.get(f"https://{HOST}:{wire.address.port}/cdn-cgi/trace",
                                        headers={"Host": HOST}, timeout=10, allow_redirects=False)
                    reply.raise_for_status()
                    if reply.status_code != 200:
                        raise RuntimeError(f"{label}: unexpected HTTP status {reply.status_code}")
                except RequestException as exc:
                    failure = exc
            observations = list(wire.observations)
            if blocked:
                if failure is None or not observations or not all(b for _, b in observations):
                    raise RuntimeError(f"{label}: expected observed filter rejection")
            else:
                if failure is not None:
                    raise RuntimeError(f"{label}: public test request failed: {failure}") from failure
                if not observations or any(b for _, b in observations):
                    raise RuntimeError(f"{label}: missing permitted wire observation")
                trace = dict(line.split("=", 1) for line in reply.text.splitlines() if "=" in line)
                if use_ech:
                    if trace.get("sni") != "encrypted" or any(h.server_name == HOST for h, _ in observations):
                        raise RuntimeError("ECH was not confirmed; plaintext fallback is not a success")
                elif any(h.server_name != HOST for h, _ in observations):
                    raise RuntimeError("plaintext SNI control did not expose the expected hostname")
            item = {"case": label, "outcome": "blocked" if blocked else "HTTP 200",
                    "visible_sni": sorted({h.server_name for h, _ in observations if h.server_name})}
            results.append(item)
            print(json.dumps(item), flush=True)
            return item

        request("ordinary TLS control", use_ech=False)
        wire.rule = lambda hello: hello.server_name == HOST
        request("target hostname rule, ordinary TLS", use_ech=False, blocked=True)
        encrypted = request("target hostname rule, ECH", use_ech=True)
        outer_names = frozenset(encrypted["visible_sni"])
        if not outer_names:
            raise RuntimeError("probe requires an observable shared outer SNI")
        wire.rule = lambda hello: hello.server_name in outer_names
        request("shared outer hostname rule, ECH", use_ech=True, blocked=True)
        request("shared outer hostname rule, ordinary TLS", use_ech=False)

    return results


if __name__ == "__main__":
    run()
