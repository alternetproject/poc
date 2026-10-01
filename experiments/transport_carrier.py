from dataclasses import replace

from alternet.client import fetch
from alternet.http_carrier import PROFILE
from alternet.lab import DEMO_BODY, Lab
from alternet.routing import RouteError
from .shared_endpoint import SITE_BODY, ordinary_get
from .wire_filter import WireFilter


def run():
    from curl_cffi.requests import Session
    from curl_cffi.requests.exceptions import RequestException

    with Lab() as lab:
        site = lab.directory / "site"
        site.mkdir()
        (site / "index.html").write_bytes(SITE_BODY)
        backend, _ = lab.start_discovery("shared-entry", (), site_root=str(site))
        with WireFilter(backend.address) as censor:
            stock = replace(lab.discovery_client((censor.url,)), gateway_only=True)
            client = replace(stock, gateway_transport="curl")
            ordinary_get(censor.url, lab.ca)
            old_profile = censor.observations[-1][0].profile

            def get(config):
                result = fetch(config, lab.url, ca_file=str(lab.ca))
                if result.status != 200 or result.body != DEMO_BODY:
                    raise RuntimeError("incorrect destination response")

            def denied(config):
                try:
                    get(config)
                except RouteError:
                    return
                raise RuntimeError("expected filter to deny this connection")

            for label, rule in (
                ("tls_profile", lambda hello: hello.profile == old_profile),
                ("alpn", lambda hello: hello.alpn == ("http/1.1",)),
            ):
                censor.rule = rule
                denied(stock)
                get(client)
                print(f"PASS {label}", flush=True)

            with Session(impersonate=PROFILE, verify=str(lab.ca), trust_env=False) as ordinary:
                if ordinary.get(censor.url, timeout=2).content != SITE_BODY:
                    raise RuntimeError("ordinary site did not work through permitted endpoint")
                censor.rule = lambda hello: True
                denied(client)
                try:
                    ordinary.get(censor.url, timeout=2)
                except RequestException:
                    pass
                else:
                    raise RuntimeError("endpoint rule unexpectedly allowed ordinary site")
            print("PASS endpoint_block", flush=True)
            censor.rule = lambda hello: False
            censor.client_byte_limit = 1024
            with Session(impersonate=PROFILE, verify=str(lab.ca), trust_env=False) as ordinary:
                if ordinary.get(censor.url, timeout=2).content != SITE_BODY:
                    raise RuntimeError("small ordinary fixture failed byte-budget control")
            get(client)
            print("PASS byte_limit", flush=True)


if __name__ == "__main__":
    run()
