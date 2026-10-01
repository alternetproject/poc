from contextlib import ExitStack
from dataclasses import replace
import http.client
import json
import ssl
from urllib.parse import urlsplit

from alternet.client import fetch
from alternet.lab import DEMO_BODY, Lab
from .wire_filter import WireFilter

SITE_BODY = b"<!doctype html><title>Fixture site</title><p>Ordinary site content.</p>\n"


def ordinary_get(url, ca, *, alpn=("http/1.1",), path="/", method="GET"):
    parsed = urlsplit(url)
    context = ssl.create_default_context(cafile=str(ca))
    context.set_alpn_protocols(list(alpn))
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=3)
    try:
        connection.request(method, path, headers={"Connection": "close"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def successful(operation):
    try:
        return bool(operation())
    except (OSError, ValueError, http.client.HTTPException):
        return False


def run(*, as_json=False):
    report = {"ordinary_population": 3, "rows": []}
    with ExitStack() as stack:
        lab = stack.enter_context(Lab())
        site = lab.directory / "site"
        site.mkdir()
        (site / "index.html").write_bytes(SITE_BODY)
        filters = []
        for index in range(3):
            child, _ = lab.start_discovery(f"shared-{index}", (), site_root=str(site))
            filters.append(stack.enter_context(WireFilter(child.address)))
        client = replace(lab.discovery_client(tuple(proxy.url for proxy in filters)), gateway_only=True)

        def routed():
            result = fetch(client, lab.url, ca_file=str(lab.ca))
            return result.status == 200 and result.body == DEMO_BODY

        def ordinary(proxy, alpn=("http/1.1",)):
            return ordinary_get(proxy.url, lab.ca, alpn=alpn) == (200, SITE_BODY)

        for count in range(4):
            for index, proxy in enumerate(filters):
                proxy.rule = (lambda hello: True) if index < count else (lambda hello: False)
            web_ok = sum(successful(lambda proxy=proxy: ordinary(proxy)) for proxy in filters)
            route_ok = sum(successful(routed) for _ in range(3))
            if web_ok != 3 - count or route_ok != (0 if count == 3 else 3):
                raise RuntimeError("endpoint-blocking experiment returned an unexpected result")
            report["rows"].append({"blocked_shared_endpoints": count, "ordinary_successes": web_ok,
                                   "ordinary_attempts": 3, "alternet_successes": route_ok,
                                   "alternet_attempts": 3})

        for proxy in filters:
            proxy.rule = lambda hello: hello.alpn == ("http/1.1",)
        alternate_ok = sum(successful(lambda proxy=proxy: ordinary(proxy, ("h2", "http/1.1")))
                           for proxy in filters)
        same_ok = sum(successful(lambda proxy=proxy: ordinary(proxy)) for proxy in filters)
        route_ok = sum(successful(routed) for _ in range(3))
        if (alternate_ok, same_ok, route_ok) != (3, 0, 0):
            raise RuntimeError("selective ClientHello blocking control did not reproduce")
        report["selective_counterexample"] = {
            "rule": "drop ClientHello with ALPN exactly ['http/1.1']",
            "ordinary_different_profile_successes": alternate_ok,
            "ordinary_matching_profile_successes": same_ok,
            "alternet_successes": route_ok, "attempts_per_class": 3}

    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("Blocked endpoints | Ordinary site successes | Alternet successes")
        for row in report["rows"]:
            print(f"{row['blocked_shared_endpoints']:17} | {row['ordinary_successes']:21}/3 | "
                  f"{row['alternet_successes']:16}/3")
        result = report["selective_counterexample"]
        print(f"clienthello_filter: alternet={result['alternet_successes']}/3 "
              f"different_profile={result['ordinary_different_profile_successes']}/3 "
              f"matching_profile={result['ordinary_matching_profile_successes']}/3")

    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Measure shared-endpoint and TLS-profile filtering.')
    parser.add_argument("--json", action="store_true")
    run(as_json=parser.parse_args().json)
