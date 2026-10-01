from dataclasses import replace
import shutil
import ssl
import subprocess
import sys
import unittest
from unittest.mock import patch

from alternet.client import fetch
from alternet.config import Config
from alternet.discovery import ServiceConfig, cached_contacts, save_contacts
from alternet.lab import DEMO_BODY, Lab
from alternet.routing import RouteError
from experiments.shared_endpoint import SITE_BODY, ordinary_get
from experiments.wire_filter import WireFilter, parse_hello


class SharedEndpointTests(unittest.TestCase):
    def setUp(self):
        self.lab = self.enterContext(Lab())
        self.site = self.lab.directory / "site"
        self.site.mkdir()
        (self.site / "index.html").write_bytes(SITE_BODY)
        child, _ = self.lab.start_discovery("shared", (), site_root=str(self.site))
        self.middlebox = self.enterContext(WireFilter(child.address))
        self.client = replace(self.lab.discovery_client((self.middlebox.url,)), gateway_only=True)

    def routed(self):
        return fetch(self.client, self.lab.url, ca_file=str(self.lab.ca))

    def ordinary(self, **kwargs):
        return ordinary_get(self.middlebox.url, self.lab.ca, **kwargs)

    def test_same_listener_certificate_sni_and_client_profile(self):
        self.assertEqual(self.ordinary(), (200, SITE_BODY))
        first, _ = self.middlebox.observations[-1]
        result = self.routed()
        second, _ = self.middlebox.observations[-1]
        self.assertEqual(result.body, DEMO_BODY)
        self.assertEqual(result.route, ("A", "shared"))
        self.assertEqual(first.server_name, "localhost")
        self.assertEqual(first, second)
        self.assertTrue(first.tls)

    def test_endpoint_block_interrupts_both_applications(self):
        self.middlebox.rule = lambda hello: True
        with self.assertRaises(OSError):
            self.ordinary()
        with self.assertRaises(RouteError):
            self.routed()
        self.assertTrue(all(blocked for _, blocked in self.middlebox.observations))

    def test_raw_protocol_filter_stops_plain_peer_but_not_shared_endpoint(self):
        relay = self.lab.start_node(self.lab.config("R"))
        raw_filter = self.enterContext(WireFilter(relay.address))
        raw_filter.rule = self.middlebox.rule = lambda hello: not hello.tls
        raw_client = self.lab.config("A", peers=(raw_filter.address,), blocked=True)
        with self.assertRaises(RouteError):
            fetch(raw_client, self.lab.url, ca_file=str(self.lab.ca))
        self.assertEqual(raw_filter.observations[-1][0].tls, False)
        self.assertEqual(self.routed().body, DEMO_BODY)
        self.assertEqual(self.ordinary(), (200, SITE_BODY))

    def test_selective_clienthello_rule_remains_a_counterexample(self):
        self.middlebox.rule = lambda hello: hello.alpn == ("http/1.1",)

        with self.assertRaises(RouteError):
            self.routed()
        self.assertEqual(self.ordinary(alpn=("h2", "http/1.1")), (200, SITE_BODY))
        with self.assertRaises(OSError):
            self.ordinary()

    @unittest.skipUnless(sys.platform == "win32" and shutil.which("curl.exe"),
                         "requires the Windows system curl for an independent TLS implementation")
    def test_python_profile_can_be_blocked_while_system_curl_still_works(self):
        self.assertEqual(self.routed().body, DEMO_BODY)
        profile = self.middlebox.observations[-1][0].profile
        self.middlebox.rule = lambda hello: hello.profile == profile
        with self.assertRaises(RouteError):
            self.routed()

        result = subprocess.run([
            shutil.which("curl.exe"), "-q", "--silent", "--show-error", "--noproxy", "*",
            "--max-time", "4", "--cacert", str(self.lab.ca), "--ssl-revoke-best-effort",
            self.middlebox.url], capture_output=True, timeout=6)
        if b"SEC_E_NO_CREDENTIALS" in result.stderr:
            self.skipTest("sandbox/service token cannot initialize Windows Schannel; run in a normal user shell")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, SITE_BODY)
        observed, blocked = self.middlebox.observations[-1]
        self.assertNotEqual(observed.profile, profile)
        self.assertFalse(blocked)

    def test_gateway_only_never_downgrades_to_manual_or_cached_raw_peers(self):
        relay = self.lab.start_node(self.lab.config("R"))
        self.client = replace(self.client, peers=(relay.address,))
        import time
        save_contacts(self.client, {self.middlebox.url: {
            "expires": time.time() + 60, "peers": [str(relay.address)], "gateway": True}})
        self.assertTrue(cached_contacts(self.client))
        self.middlebox.rule = lambda hello: True
        with patch("alternet.routing.connect_tcp") as dial:
            with self.assertRaises(RouteError):
                self.routed()

        dial.assert_not_called()

    def test_second_shared_endpoint_recovers_from_actual_first_endpoint_block(self):
        child, _ = self.lab.start_discovery("shared-2", (), site_root=str(self.site))
        second = self.enterContext(WireFilter(child.address))
        self.client = replace(self.client, discovery=(self.middlebox.url, second.url))
        self.middlebox.rule = lambda hello: True
        self.assertEqual(self.routed().route, ("A", "shared-2"))

    def test_origin_verification_is_preserved_with_shared_site(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            fetch(self.client, self.lab.url)

    def test_site_head_missing_file_and_path_traversal(self):
        (self.lab.directory / "private.txt").write_text("must not be served", encoding="utf-8")
        self.assertEqual(self.ordinary(method="HEAD"), (200, b""))
        for path in ("/missing", "/../private.txt", "/%2e%2e/private.txt", "/C:/Windows/win.ini",
                     "/..%5cprivate.txt", "/%00", "/%ff"):
            with self.subTest(path=path):
                status, body = self.ordinary(path=path)
                self.assertEqual(status, 404)
                self.assertNotIn(b"must not be served", body)

    def test_participation_is_not_hidden_from_an_active_client(self):
        status, body = self.ordinary(path="/v1/peers")
        self.assertEqual(status, 200)
        self.assertIn(b'"gateway": true', body)

    def test_configuration_requires_bootstrap_for_gateway_only(self):
        with self.assertRaisesRegex(ValueError, "requires discovery"):
            Config.from_dict({"name": "A", "allowed_destinations": [], "gateway_only": True})
        config = ServiceConfig.load(self.lab.directory / "shared-discovery.json")
        self.assertEqual(config.site_root, str(self.site))


class HelloParserTests(unittest.TestCase):
    def test_truncated_clienthello_is_rejected(self):
        for body in (b"", b"\x03\x03", bytes(35), bytes(40)):
            with self.subTest(length=len(body)), self.assertRaises(ValueError):
                parse_hello(body)


if __name__ == "__main__":
    unittest.main()
