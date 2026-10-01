import importlib.util
import socket
import ssl
import time
from types import SimpleNamespace
import unittest

from alternet.config import Address, Config
from alternet.http_carrier import CarrierSession
from alternet.lab import Lab
from experiments.recovery_race import HOSTS, PersistentBlocks, assess, scenario, window_summary
from experiments.wire_filter import WireFilter


class RecoveryMeasurementTests(unittest.TestCase):
    def test_wall_clock_goodput_includes_failures_and_excludes_late_bodies(self):
        samples = [
            {"start": 0, "end": 1, "completed": True, "elapsed_seconds": 1, "completed_body_bytes": 100},
            {"start": 1, "end": 8, "completed": False, "elapsed_seconds": 7, "completed_body_bytes": 0},
            {"start": 8, "end": 12, "completed": True, "elapsed_seconds": 4, "completed_body_bytes": 100},
        ]
        report = window_summary(samples, 0, 10)
        self.assertEqual(report["useful_bytes_per_wall_second"], 10)
        self.assertEqual(report["successful_completions"], 1)
        self.assertEqual(report["failures_completed"], 1)
        self.assertEqual(report["in_flight_at_end"], 1)
        self.assertEqual(report["longest_completion_gap_seconds"], 9)

    def test_empty_window_is_an_entire_observed_gap(self):
        report = window_summary([], 5, 12)
        self.assertEqual(report["longest_completion_gap_seconds"], 7)
        self.assertEqual(report["successful_completions"], 0)

    def test_run_size_validation(self):
        for kwargs in ({"mode": "unknown"}, {"mode": "frozen", "rounds": 3},
                       {"mode": "frozen", "rounds": True}, {"mode": "frozen", "tail_seconds": 0},
                       {"mode": "frozen", "peer_count": 3}, {"mode": "frozen", "peer_count": 17},
                       {"mode": "frozen", "client_policy": "oracle"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                scenario(**kwargs)

    def test_available_but_unused_routes_are_not_misreported_as_total_blocking(self):
        row = {"summaries": {"alternet": {"tail": {"successful_completions": 0}}},
               "uncensored_diagnostic": {"completed": True},
               "final_unblocked_active_ips": [HOSTS[0]]}
        self.assertEqual(assess(row), "unblocked_active_peer_exists_but_no_final_window_completion")
        row["final_unblocked_active_ips"] = []
        self.assertEqual(assess(row), "all_remaining_active_addresses_blocked")

    def test_new_ip_block_terminates_an_already_established_tls_connection(self):
        with Lab(cert_extra_hosts=(HOSTS[0],)) as lab:
            child, _ = lab.start_discovery("peer", ())
            with WireFilter(child.address, listen=Address(HOSTS[0], 0)) as wire:
                policy = PersistentBlocks([wire])
                context = ssl.create_default_context(cafile=lab.ca)
                with socket.create_connection((wire.address.host, wire.address.port), timeout=2) as raw:
                    with context.wrap_socket(raw, server_hostname=wire.address.host) as secured:
                        self.assertEqual(policy.learn([wire.url]), [HOSTS[0]])
                        self.assertGreater(policy.disconnected_sockets, 0)
                        try:
                            secured.sendall(b"GET /v1/peers HTTP/1.1\r\nHost: peer\r\nConnection: close\r\n\r\n")
                            self.assertEqual(secured.recv(100), b"")
                        except (OSError, ssl.SSLError):
                            pass
                self.assertEqual(policy.learn([wire.url]), [])
                self.assertIn(HOSTS[0], policy.hosts)

    def test_incomplete_upload_fragments_do_not_wait_for_an_impossible_reply(self):
        owner = SimpleNamespace(track=lambda sock: None, untrack=lambda sock: None)
        config = Config("fragment-relay", Address("127.0.0.1", 0), (), frozenset())
        carrier = CarrierSession(owner, config)
        try:
            started = time.monotonic()
            self.assertEqual(carrier.exchange(1, 0, b""), (b"", False))
            prefix = b"CONNECT localhost:443 HTTP/1.1\r\nX-Padding: "
            self.assertEqual(carrier.exchange(2, 1, prefix), (b"", False))
            for sequence in range(2, 34):
                self.assertEqual(carrier.exchange(2, sequence, b"x" * 32), (b"", False))
            self.assertLess(time.monotonic() - started, .8)
        finally:
            carrier.close()
            carrier.worker.join(2)
        self.assertFalse(carrier.worker.is_alive())


@unittest.skipUnless(importlib.util.find_spec("curl_cffi"), "requires optional curl transport")
class ContinuousRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frozen = scenario("frozen", step_seconds=.8, rounds=5, tail_seconds=3)
        cls.updated = scenario("continuous_fast", step_seconds=.8, rounds=5, tail_seconds=3)

    def test_frozen_list_allows_actual_recovery_during_participation_changes(self):
        row = self.frozen
        self.assertEqual(len(row["blocked_ips"]), 2)
        self.assertGreater(row["summaries"]["alternet"]["whole"]["successful_completions"], 0)
        for client in row["clients"].values():
            self.assertGreater(client["successful_completions"], 0)
        routes = [s["route"] for s in row["samples"] if s["kind"] == "alternet" and s["completed"]]
        self.assertTrue(any("peer-2" in route or "peer-3" in route for route in routes))

    def test_updated_blocks_persist_when_participant_rejoins_and_stop_tail_workload(self):
        row = self.updated
        self.assertEqual(set(row["blocked_ips"]), set(HOSTS[:4]))
        self.assertEqual(row["summaries"]["alternet"]["tail"]["successful_completions"], 0)
        self.assertGreater(row["wire_rejections"], 0)
        self.assertTrue(any(e["kind"] == "relay_enabled" and e["already_blocked"] for e in row["events"]))
        self.assertTrue(row["uncensored_diagnostic"]["completed"])

    def test_independent_sites_continue_and_no_control_provides_magic_new_contacts(self):
        for row in (self.frozen, self.updated):
            self.assertEqual(len(row["candidate_urls"]), 6)
            self.assertGreater(row["summaries"]["independent_site"]["tail"]["successful_completions"], 0)
            self.assertEqual(row["summaries"]["independent_site"]["whole"]["failures_completed"], 0)
            supplied = set(row["candidate_urls"])
            for event in row["client_discovery"]:
                self.assertLessEqual(set(event["entries"]), supplied)
            for event in row["events"]:
                if event["kind"] == "censor_probe":
                    self.assertLessEqual(set(event["result"]["entries"]), supplied)


if __name__ == "__main__":
    unittest.main()
