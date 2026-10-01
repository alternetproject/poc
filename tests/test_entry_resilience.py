import importlib.util
import unittest

from experiments.entry_resilience import Censor, HOSTS, experiment, summarize, verdict
from experiments.wire_filter import Hello


class CensorPolicyTests(unittest.TestCase):
    def test_probing_learns_only_advertised_entries_and_blocks_by_ip(self):
        censor = Censor()
        censor.learn({"entries": ["https://127.0.0.11:1000", "https://127.0.0.11:2000"],
                      "non_relays": ["https://127.0.1.21:1000"], "errors": []})
        self.assertEqual(censor.blocked_ips, {"127.0.0.11"})
        self.assertTrue(censor.blocks("127.0.0.11", Hello(True)))
        self.assertTrue(censor.blocks("127.0.0.11", Hello(False)))
        self.assertFalse(censor.blocks("127.0.1.21", Hello(True)))

    def test_prefix_and_tls_rules_use_only_observable_information(self):
        prefix = Censor(prefix="127.0.0.0/24")
        self.assertTrue(prefix.blocks("127.0.0.199", Hello(True)))
        self.assertFalse(prefix.blocks("127.0.1.21", Hello(True)))
        tls = Censor(all_tls=True)
        self.assertTrue(tls.blocks("127.0.1.21", Hello(True)))
        self.assertFalse(tls.blocks("127.0.1.21", Hello(False)))

    def test_failed_downloads_do_not_contribute_completed_body_goodput(self):
        result = summarize([{"completed": True, "elapsed_seconds": 1, "completed_body_bytes": 100},
                            {"completed": False, "elapsed_seconds": 9, "completed_body_bytes": 0}])
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(result["completed_body_bytes_per_second"], 10)

    def test_missing_counterexample_is_inconclusive(self):
        result = verdict([
            {"name": "replacement_before_rescan", "alternet": {"completed": 1}},
            {"name": "replacement_after_rescan", "alternet": {"completed": 1},
             "ordinary": {"independent": {"attempts": 6, "completed": 6}},
             "wire": {"rejected_connections": 0}},
        ])
        self.assertEqual(result["hypothesis"], "inconclusive")
        self.assertIsNone(result["witness"])

    def test_run_size_is_bounded(self):
        for trials in (0, -1, 6, True, 1.5):
            with self.subTest(trials=trials), self.assertRaises(ValueError):
                experiment(trials=trials)


@unittest.skipUnless(importlib.util.find_spec("curl_cffi"), "requires optional curl transport")
class EntryReplacementExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = experiment(trials=1)
        cls.rows = {row["name"]: row for row in cls.report["rows"]}

    def test_verified_baseline_and_restoration(self):
        for name in ("baseline", "restored"):
            with self.subTest(name=name):
                row = self.rows[name]
                self.assertEqual(row["alternet"]["completed"], 1)
                self.assertEqual(row["alternet"]["completed_body_bytes"], self.report["download_bytes"])
                for group in row["ordinary"].values():
                    self.assertEqual(group["completed"], group["attempts"])

    def test_fixed_finite_ip_population_and_equal_size_controls(self):
        endpoints = self.report["endpoints"]
        self.assertEqual([endpoint["ip"] for endpoint in endpoints], list(HOSTS))
        self.assertEqual(len({endpoint["ip"] for endpoint in endpoints}), 6)
        baseline = self.rows["baseline"]
        for sample in baseline["ordinary_samples"]:
            if sample["kind"] == "download":
                self.assertEqual(sample["completed_body_bytes"], self.report["download_bytes"])

    def test_frozen_blocklist_stops_old_entries_but_new_participant_restores_access(self):
        blocked = self.rows["known_entries_blocked"]
        self.assertEqual(blocked["alternet"]["completed"], 0)
        self.assertGreater(blocked["wire"]["rejected_connections"], 0)
        replacement = self.rows["replacement_before_rescan"]
        self.assertEqual(replacement["policy"]["blocked_ips"], blocked["policy"]["blocked_ips"])
        self.assertEqual(replacement["alternet"]["completed"], 1)
        self.assertIsNotNone(replacement["recovery_seconds_from_activation"])

    def test_rescan_identifies_new_entry_over_actual_https(self):
        row = self.rows["replacement_after_rescan"]
        new_url = self.report["endpoints"][2]["url"]
        self.assertIn(new_url, row["attacker_probe"]["entries"])
        self.assertEqual(row["attacker_probe"]["attempts"], 6)
        self.assertIn(HOSTS[2], row["policy"]["blocked_ips"])
        self.assertEqual(row["alternet"]["completed"], 0)
        self.assertFalse(row["policy"]["block_all_tls"])
        self.assertIsNone(row["policy"]["blocked_prefix"])

    def test_independent_web_survives_complete_learned_entry_cut(self):
        row = self.rows["replacement_after_rescan"]
        self.assertEqual(row["ordinary"]["independent"]["completed"], 6)
        self.assertEqual(row["ordinary"]["peer_sites"]["completed"], 0)
        self.assertTrue(self.report["uncensored_diagnostic"]["completed"])
        self.assertEqual(self.report["result"]["hypothesis"], "rejected_in_this_experiment")

    def test_broad_filter_control_has_measured_ordinary_impact(self):
        prefix = self.rows["peer_prefix_blocked"]
        self.assertEqual(prefix["alternet"]["completed"], 0)
        self.assertEqual(prefix["ordinary"]["independent"]["completed"], 6)
        all_tls = self.rows["all_tls_blocked"]
        self.assertEqual(all_tls["alternet"]["completed"], 0)
        self.assertTrue(all(group["completed"] == 0 for group in all_tls["ordinary"].values()))

    def test_degradation_experiments_record_outcomes_without_assuming_resistance(self):
        rate = self.rows["aggregate_rate_64_KiB_s"]
        self.assertEqual(rate["policy"]["aggregate_bytes_per_second_per_endpoint"], 65536)
        self.assertGreater(rate["ordinary_by_size"]["download"]["elapsed_seconds"], 0)
        timed = self.rows["connections_cut_at_200_ms"]
        self.assertGreater(timed["wire"]["timed_disconnects"], 0)
        for row in (rate, timed):
            self.assertEqual(row["ordinary_by_size"]["page"]["attempts"], 6)
            self.assertEqual(row["ordinary_by_size"]["download"]["attempts"], 6)


if __name__ == "__main__":
    unittest.main()
