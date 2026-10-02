import importlib.util
import pytest

from experiments.entry_resilience import Censor, HOSTS, experiment, summarize, verdict
from experiments.wire_filter import Hello


@pytest.fixture(scope="module")
def entry_report():
    return experiment(trials=1)


class TestCensorPolicy:
    def test_probing_learns_only_advertised_entries_and_blocks_by_ip(self):
        censor = Censor()
        censor.learn({"entries": ["https://127.0.0.11:1000", "https://127.0.0.11:2000"],
                      "non_relays": ["https://127.0.1.21:1000"], "errors": []})
        assert censor.blocked_ips == {'127.0.0.11'}
        assert censor.blocks('127.0.0.11', Hello(True))
        assert censor.blocks('127.0.0.11', Hello(False))
        assert not censor.blocks('127.0.1.21', Hello(True))

    def test_prefix_and_tls_rules_use_only_observable_information(self):
        prefix = Censor(prefix="127.0.0.0/24")
        assert prefix.blocks('127.0.0.199', Hello(True))
        assert not prefix.blocks('127.0.1.21', Hello(True))
        tls = Censor(all_tls=True)
        assert tls.blocks('127.0.1.21', Hello(True))
        assert not tls.blocks('127.0.1.21', Hello(False))

    def test_failed_downloads_do_not_contribute_completed_body_goodput(self):
        result = summarize([{"completed": True, "elapsed_seconds": 1, "completed_body_bytes": 100},
                            {"completed": False, "elapsed_seconds": 9, "completed_body_bytes": 0}])
        assert result['completed'] == 1
        assert result['attempts'] == 2
        assert result['completed_body_bytes_per_second'] == 10

    def test_missing_counterexample_is_inconclusive(self):
        result = verdict([
            {"name": "replacement_before_rescan", "alternet": {"completed": 1}},
            {"name": "replacement_after_rescan", "alternet": {"completed": 1},
             "ordinary": {"independent": {"attempts": 6, "completed": 6}},
             "wire": {"rejected_connections": 0}},
        ])
        assert result['hypothesis'] == 'inconclusive'
        assert result['witness'] is None

    @pytest.mark.parametrize("trials", [0, -1, 6, True, 1.5])
    def test_run_size_is_bounded(self, trials):
        with pytest.raises(ValueError):
            experiment(trials=trials)


@pytest.mark.skipif(not (importlib.util.find_spec('curl_cffi')), reason='requires optional curl transport')
class TestEntryReplacementExperiment:
    @pytest.fixture(autouse=True)
    def measurements(self, entry_report, trace):
        self.report = entry_report
        self.rows = {row["name"]: row for row in self.report["rows"]}
        for row in self.rows.values():
            trace(f"{row['name']}: Alternet {row['alternet']['completed']}/{row['alternet']['attempts']}, "
                  f"independent sites {row['ordinary']['independent']['completed']}/"
                  f"{row['ordinary']['independent']['attempts']}")

    @pytest.mark.parametrize("name", ["baseline", "restored"])
    def test_verified_baseline_and_restoration(self, name):
        row = self.rows[name]
        assert row['alternet']['completed'] == 1
        assert row['alternet']['completed_body_bytes'] == self.report['download_bytes']
        for group in row["ordinary"].values():
            assert group['completed'] == group['attempts']

    def test_fixed_finite_ip_population_and_equal_size_controls(self):
        endpoints = self.report["endpoints"]
        assert [endpoint['ip'] for endpoint in endpoints] == list(HOSTS)
        assert len({endpoint['ip'] for endpoint in endpoints}) == 6
        baseline = self.rows["baseline"]
        for sample in baseline["ordinary_samples"]:
            if sample["kind"] == "download":
                assert sample['completed_body_bytes'] == self.report['download_bytes']

    def test_frozen_blocklist_stops_old_entries_but_new_participant_restores_access(self):
        blocked = self.rows["known_entries_blocked"]
        assert blocked['alternet']['completed'] == 0
        assert blocked['wire']['rejected_connections'] > 0
        replacement = self.rows["replacement_before_rescan"]
        assert replacement['policy']['blocked_ips'] == blocked['policy']['blocked_ips']
        assert replacement['alternet']['completed'] == 1
        assert replacement['recovery_seconds_from_activation'] is not None

    def test_rescan_identifies_new_entry_over_actual_https(self):
        row = self.rows["replacement_after_rescan"]
        new_url = self.report["endpoints"][2]["url"]
        assert new_url in row['attacker_probe']['entries']
        assert row['attacker_probe']['attempts'] == 6
        assert HOSTS[2] in row['policy']['blocked_ips']
        assert row['alternet']['completed'] == 0
        assert not row['policy']['block_all_tls']
        assert row['policy']['blocked_prefix'] is None

    def test_independent_web_survives_complete_learned_entry_cut(self):
        row = self.rows["replacement_after_rescan"]
        assert row['ordinary']['independent']['completed'] == 6
        assert row['ordinary']['peer_sites']['completed'] == 0
        assert self.report['uncensored_diagnostic']['completed']
        assert self.report['result']['hypothesis'] == 'rejected_in_this_experiment'

    def test_broad_filter_control_has_measured_ordinary_impact(self):
        prefix = self.rows["peer_prefix_blocked"]
        assert prefix['alternet']['completed'] == 0
        assert prefix['ordinary']['independent']['completed'] == 6
        all_tls = self.rows["all_tls_blocked"]
        assert all_tls['alternet']['completed'] == 0
        assert all((group['completed'] == 0 for group in all_tls['ordinary'].values()))

    def test_degradation_experiments_record_outcomes_without_assuming_resistance(self):
        rate = self.rows["aggregate_rate_64_KiB_s"]
        assert rate['policy']['aggregate_bytes_per_second_per_endpoint'] == 65536
        assert rate['ordinary_by_size']['download']['elapsed_seconds'] > 0
        timed = self.rows["connections_cut_at_200_ms"]
        assert timed['wire']['timed_disconnects'] > 0
        for row in (rate, timed):
            assert row['ordinary_by_size']['page']['attempts'] == 6
            assert row['ordinary_by_size']['download']['attempts'] == 6
