import pytest

from experiments.discovery_enumeration import (GroupAssignments, IdentityAssignments,
                                              RandomAssignments, availability, collect,
                                              crawl_public_neighbors, measure_availability)


class TestDiscoveryModel:
    def test_fresh_sampling_allows_one_identity_to_crawl(self):
        policy = RandomAssignments(1000)
        learned = collect(policy, queries=10000, identities=1, groups=1)
        assert len(learned) == 1000

    def test_identity_stickiness_does_not_stop_new_identity_attack(self):
        policy = IdentityAssignments(1000)
        repeated = collect(policy, queries=10000, identities=1, groups=1)
        sybils = collect(policy, queries=10000, identities=10000, groups=1)
        assert len(repeated) == 3
        assert len(sybils) > 950

    def test_source_budget_covers_fresh_identities_and_false_failures(self):
        policy = GroupAssignments(1000, budget=6)
        learned = collect(policy, queries=10000, identities=10000, groups=1, request_replacements=True)
        assert len(learned) == 6

    def test_bound_scales_with_real_source_groups(self):
        policy = GroupAssignments(10000, budget=6)
        learned = collect(policy, queries=10000, identities=10000, groups=100, request_replacements=True)
        assert len(learned) <= 600
        assert len(learned) > 6

    def test_shared_nat_user_can_be_completely_excluded(self):
        policy = GroupAssignments(1000, budget=6)
        blocked = collect(policy, queries=10000, identities=10000, groups=1, request_replacements=True)
        honest = policy.request("honest-new-identity", "attacker-group-0")
        assert not any((relay not in blocked for relay in honest))
        assert honest == ()

    def test_blocked_contacts_have_bounded_recovery(self):
        policy = GroupAssignments(1000, budget=6)
        first = policy.request("honest", "group")
        second = policy.request("honest", "group", first)
        assert len(second) == 3
        assert not set(first) & set(second)
        assert policy.request('honest', 'group', second) == ()

    def test_other_source_groups_can_remain_usable(self):
        policy = GroupAssignments(10000)
        blocked = collect(policy, queries=10000, identities=10000, groups=10, request_replacements=True)
        assert availability(policy, blocked) > 0.99

    def test_no_global_directory_does_not_prevent_neighbor_crawling(self):
        assert crawl_public_neighbors(1000) == 1000

    def test_recovery_measurement_uses_the_same_initial_attempt(self):
        class RecordingPolicy:
            def __init__(self):
                self.calls = []

            def request(self, identity, group, failed=()):
                self.calls.append((identity, group, failed))
                return (1,) if not failed else (2,)

        policy = RecordingPolicy()
        initial, recovered = measure_availability(policy, {1}, clients=1, recover=True)
        assert (initial, recovered) == (0, 1)
        assert len(policy.calls) == 2
        assert policy.calls[1][2] == (1,)
