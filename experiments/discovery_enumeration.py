import argparse
from dataclasses import dataclass, field
import hashlib
import json
import random


def random_for(seed: int, label: str) -> random.Random:
    digest = hashlib.sha256(f"{seed}:{label}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


class RandomAssignments:
    def __init__(self, pool_size: int, *, seed: int = 1, bundle: int = 3):
        self.pool_size = pool_size
        self.bundle = min(bundle, pool_size)
        self.random = random_for(seed, "fresh")

    def request(self, identity: str, group: str, failed: tuple[int, ...] = ()) -> tuple[int, ...]:
        return tuple(self.random.sample(range(self.pool_size), self.bundle))


class IdentityAssignments:
    def __init__(self, pool_size: int, *, seed: int = 1, bundle: int = 3):
        self.pool_size = pool_size
        self.bundle = min(bundle, pool_size)
        self.seed = seed

    def request(self, identity: str, group: str, failed: tuple[int, ...] = ()) -> tuple[int, ...]:
        return tuple(random_for(self.seed, identity).sample(range(self.pool_size), self.bundle))


@dataclass
class GroupState:
    random: random.Random
    disclosed: set[int] = field(default_factory=set)
    active: list[int] = field(default_factory=list)


class GroupAssignments:
    def __init__(self, pool_size: int, *, seed: int = 1, bundle: int = 3, budget: int = 6):
        if pool_size < 1 or bundle < 1 or budget < bundle:
            raise ValueError("require a positive pool and budget >= bundle >= 1")
        self.pool_size = pool_size
        self.bundle = min(bundle, pool_size)
        self.budget = min(budget, pool_size)
        self.seed = seed
        self.groups: dict[str, GroupState] = {}

    def request(self, identity: str, group: str, failed: tuple[int, ...] = ()) -> tuple[int, ...]:
        if group not in self.groups:
            self.groups[group] = GroupState(random_for(self.seed, group))
        state = self.groups[group]

        failed_set = set(failed)
        state.active = [relay for relay in state.active if relay not in failed_set]
        while len(state.active) < self.bundle and len(state.disclosed) < self.budget:
            candidate = state.random.randrange(self.pool_size)
            if candidate not in state.disclosed:
                state.disclosed.add(candidate)
                state.active.append(candidate)
        return tuple(state.active)


def collect(policy, *, queries: int, identities: int, groups: int,
            request_replacements: bool = False) -> set[int]:
    learned: set[int] = set()
    last: dict[str, tuple[int, ...]] = {}
    for query in range(queries):
        identity = f"attacker-id-{query % identities}"
        group = f"attacker-group-{query % groups}"
        result = policy.request(identity, group, last.get(group, ()) if request_replacements else ())
        learned.update(result)
        last[group] = result
    return learned


def measure_availability(policy, blocked: set[int], clients: int = 1000, *,
                         recover: bool = False) -> tuple[float, float]:
    connected = recovered = 0
    for client in range(clients):
        identity, group = f"honest-{client}", f"honest-group-{client}"
        assigned = policy.request(identity, group)
        reachable = any(relay not in blocked for relay in assigned)
        connected += reachable
        if not reachable and recover:
            assigned = policy.request(identity, group, assigned)
            reachable = any(relay not in blocked for relay in assigned)
        recovered += reachable
    return connected / clients, recovered / clients


def availability(policy, blocked: set[int], clients: int = 1000, *, recover: bool = False) -> float:
    initial, after_retry = measure_availability(policy, blocked, clients, recover=recover)
    return after_retry if recover else initial


def crawl_public_neighbors(pool_size: int) -> int:
    learned, pending = {0}, [0]
    while pending:
        node = pending.pop()
        for neighbor in ((node - 1) % pool_size, (node + 1) % pool_size):
            if neighbor not in learned:
                learned.add(neighbor)
                pending.append(neighbor)
    return len(learned)


def experiment(pool_size: int = 10000, seed: int = 20261001) -> dict:
    rows = []
    scenarios = [
        ("fresh samples, one identity", RandomAssignments, 10000, 1, 1, False),
        ("sticky identity, one identity", IdentityAssignments, 10000, 1, 1, False),
        ("sticky identity, 10000 identities", IdentityAssignments, 10000, 10000, 1, False),
    ]
    for groups in (1, 10, 100, 1000, 5000):
        scenarios.append((f"source-group budget, {groups} groups", GroupAssignments,
                          max(10000, groups * 3), 10000, groups, True))
    for name, factory, queries, identities, groups, replacements in scenarios:
        policy = factory(pool_size, seed=seed)
        blocked = collect(policy, queries=queries, identities=identities, groups=groups,
                          request_replacements=replacements)
        initial, recovered = measure_availability(policy, blocked, recover=True)
        rows.append({"policy": name, "queries": queries, "attacker_identities": identities,
                     "attacker_source_groups": groups, "learned_relay_ips": len(blocked),
                     "enumerated_fraction": len(blocked) / pool_size,
                     "honest_initial_availability": initial,
                     "honest_availability_after_one_retry": recovered})

    policy = GroupAssignments(pool_size, seed=seed)
    blocked = collect(policy, queries=10000, identities=10000, groups=1, request_replacements=True)
    shared_nat_assignment = policy.request("innocent-new-user", "attacker-group-0")
    shared_nat_ok = any(relay not in blocked for relay in shared_nat_assignment)

    all_blocked = set(range(pool_size))
    changed_key_ips = set(range(pool_size))
    fresh_count = max(1, pool_size // 10)
    genuinely_new_ips = set(range(fresh_count, pool_size + fresh_count))
    return {
        "model_only": True, "seed": seed, "relay_pool_size": pool_size,
        "scenarios": rows,
        "counterexamples": {
            "shared_nat_honest_client_can_connect": shared_nat_ok,
            "shared_nat_attacker_learned": len(blocked),
            "ips_learned_by_crawling_public_neighbor_lists_from_one_seed": crawl_public_neighbors(pool_size),
        },
        "analytic_boundaries_not_network_measurements": {
            "unblocked_ips_after_key_or_port_rotation": len(changed_key_ips - all_blocked),
            "unblocked_ips_after_ten_percent_actual_ip_replacement": len(genuinely_new_ips - all_blocked),
            "cold_start_with_every_bootstrap_path_blocked": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Compare discovery assignment policies.')
    parser.add_argument("--seed", type=int, default=20261001)
    parser.add_argument("--relays", type=int, default=10000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.relays < 10:
        parser.error("--relays must be at least 10")
    result = experiment(args.relays, args.seed)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"model=discovery relays={args.relays} clients=1000 seed={args.seed}")

    print(f"{'Policy':45} {'IPs learned':>12} {'Initial access':>15} {'After retry':>13}")
    for row in result["scenarios"]:
        print(f"{row['policy']:45} {row['learned_relay_ips']:12d} "
              f"{row['honest_initial_availability']:14.1%} "
              f"{row['honest_availability_after_one_retry']:12.1%}")
    print("\nCounterexamples:")
    for name, value in result["counterexamples"].items():
        print(f"  {name}: {value}")
    print("\nAnalytic results:")
    for name, value in result["analytic_boundaries_not_network_measurements"].items():
        print(f"  {name}: {value}")


if __name__ == "__main__":
    main()
