import argparse
from dataclasses import dataclass
from fractions import Fraction
import json
from pathlib import Path
from urllib.parse import urlsplit

from alternet.config import Config

KINDS = ("fresh", "returning", "ordinary")
LIMIT = 16


@dataclass(frozen=True)
class Workload:
    name: str
    kind: str
    weight: int
    paths: tuple[frozenset[str], ...]


@dataclass(frozen=True)
class Rule:
    name: str
    blocks: frozenset[str]


@dataclass(frozen=True)
class Model:
    name: str
    rules: tuple[Rule, ...]
    workloads: tuple[Workload, ...]

    @classmethod
    def from_dict(cls, data):
        def label(value):
            if not isinstance(value, str) or not value.strip():
                raise ValueError("names and dependencies must be nonempty strings")
            return value

        def labels(values):
            if not isinstance(values, list):
                raise ValueError("dependencies must be arrays")
            return frozenset(label(value) for value in values)

        if not isinstance(data, dict) or set(data) != {"name", "rules", "workloads"}:
            raise ValueError("model requires exactly name, rules, and workloads")
        name = label(data["name"])
        if not isinstance(data["rules"], list) or len(data["rules"]) > LIMIT:
            raise ValueError(f"exact search supports at most {LIMIT} rules")
        rules = []
        for rule in data["rules"]:
            if not isinstance(rule, dict) or set(rule) != {"name", "blocks"}:
                raise ValueError("rule requires exactly name and blocks")
            rules.append(Rule(label(rule["name"]), labels(rule["blocks"])))
        if not isinstance(data["workloads"], list) or not 1 <= len(data["workloads"]) <= 256:
            raise ValueError("supply 1-256 workloads")
        workloads = []
        for item in data["workloads"]:
            if not isinstance(item, dict) or set(item) != {"name", "kind", "weight", "paths"}:
                raise ValueError("workload requires exactly name, kind, weight, and paths")
            if item["kind"] not in KINDS:
                raise ValueError("kind must be fresh, returning, or ordinary")
            if type(item["weight"]) is not int or item["weight"] <= 0:
                raise ValueError("weights must be positive integers")
            if not isinstance(item["paths"], list) or not 1 <= len(item["paths"]) <= 256:
                raise ValueError("supply 1-256 paths per workload; baseline must be reachable")
            workloads.append(Workload(label(item["name"]), item["kind"], item["weight"],
                                      tuple(labels(path) for path in item["paths"])))
        for collection in (rules, workloads):
            if len({item.name for item in collection}) != len(collection):
                raise ValueError("duplicate rule or workload name")
        if not any(item.kind == "ordinary" for item in workloads):
            raise ValueError("an ordinary-workload denominator is required")
        if not any(item.kind != "ordinary" for item in workloads):
            raise ValueError("at least one Alternet workload is required")
        return cls(name, tuple(rules), tuple(workloads))


def analyze(model: Model, targets=(Fraction(1, 2), Fraction(9, 10), Fraction(1))):
    if len(model.rules) > LIMIT:
        raise ValueError(f"exact search supports at most {LIMIT} rules")
    if any(not 0 < target <= 1 for target in targets):
        raise ValueError("targets must be greater than zero and at most one")
    totals = {kind: sum(w.weight for w in model.workloads if w.kind == kind) for kind in KINDS}

    masks = [tuple(sum(1 << i for i, rule in enumerate(model.rules) if rule.blocks & path)
                   for path in workload.paths) for workload in model.workloads]
    best = {(kind, target): None for kind in KINDS[:-1] if totals[kind] for target in targets}
    for attack in range(1 << len(model.rules)):
        lost = {kind: 0 for kind in KINDS}
        for workload, paths in zip(model.workloads, masks):
            if all(attack & path for path in paths):
                lost[workload.kind] += workload.weight
        score = (lost["ordinary"], attack.bit_count(), attack)
        for (kind, target), previous in best.items():
            if lost[kind] * target.denominator < totals[kind] * target.numerator:
                continue
            if previous is None or score < previous[0]:
                best[kind, target] = (score, dict(lost))
    results = []
    for (kind, target), found in best.items():
        result = {"population": kind, "target_loss_fraction": str(target), "witness": None}
        if found is not None:
            score, lost = found
            attack = score[2]
            result["witness"] = {
                "rules": [r.name for i, r in enumerate(model.rules) if attack & (1 << i)],
                "lost_weight": lost,
                "ordinary_loss_fraction": str(Fraction(lost["ordinary"], totals["ordinary"])),
                "failed_workloads": [w.name for w, paths in zip(model.workloads, masks)
                                     if all(attack & path for path in paths)],
            }
        results.append(result)
    return {"name": model.name, "model_only": True, "total_weight": totals,
            "rule_subsets_checked": 1 << len(model.rules), "results": results}


def bootstrap_cut(config: Config):
    if not config.gateway_only:
        raise ValueError("static config audit currently supports gateway_only configurations only")
    hosts = sorted({urlsplit(url).hostname for url in config.discovery})
    return {
        "name": config.name,
        "requires_blocked_origin": True,
        "configured_gateway_urls": list(config.discovery),
        "sufficient_cut": {"block_all_gateway_hostnames": hosts, "rule_count": len(hosts)},
        "affected": ["fresh", "returning"],
        "collateral": None,
    }


def main():
    parser = argparse.ArgumentParser(description='Analyze blocking rules and path dependencies.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--model", type=Path)
    source.add_argument("--config", type=Path)
    args = parser.parse_args()
    try:
        if args.config:
            result = bootstrap_cut(Config.load(args.config))
        else:
            result = analyze(Model.from_dict(json.loads(args.model.read_text(encoding="utf-8"))))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"ERROR: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
