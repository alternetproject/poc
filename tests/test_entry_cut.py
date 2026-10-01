from dataclasses import replace
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import unittest

from alternet.client import fetch
from alternet.config import Config
from alternet.lab import DEMO_BODY, Lab
from alternet.routing import RouteError
from experiments.entry_cut import Model, analyze, bootstrap_cut
from experiments.wire_filter import WireFilter


def workload(name, kind, paths, weight=1):
    return dict(name=name, kind=kind, paths=paths, weight=weight)


def model(rules, workloads):
    return Model.from_dict(dict(name="test",
                               rules=[dict(name=name, blocks=blocks) for name, blocks in rules],
                               workloads=workloads))


def witness(data, kind="fresh"):
    return next(r["witness"] for r in analyze(data, (Fraction(1),))["results"]
                if r["population"] == kind)


class EntryCutTests(unittest.TestCase):
    def test_cohosting_does_not_imply_large_collateral(self):
        path = Path(__file__).resolve().parents[1] / "examples" / "entry-cut-model.json"
        result = witness(Model.from_dict(json.loads(path.read_text(encoding="utf-8"))))
        self.assertEqual(result["ordinary_loss_fraction"], "1/50")
        self.assertEqual(result["lost_weight"], dict(fresh=100, returning=100, ordinary=2))
        self.assertEqual(len(result["rules"]), 2)

    def test_bootstrap_cut_can_exclude_only_new_clients(self):
        data = model([("bootstrap", ["directory"])], [
            workload("cold", "fresh", [["directory", "relay-a"], ["directory", "relay-b"]]),
            workload("warm", "returning", [["relay-a"], ["relay-b"]]),
            workload("web", "ordinary", [["web"]]),
        ])
        self.assertEqual(witness(data)["ordinary_loss_fraction"], "0")
        self.assertIsNone(witness(data, "returning"))

    def test_search_prefers_selective_classifier_over_endpoint_cut(self):
        data = model([("endpoint", ["shared"]), ("classifier", ["distinguishable"])], [
            workload("client", "fresh", [["shared", "distinguishable"]]),
            workload("web", "ordinary", [["shared"]]),
        ])
        self.assertEqual(witness(data)["rules"], ["classifier"])
        self.assertEqual(witness(data)["ordinary_loss_fraction"], "0")

    def test_shared_provider_is_a_common_dependency_of_many_entries(self):
        data = model([("provider", ["provider"])], [
            workload("client", "fresh", [["provider", f"entry-{n}"] for n in range(100)]),
            workload("web", "ordinary", [["other-provider"]]),
        ])
        self.assertEqual(witness(data)["rules"], ["provider"])

    def test_rules_can_combine_to_break_alternative_paths(self):
        data = model([("a", ["a"]), ("b", ["b"])], [
            workload("client", "fresh", [["a"], ["b"]]),
            workload("same-web-workload", "ordinary", [["a"], ["b"]], weight=7),
        ])
        result = witness(data)
        self.assertEqual(result["rules"], ["a", "b"])
        self.assertEqual(result["lost_weight"]["ordinary"], 7)

    def test_loss_thresholds_use_weights_not_workload_counts(self):
        data = model([("a", ["a"]), ("b", ["b"])], [
            workload("large", "fresh", [["a"]], weight=9),
            workload("small", "fresh", [["b"]]),
            workload("web", "ordinary", [["b"]]),
        ])
        result = analyze(data, (Fraction(9, 10),))["results"][0]["witness"]
        self.assertEqual(result["rules"], ["a"])
        self.assertEqual(result["lost_weight"]["fresh"], 9)

    def test_path_without_modeled_dependencies_survives_all_rules(self):
        data = model([("everything-known", ["a", "b"])], [
            workload("client", "fresh", [[]]),
            workload("web", "ordinary", [["a"]]),
        ])
        self.assertIsNone(witness(data))
        self.assertTrue(analyze(data)["model_only"])

    def test_input_rejects_missing_denominator_invalid_weights_and_excessive_search(self):
        for workloads in ([workload("client", "fresh", [["a"]])],
                          [workload("client", "fresh", []), workload("web", "ordinary", [["a"]])],
                          [workload("client", "fresh", [["a"]]),
                           workload("web", "ordinary", [["a"]], weight=True)]):
            with self.assertRaises(ValueError):
                model([], workloads)
        with self.assertRaises(ValueError):
            model([(str(i), [str(i)]) for i in range(17)], [
                workload("client", "fresh", [["a"]]), workload("web", "ordinary", [["a"]])])

    def test_config_cut_groups_urls_by_hostname_and_does_not_invent_collateral(self):
        config = Config.from_dict(dict(name="client", allowed_destinations=["example.com:443"],
                                       discovery=["https://entry.example:443", "https://entry.example:9443"],
                                       gateway_only=True, gateway_transport="curl"))
        result = bootstrap_cut(config)
        self.assertEqual(result["sufficient_cut"]["rule_count"], 1)
        self.assertIsNone(result["collateral"])
        with self.assertRaises(ValueError):
            bootstrap_cut(replace(config, gateway_only=False, gateway_transport="stdlib"))


@unittest.skipUnless(importlib.util.find_spec("curl_cffi"), "requires optional curl transport")
class EntryCutSocketTests(unittest.TestCase):
    def test_all_gateways_cut_off_client_while_hidden_relays_remain_healthy(self):
        with Lab() as lab:
            relay = lab.start_node(lab.config("hidden-relay"))
            entry1, _ = lab.start_discovery("entry-one", (relay.address,), blocked=True)
            entry2, _ = lab.start_discovery("entry-two", (relay.address,), blocked=True)
            with WireFilter(entry1.address) as first, WireFilter(entry2.address) as second:
                client = replace(lab.discovery_client((first.url, second.url)),
                                 gateway_only=True, gateway_transport="curl")
                self.assertEqual(fetch(client, lab.url, ca_file=str(lab.ca)).body, DEMO_BODY)
                first.rule = lambda hello: True

                result = fetch(client, lab.url, ca_file=str(lab.ca))
                self.assertEqual(result.route, ("A", "entry-two", "hidden-relay"))
                second.rule = lambda hello: True

                for name in ("A", "fresh-client"):
                    with self.subTest(name=name), self.assertRaises(RouteError):
                        fetch(replace(client, name=name), lab.url, ca_file=str(lab.ca))

                diagnostic = lab.config("diagnostic", peers=(relay.address,), blocked=True)
                self.assertEqual(fetch(diagnostic, lab.url, ca_file=str(lab.ca)).body, DEMO_BODY)
                self.assertTrue(any(blocked for _, blocked in first.observations))
                self.assertTrue(any(blocked for _, blocked in second.observations))


if __name__ == "__main__":
    unittest.main()
