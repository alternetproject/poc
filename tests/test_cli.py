import importlib
import logging
import subprocess
import sys

import pytest

from alternet.cli import main


@pytest.fixture(autouse=True)
def restore_logging():
    logger = logging.getLogger("alternet")
    level = logger.level
    yield
    logger.setLevel(level)


def test_module_help_lists_existing_commands():
    result = subprocess.run([sys.executable, "-m", "alternet", "--help"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    for command in ("node", "fetch", "discover", "discovery", "demo", "demo-discovery",
                    "demo-peers", "demo-carrier", "demo-shared", "demo-resilience", "demo-recovery"):
        assert command in result.stdout


@pytest.mark.parametrize("arguments,module,expected", [
    (["demo"], "alternet.demo", {}),
    (["demo-discovery"], "alternet.discovery_demo", {}),
    (["demo-peers"], "alternet.peer_demo", {}),
    (["demo-carrier"], "experiments.transport_carrier", {}),
    (["demo-shared", "--json"], "experiments.shared_endpoint", {"as_json": True}),
    (["demo-resilience", "--json", "--trials", "1", "--output", "report.json"],
     "experiments.entry_resilience", {"as_json": True, "trials": 1, "output": "report.json"}),
    (["demo-recovery", "--json", "--output", "report.json", "--modes", "frozen", "continuous_fast",
      "--step-seconds", "0.8", "--rounds", "5", "--tail-seconds", "3", "--peer-count", "6",
      "--client-policy", "advertised"], "experiments.recovery_race",
     {"as_json": True, "output": "report.json", "modes": ["frozen", "continuous_fast"],
      "step_seconds": 0.8, "rounds": 5, "tail_seconds": 3.0, "peer_count": 6,
      "client_policy": "advertised"}),
], ids=["routing", "discovery", "peers", "carrier", "shared", "resilience", "recovery"])
def test_demo_commands_preserve_options(arguments, module, expected, monkeypatch, trace):
    calls = []
    monkeypatch.setattr(importlib.import_module(module), "run", lambda **kwargs: calls.append(kwargs))
    trace("alternet " + " ".join(arguments))
    assert main(arguments) == 0
    assert calls == [expected]


def test_demo_failure_returns_nonzero(monkeypatch, caplog):
    def fail():
        raise RuntimeError("origin unavailable")

    monkeypatch.setattr(importlib.import_module("alternet.demo"), "run", fail)
    assert main(["demo"]) == 1
    assert "origin unavailable" in caplog.text


def test_demo_interrupt_returns_130(monkeypatch):
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(importlib.import_module("alternet.demo"), "run", interrupt)
    assert main(["demo"]) == 130
