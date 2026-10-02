from pathlib import Path

import pytest

pytest_plugins = ["pytester"]


@pytest.mark.parametrize("enabled", [False, True], ids=["quiet", "trace"])
def test_trace_flag_controls_transcript(pytester, enabled):
    pytester.makeconftest(Path(__file__).with_name("conftest.py").read_text(encoding="utf-8"))
    pytester.makepyfile(
        "import logging\n"
        "def test_exchange(trace):\n"
        "    trace('request started')\n"
        "    logging.getLogger('alternet').info('route=A -> C')\n"
    )
    arguments = ["-vv", "--alternet-trace"] if enabled else ["-q"]
    result = pytester.runpytest_subprocess(*arguments, timeout=20)
    result.assert_outcomes(passed=1)
    output = result.stdout.str()
    assert ("TRACE test_trace_flag_controls_transcript.py::test_exchange" in output) == enabled
    assert ("request started" in output) == enabled
    assert ("route=A -> C" in output) == enabled
