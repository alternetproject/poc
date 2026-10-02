from contextlib import ExitStack
import logging

import pytest

from alternet.lab import Lab


class AlternetTrace:
    def __init__(self, config: pytest.Config, nodeid: str):
        self.enabled = bool(config.getoption("--alternet-trace"))
        self.nodeid = nodeid
        self._terminal = config.pluginmanager.get_plugin("terminalreporter")
        self._opened = False

    def __call__(self, message: str) -> None:
        if not self.enabled:
            return
        if not self._opened:
            self._write("")
            self._write(f"TRACE {self.nodeid}")
            self._opened = True
        for line in message.splitlines():
            self._write(f"  {line}")

    def _write(self, message: str) -> None:
        if self._terminal is not None:
            self._terminal.write_line(message)
        else:
            print(message)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--alternet-trace",
        action="store_true",
        default=False,
        help="Print a transcript of Alternet routing and discovery steps.",
    )


@pytest.fixture
def trace(request: pytest.FixtureRequest) -> AlternetTrace:
    return AlternetTrace(request.config, request.node.nodeid)


@pytest.fixture(autouse=True)
def protocol_trace(trace):
    if not trace.enabled:
        yield
        return
    messages = []

    class TraceHandler(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    logger = logging.getLogger("alternet")
    previous_level = logger.level
    handler = TraceHandler(logging.INFO)
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        for message in messages:
            trace(message)


@pytest.fixture
def resources():
    with ExitStack() as stack:
        yield stack


@pytest.fixture
def lab():
    with Lab() as instance:
        yield instance
