"""Shared test configuration.

`filterwarnings = error` (pyproject.toml) turns ResourceWarning and "coroutine was never
awaited" into failures. Both are only raised when the leaked object is garbage collected,
so a test module that opens sockets, event loops or tasks is marked `leakcheck` and gets a
garbage collection after each test: a leak is then reported against the test that caused
it instead of a later one. A full collection after every test of the whole suite costs more
than the rest of the suite together, so it is opt-in. tests/test_leak_detection.py proves
that the combination fails on leaks.
"""

from __future__ import annotations

import gc
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _collect_garbage_after_leakcheck_tests(request: pytest.FixtureRequest) -> Iterator[None]:
    yield
    if request.node.get_closest_marker("leakcheck") is not None:
        gc.collect()
