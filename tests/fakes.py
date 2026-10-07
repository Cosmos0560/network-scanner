"""Test doubles for the injected interfaces. Nothing here touches the network or real DNS."""

from __future__ import annotations

from collections.abc import Mapping

from network_scanner.core.errors import ResolutionError


class FakeResolver:
    """A `Resolver` that answers from a dict and records every call.

    A value that is an exception instance (or class) is raised instead of returned;
    a name that is not in the dict raises `ResolutionError`, like an NXDOMAIN.
    """

    def __init__(
        self, answers: Mapping[str, tuple[str, ...] | BaseException] | None = None
    ) -> None:
        self.answers = dict(answers or {})
        self.calls: list[tuple[str, float]] = []

    async def resolve(self, name: str, *, timeout: float) -> tuple[str, ...]:
        self.calls.append((name, timeout))
        result = self.answers.get(name, ResolutionError(name))
        if isinstance(result, BaseException):
            raise result
        return result
