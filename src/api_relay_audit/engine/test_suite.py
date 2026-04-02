"""Test suite management and execution."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Iterator

from api_relay_audit.engine.result import TestCase

logger = logging.getLogger(__name__)


@dataclass
class TestSuite:
    """A collection of related test cases."""

    name: str
    description: str
    tests: list[TestCase] = field(default_factory=list)
    enabled: bool = True

    def add(self, test: TestCase) -> None:
        """Add a test case to the suite."""
        self.tests.append(test)

    def passed_count(self) -> int:
        return sum(1 for t in self.tests if t.passed)

    def failed_count(self) -> int:
        return sum(1 for t in self.tests if not t.passed)

    def __iter__(self) -> Iterator[TestCase]:
        return iter(self.tests)


class TestRunner:
    """Executes test suites with filtering and skip support."""

    def __init__(self):
        self._suites: list[TestSuite] = []
        self._skip_patterns: set[str] = set()

    def register(self, suite: TestSuite) -> None:
        """Register a test suite."""
        self._suites.append(suite)

    def skip(self, detector_id: str) -> None:
        """Skip a detector by ID."""
        self._skip_patterns.add(detector_id)

    def should_skip(self, detector_id: str) -> bool:
        return detector_id in self._skip_patterns

    def run(
        self,
        filter_detectors: list[str] | None = None,
        skip_detectors: list[str] | None = None,
    ) -> dict[str, TestSuite]:
        """Run all registered suites, optionally filtered.

        Returns:
            Dict of detector_id -> TestSuite results.
        """
        if skip_detectors:
            for d in skip_detectors:
                self.skip(d)

        results: dict[str, TestSuite] = {}
        for suite in self._suites:
            if filter_detectors and suite.name not in filter_detectors:
                continue
            if self.should_skip(suite.name):
                logger.info(f"Skipping suite: {suite.name}")
                continue
            results[suite.name] = suite

        return results

    def all_tests(self) -> Iterator[tuple[str, TestCase]]:
        """Iterate over all tests in all registered suites."""
        for suite in self._suites:
            for test in suite:
                yield suite.name, test
