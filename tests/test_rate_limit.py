"""Tests for rate-limit (429) detection across operations, security, and reporting."""

from __future__ import annotations

import asyncio
import unittest
from collections import Counter

from mcprift.actors import Actor, ActorKind
from mcprift.client import HTTPStatusRecorder
from mcprift.operations import (
    Action,
    ActionKind,
    Observation,
    Outcome,
    _exception_outcome,
    observe_client,
)
from mcprift.reporting import _summary, sarif_report, terminal_report
from mcprift.security import (
    ExpectedProperty,
    ResultStatus,
    SecurityCase,
    evaluate,
)

# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# operations._exception_outcome
# ---------------------------------------------------------------------------


class RateLimitOutcomeTests(unittest.TestCase):
    """HTTP 429 must map to RATE_LIMITED, not TRANSPORT_ERROR."""

    def test_http_429_maps_to_rate_limited(self) -> None:
        outcome = _exception_outcome(RuntimeError("server busy"), http_status=429)
        self.assertEqual(outcome, Outcome.RATE_LIMITED)

    def test_http_401_still_maps_to_authentication_denied(self) -> None:
        outcome = _exception_outcome(RuntimeError("no auth"), http_status=401)
        self.assertEqual(outcome, Outcome.AUTHENTICATION_DENIED)

    def test_http_403_still_maps_to_authorization_denied(self) -> None:
        outcome = _exception_outcome(RuntimeError("forbidden"), http_status=403)
        self.assertEqual(outcome, Outcome.AUTHORIZATION_DENIED)

    def test_no_status_falls_back_to_transport_error(self) -> None:
        outcome = _exception_outcome(RuntimeError("unknown"), http_status=None)
        self.assertEqual(outcome, Outcome.TRANSPORT_ERROR)

    def test_observe_client_records_rate_limited_via_recorder(self) -> None:
        """observe_client must produce RATE_LIMITED when the recorder sees 429."""
        actor = Actor("anonymous", ActorKind.ANONYMOUS)
        action = Action(ActionKind.RESOURCE_READ, "lab://test")

        class RateLimitingClient:
            protocol_version = "2025-06-18"

            def __init__(self, recorder: HTTPStatusRecorder) -> None:
                self._recorder = recorder

            async def read_resource(self, target: str) -> object:
                self._recorder.status = 429
                raise RuntimeError("too many requests")

        async def observe() -> Observation:
            recorder = HTTPStatusRecorder()
            return await observe_client(
                RateLimitingClient(recorder),
                actor,
                action,
                recorder,  # type: ignore[arg-type]
            )

        observation = asyncio.run(observe())
        self.assertEqual(observation.outcome, Outcome.RATE_LIMITED)
        self.assertNotIn("too many requests", repr(observation))


# ---------------------------------------------------------------------------
# security.evaluate
# ---------------------------------------------------------------------------


class RateLimitEvaluationTests(unittest.TestCase):
    """RATE_LIMITED must always resolve to ERROR, never PASS or FAIL."""

    def _make_case(self, expected: ExpectedProperty) -> SecurityCase:
        actor = Actor("alice", ActorKind.AUTHENTICATED, "tok")
        action = Action(
            ActionKind.TOOL_CALL,
            "safe_echo",
            {"message": "probe"},
            known_safe=True,
        )
        return SecurityCase("TEST-001", "rate limit test", actor, action, expected)

    def _make_observation(self) -> Observation:
        return Observation(
            actor_name="alice",
            actor_kind="authenticated",
            outcome=Outcome.RATE_LIMITED,
            protocol_version="2025-06-18",
        )

    def test_rate_limited_with_expected_allowed_is_error(self) -> None:
        case = self._make_case(ExpectedProperty.ALLOWED)
        result = evaluate(case, self._make_observation())
        self.assertEqual(result.status, ResultStatus.ERROR)

    def test_rate_limited_with_expected_denied_is_error(self) -> None:
        case = self._make_case(ExpectedProperty.DENIED)
        result = evaluate(case, self._make_observation())
        self.assertEqual(result.status, ResultStatus.ERROR)


# ---------------------------------------------------------------------------
# reporting._summary
# ---------------------------------------------------------------------------


class RateLimitSummaryTests(unittest.TestCase):
    """_summary must include a rate-limited count in the output line."""

    def test_summary_includes_rate_limited_when_nonzero(self) -> None:
        counts: Counter[str] = Counter(
            {"pass": 5, "fail": 1, "error": 0, "rate-limited": 2}
        )
        result = _summary(counts, color=False)
        self.assertIn("2 rate-limited", result)
        self.assertIn("5 passed", result)
        self.assertIn("1 failed", result)

    def test_summary_shows_zero_rate_limited_when_none(self) -> None:
        counts: Counter[str] = Counter({"pass": 22, "fail": 0, "error": 0})
        result = _summary(counts, color=False)
        self.assertIn("0 rate-limited", result)

    def test_summary_without_color_contains_no_ansi(self) -> None:
        counts: Counter[str] = Counter({"pass": 1, "rate-limited": 1})
        result = _summary(counts, color=False)
        self.assertNotIn("\x1b[", result)


# ---------------------------------------------------------------------------
# reporting.sarif_report - rate-limited maps to warning
# ---------------------------------------------------------------------------


class RateLimitSarifTests(unittest.TestCase):
    """rate-limited items must appear as SARIF warning, not error."""

    def _make_evidence(self, status: str, outcome: str) -> dict:
        return {
            "tool": {"version": "0.5.0"},
            "results": [
                {
                    "case": {
                        "id": "MCPRIFT-AUTH-002",
                        "title": "Alice can invoke the safe tool",
                        "actor": {"name": "alice", "kind": "authenticated"},
                        "action": {
                            "kind": "tool-call",
                            "target": "safe_echo",
                            "argument_names": [],
                            "known_safe": True,
                        },
                        "expected": "allowed",
                        "session": {"policy": "isolated"},
                    },
                    "observation": {
                        "actor": {"name": "alice", "kind": "authenticated"},
                        "outcome": outcome,
                        "protocol_version": "2025-06-18",
                        "item_count": None,
                        "session": {"policy": "isolated"},
                    },
                    "status": status,
                }
            ],
            "contract_results": [],
            "oauth_checks": [],
        }

    def test_rate_limited_status_renders_as_sarif_warning(self) -> None:
        import json

        evidence = self._make_evidence("error", "rate-limited")
        doc = json.loads(sarif_report(evidence))
        findings = doc["runs"][0]["results"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "warning")

    def test_fail_status_renders_as_sarif_error(self) -> None:
        import json

        evidence = self._make_evidence("fail", "allowed")
        doc = json.loads(sarif_report(evidence))
        findings = doc["runs"][0]["results"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "error")


# ---------------------------------------------------------------------------
# terminal_report - rate-limited verdict surfaced correctly
# ---------------------------------------------------------------------------


class RateLimitTerminalReportTests(unittest.TestCase):
    """terminal_report must display ERROR status for 429 cases."""

    def _make_simple_evidence(self, status: str, outcome: str) -> dict:
        return {
            "results": [
                {
                    "case": {
                        "id": "MCPRIFT-AUTH-002",
                        "title": "Alice can invoke the safe tool",
                        "actor": {"name": "alice", "kind": "authenticated"},
                        "action": {
                            "kind": "tool-call",
                            "target": "safe_echo",
                            "argument_names": [],
                            "known_safe": True,
                        },
                        "expected": "allowed",
                        "session": {"policy": "isolated"},
                    },
                    "observation": {
                        "actor": {"name": "alice", "kind": "authenticated"},
                        "outcome": outcome,
                        "protocol_version": "2025-06-18",
                        "item_count": None,
                        "session": {"policy": "isolated"},
                    },
                    "status": status,
                }
            ],
            "oauth_checks": [],
        }

    def test_rate_limited_status_appears_in_terminal_output(self) -> None:
        evidence = self._make_simple_evidence("error", "rate-limited")
        report = terminal_report(evidence, color=False)
        self.assertIn("ERROR", report)

    def test_summary_line_shows_rate_limited_count(self) -> None:
        evidence = self._make_simple_evidence("error", "rate-limited")
        report = terminal_report(evidence, color=False)
        self.assertIn("rate-limited", report)


if __name__ == "__main__":
    unittest.main()
