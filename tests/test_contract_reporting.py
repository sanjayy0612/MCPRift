from __future__ import annotations

import json
import unittest

from mcprift.actors import Actor, ActorKind
from mcprift.cli import _contract_exit_code
from mcprift.contract_runner import _access_result
from mcprift.operations import Action, ActionKind, Observation, Outcome
from mcprift.reporting import sarif_report, terminal_report
from mcprift.security import (
    ExpectedProperty,
    ResultStatus,
    SecurityCase,
    SecurityResult,
)


class ContractReportingTests(unittest.TestCase):
    def test_expected_denial_remains_a_passing_contract_verdict(self) -> None:
        actor = Actor("alice", ActorKind.AUTHENTICATED, "test-token")
        case = SecurityCase(
            "MCPRIFT-BOUNDARY-002",
            "Alice cannot read Bob's resource",
            actor,
            Action(ActionKind.RESOURCE_READ, "lab://users/bob"),
            ExpectedProperty.DENIED,
        )
        result = SecurityResult(
            case,
            Observation("alice", "authenticated", Outcome.AUTHORIZATION_DENIED, "test"),
            ResultStatus.PASS,
        )

        rendered = _access_result(result, {})

        self.assertEqual(rendered["observed"], "denied")
        self.assertEqual(rendered["verdict"], "pass")

    def test_contract_failure_becomes_a_sarif_error(self) -> None:
        evidence = {
            "tool": {"version": "0.4.0"},
            "results": [],
            "contract_results": [
                {
                    "case_id": "MCPRIFT-BOUNDARY-002",
                    "title": "Alice cannot read Bob's resource",
                    "family": "access",
                    "identity": {"name": "alice", "kind": "authenticated"},
                    "probe": {"kind": "resource-read"},
                    "expected": "denied",
                    "observed": "allowed",
                    "verdict": "fail",
                    "source": {
                        "uri": "testdata/lab-assessment.json",
                        "line": 42,
                    },
                }
            ],
        }

        sarif = json.loads(sarif_report(evidence))
        finding = sarif["runs"][0]["results"][0]

        self.assertEqual(finding["ruleId"], "MCPRIFT-BOUNDARY-002")
        self.assertEqual(finding["level"], "error")
        self.assertIn("expected denied, observed allowed", finding["message"]["text"])
        location = finding["locations"][0]["physicalLocation"]
        self.assertEqual(
            location["artifactLocation"]["uri"], "testdata/lab-assessment.json"
        )
        self.assertEqual(location["region"]["startLine"], 42)
        self.assertEqual(_contract_exit_code(tuple(evidence["contract_results"])), 1)

    def test_sarif_omits_unsafe_source_location(self) -> None:
        result = {
            "case_id": "MCPRIFT-BOUNDARY-002",
            "title": "Alice cannot read Bob's resource",
            "family": "access",
            "identity": {"name": "alice", "kind": "authenticated"},
            "probe": {"kind": "resource-read"},
            "expected": "denied",
            "observed": "allowed",
            "verdict": "fail",
            "source": {"uri": "/Users/operator/assessment.json", "line": 42},
        }

        sarif = json.loads(
            sarif_report(
                {
                    "tool": {"version": "0.5.0"},
                    "results": [],
                    "contract_results": [result],
                }
            )
        )

        self.assertNotIn("locations", sarif["runs"][0]["results"][0])

    def test_contract_error_has_non_success_exit_code_and_safe_terminal_output(
        self,
    ) -> None:
        result = {
            "case_id": "MCPRIFT-PROTOCOL-001",
            "title": "bad\x1b[31m title",
            "family": "protocol",
            "identity": None,
            "probe": {"kind": "protocol-mutation"},
            "expected": "rejected",
            "observed": "error",
            "verdict": "error",
        }

        report = terminal_report({"contract_results": [result]})

        self.assertNotIn("\x1b", report)
        self.assertIn("1 errors", report)
        self.assertEqual(_contract_exit_code((result,)), 2)

    def test_oauth_http_429_is_marked_rate_limited_in_sarif(self) -> None:
        sarif = json.loads(
            sarif_report(
                {
                    "tool": {"version": "0.5.0"},
                    "results": [],
                    "oauth_checks": [
                        {
                            "check_id": "MCPRIFT-OAUTH-010",
                            "title": "authorization rejects a resource indicator",
                            "passed": False,
                            "observed": "authorize HTTP 429",
                            "expected": "redirect with invalid_target",
                        }
                    ],
                }
            )
        )
        finding = sarif["runs"][0]["results"][0]

        self.assertEqual(finding["level"], "warning")
        self.assertTrue(finding["properties"]["rate_limited"])
