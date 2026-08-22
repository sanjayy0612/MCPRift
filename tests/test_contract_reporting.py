from __future__ import annotations

import json
import unittest

from mcprift.cli import _contract_exit_code
from mcprift.reporting import sarif_report, terminal_report


class ContractReportingTests(unittest.TestCase):
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
                }
            ],
        }

        sarif = json.loads(sarif_report(evidence))
        finding = sarif["runs"][0]["results"][0]

        self.assertEqual(finding["ruleId"], "MCPRIFT-BOUNDARY-002")
        self.assertEqual(finding["level"], "error")
        self.assertIn("expected denied, observed allowed", finding["message"]["text"])
        self.assertEqual(_contract_exit_code(tuple(evidence["contract_results"])), 1)

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
