from __future__ import annotations

import unittest

from mcprift.reporting import terminal_report
from mcprift.terminal import green, verdict, yellow


class TerminalTests(unittest.TestCase):
    def test_styling_can_be_disabled_for_machine_readable_output(self) -> None:
        self.assertEqual(green("pass", enabled=False), "pass")
        self.assertEqual(yellow("warning", enabled=False), "warning")

    def test_styling_uses_green_for_pass_and_yellow_for_attention(self) -> None:
        self.assertIn("\x1b[1;38;5;48mPASS", verdict("PASS", "pass", enabled=True))
        self.assertIn("\x1b[1;38;5;220mFAIL", verdict("FAIL", "fail", enabled=True))

    def test_colored_contract_report_preserves_the_plain_values(self) -> None:
        evidence = {
            "contract_results": [
                {
                    "case_id": "TEST-001",
                    "title": "test case",
                    "family": "access",
                    "identity": {"name": "alice"},
                    "probe": {"kind": "resource-read"},
                    "expected": "denied",
                    "observed": "allowed",
                    "verdict": "fail",
                }
            ]
        }

        report = terminal_report(evidence, color=True)

        self.assertIn("TEST-001", report)
        self.assertIn("FAIL", report)
        self.assertIn("\x1b[1;38;5;48m", report)
        self.assertIn("\x1b[1;38;5;220m", report)
