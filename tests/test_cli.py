from __future__ import annotations

import subprocess
import sys
import unittest


class CliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "mcprift.cli", *arguments],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_version(self) -> None:
        result = self.run_cli("version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "mcprift 0.1.0\n")
        self.assertEqual(result.stderr, "")

    def test_help(self) -> None:
        result = self.run_cli("help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: mcprift", result.stdout)
        self.assertIn("connect", result.stdout)

    def test_connect_error_hides_credential_bearing_url(self) -> None:
        result = self.run_cli("connect", "http://user:secret@127.0.0.1:8080/mcp")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("secret", result.stderr)
