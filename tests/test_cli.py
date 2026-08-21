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
        self.assertEqual(result.stdout, "mcprift 0.3.0\n")
        self.assertEqual(result.stderr, "")

    def test_help(self) -> None:
        result = self.run_cli("help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: mcprift", result.stdout)
        self.assertIn("connect", result.stdout)
        self.assertIn("inspect", result.stdout)
        self.assertIn("compare", result.stdout)
        self.assertIn("session-test", result.stdout)
        self.assertIn("oauth-test", result.stdout)

    def test_compare_requires_tokens_via_environment(self) -> None:
        result = self.run_cli(
            "compare",
            "http://127.0.0.1:8080/mcp",
            "--safe-tool",
            "safe_echo",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("environment variable", result.stderr)

    def test_connect_error_hides_credential_bearing_url(self) -> None:
        result = self.run_cli("connect", "http://user:secret@127.0.0.1:8080/mcp")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("secret", result.stderr)
