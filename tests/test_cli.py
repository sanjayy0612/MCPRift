from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from mcprift.assessment import load_assessment
from mcprift.capabilities import CapabilityInventory
from mcprift.cli import _demo_assessment, main
from mcprift.client import ConnectionResult


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
        self.assertEqual(result.stdout, "mcprift 0.4.0\n")
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

    def test_demo_command_dispatches_without_requiring_arguments(self) -> None:
        with patch("mcprift.cli._run_demo", return_value=0) as demo:
            exit_code = main(["demo"])

        self.assertEqual(exit_code, 0)
        demo.assert_called_once_with(None)

    def test_demo_assessment_uses_the_temporary_lab_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = _demo_assessment(
                Path(directory), "http://127.0.0.1:48123/mcp"
            )
            value = json.loads(path.read_text())
            plan = load_assessment(path)

        self.assertEqual(value["target"], "http://127.0.0.1:48123/mcp")
        self.assertEqual(plan.target, "http://127.0.0.1:48123/mcp")
        self.assertNotIn("mcprift-lab-alice", json.dumps(value))

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

    def test_authenticated_inspect_requires_an_environment_token(self) -> None:
        result = self.run_cli(
            "inspect",
            "http://127.0.0.1:8080/mcp",
            "--actor",
            "alice",
            "--token-env",
            "MCPRIFT_MISSING_TEST_TOKEN",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("environment variable", result.stderr)

    def test_inspect_rejects_a_token_variable_without_an_actor(self) -> None:
        result = self.run_cli(
            "inspect",
            "http://127.0.0.1:8080/mcp",
            "--token-env",
            "MCPRIFT_MISSING_TEST_TOKEN",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires --actor", result.stderr)

    def test_authenticated_inspect_uses_the_named_environment_actor(self) -> None:
        observed = []

        async def inspect(url: str, actor: object) -> CapabilityInventory:
            observed.append((url, actor))
            return CapabilityInventory(
                ConnectionResult("2026-06-18", "test-server", "1.0"), ()
            )

        output = io.StringIO()
        with (
            patch.dict(os.environ, {"MCPRIFT_INSPECT_TEST_TOKEN": "secret-token"}),
            patch("mcprift.cli.inspect_capabilities", new=inspect),
            redirect_stdout(output),
        ):
            exit_code = main(
                [
                    "inspect",
                    "http://127.0.0.1:8080/mcp",
                    "--actor",
                    "alice",
                    "--token-env",
                    "MCPRIFT_INSPECT_TEST_TOKEN",
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(observed[0][0], "http://127.0.0.1:8080/mcp")
        actor = observed[0][1]
        self.assertEqual(actor.to_dict(), {"name": "alice", "kind": "authenticated"})
        self.assertEqual(actor.headers, {"Authorization": "Bearer secret-token"})
        self.assertNotIn("secret-token", output.getvalue())

    def test_init_and_validate_do_not_need_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "assessment.json")
            initialized = self.run_cli("init", path, "--lab")
            validated = self.run_cli("validate", path)

        self.assertEqual(initialized.returncode, 0)
        self.assertEqual(validated.returncode, 0)
        self.assertIn("valid assessment", validated.stdout)

    def test_run_requires_safe_action_acknowledgment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "assessment.json")
            self.assertEqual(self.run_cli("init", path, "--lab").returncode, 0)
            result = self.run_cli("run", path)

        self.assertEqual(result.returncode, 2)
        self.assertIn("acknowledge-safe-actions", result.stderr)
