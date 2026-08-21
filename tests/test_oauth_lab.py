from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from mcprift.cli import main
from mcprift.oauth_checks import run_oauth_checks


class OAuthLabIntegrationTests(unittest.TestCase):
    def test_secure_oauth_lab_passes_all_checks(self) -> None:
        fixture, url = self._start_lab()
        try:
            results = asyncio.run(run_oauth_checks(url))
        finally:
            fixture.terminate()
            fixture.wait(timeout=5)

        self.assertEqual(len(results), 12)
        self.assertTrue(
            all(result.passed for result in results),
            [(result.check_id, result.observed) for result in results],
        )

    def test_oauth_vulnerabilities_are_detected(self) -> None:
        for vulnerability, check_id in (
            ("wrong-audience", "MCPRIFT-OAUTH-005"),
            ("token-passthrough", "MCPRIFT-OAUTH-008"),
        ):
            with self.subTest(vulnerability=vulnerability):
                fixture, url = self._start_lab(vulnerability)
                try:
                    results = asyncio.run(run_oauth_checks(url))
                finally:
                    fixture.terminate()
                    fixture.wait(timeout=5)
                result = next(item for item in results if item.check_id == check_id)
                self.assertFalse(result.passed)

    def test_oauth_cli_writes_sanitized_evidence(self) -> None:
        fixture, url = self._start_lab()
        try:
            with tempfile.TemporaryDirectory() as directory:
                stdout = StringIO()
                stderr = StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = main(["oauth-test", url, "--evidence-dir", directory])
                evidence_paths = list(Path(directory).glob("*.json"))
                evidence_text = evidence_paths[0].read_text()
        finally:
            fixture.terminate()
            fixture.wait(timeout=5)

        self.assertEqual(exit_code, 0)
        self.assertIn("12 passed, 0 failed", stdout.getvalue())
        self.assertEqual(len(evidence_paths), 1)
        self.assertNotIn(url, evidence_text)
        self.assertNotIn("mcprift-oauth-valid", evidence_text)

    def _start_lab(
        self, vulnerability: str | None = None
    ) -> tuple[subprocess.Popen[bytes], str]:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        command = [
            sys.executable,
            "-m",
            "mcprift.oauth_lab",
            "--port",
            str(port),
        ]
        if vulnerability is not None:
            command.extend(("--vulnerable", vulnerability))
        fixture = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait_until_listening(port, fixture)
        return fixture, f"http://127.0.0.1:{port}/mcp"

    def _wait_until_listening(
        self, port: int, fixture: subprocess.Popen[bytes]
    ) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if fixture.poll() is not None:
                self.fail("OAuth lab exited before accepting connections")
            with socket.socket() as client:
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    return
            time.sleep(0.05)
        fixture.terminate()
        fixture.wait(timeout=5)
        self.fail("OAuth lab did not start within 10 seconds")
