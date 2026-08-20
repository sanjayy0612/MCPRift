from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
import unittest

from mcprift.capabilities import inspect_capabilities
from mcprift.lab import ALICE_TOKEN, BOB_TOKEN, EXPIRED_TOKEN
from mcprift.mutation import MutationKind, run_mutation
from mcprift.security import ResultStatus, built_in_cases, run_cases


class LabIntegrationTests(unittest.TestCase):
    def test_secure_lab_passes_authorization_suite(self) -> None:
        fixture, url = self._start_lab()
        try:
            results = asyncio.run(run_cases(url, self._cases()))
            inventory = asyncio.run(inspect_capabilities(url))
            mutation = asyncio.run(run_mutation(url, MutationKind.UNKNOWN_METHOD))
        finally:
            fixture.terminate()
            fixture.wait(timeout=5)

        self.assertTrue(all(result.status is ResultStatus.PASS for result in results))
        self.assertEqual(len(inventory.capabilities), 4)
        # JSON-RPC errors may correctly use HTTP 200; the protocol verdict is in
        # the body, which MCPRift records only as size and digest.
        self.assertEqual(mutation.http_status, 200)
        self.assertGreater(mutation.response_bytes, 0)

    def test_vulnerability_toggles_create_reproducible_failures(self) -> None:
        selected = (
            ("anonymous-tool", 0),
            ("expired-credential", 3),
            ("cross-user-resource", 5),
        )
        for vulnerability, case_index in selected:
            with self.subTest(vulnerability=vulnerability):
                fixture, url = self._start_lab(vulnerability)
                try:
                    result = asyncio.run(run_cases(url, (self._cases()[case_index],)))[
                        0
                    ]
                finally:
                    fixture.terminate()
                    fixture.wait(timeout=5)
                self.assertEqual(result.status, ResultStatus.FAIL)

    def _cases(self) -> tuple:
        return built_in_cases(
            alice_token=ALICE_TOKEN,
            bob_token=BOB_TOKEN,
            invalid_token="mcprift-lab-invalid",
            expired_token=EXPIRED_TOKEN,
        )

    def _start_lab(
        self, vulnerability: str | None = None
    ) -> tuple[subprocess.Popen[bytes], str]:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        command = [
            sys.executable,
            "-m",
            "mcprift.lab",
            "--port",
            str(port),
        ]
        if vulnerability:
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
                self.fail("lab exited before accepting connections")
            with socket.socket() as client:
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    return
            time.sleep(0.05)
        fixture.terminate()
        fixture.wait(timeout=5)
        self.fail("lab did not start within 10 seconds")
