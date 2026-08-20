from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
import unittest

from mcprift.actors import Actor, ActorKind
from mcprift.capabilities import inspect_capabilities
from mcprift.client import controlled_session
from mcprift.evidence import create_evidence
from mcprift.lab import ALICE_TOKEN, BOB_TOKEN, EXPIRED_TOKEN
from mcprift.mutation import MutationKind, run_mutation
from mcprift.operations import Action, ActionKind, Outcome, observe_client
from mcprift.registry import default_registry
from mcprift.replay import replay_case
from mcprift.security import ResultStatus, built_in_cases, run_cases


class LabIntegrationTests(unittest.TestCase):
    def test_secure_lab_passes_authorization_suite(self) -> None:
        fixture, url = self._start_lab()
        try:
            results = asyncio.run(run_cases(url, self._cases()))
            inventory = asyncio.run(inspect_capabilities(url))
            mutation = asyncio.run(run_mutation(url, MutationKind.UNKNOWN_METHOD))
            evidence = create_evidence(url, results=(results[-1],)).to_dict()
            replayed = asyncio.run(
                replay_case(
                    url,
                    evidence,
                    results[-1].case.case_id,
                    self._registry(),
                )
            )
        finally:
            fixture.terminate()
            fixture.wait(timeout=5)

        self.assertTrue(all(result.status is ResultStatus.PASS for result in results))
        self.assertEqual(len(inventory.capabilities), 4)
        # The stateful lab rejects a raw request without an established session;
        # MCPRift retains only the status, size, and digest of that response.
        self.assertEqual(mutation.http_status, 400)
        self.assertGreater(mutation.response_bytes, 0)
        self.assertEqual(results[-1].observation.establishing_actor_name, "alice")
        self.assertEqual(results[-1].observation.actor_name, "bob")
        self.assertEqual(replayed.status, ResultStatus.PASS)

    def test_vulnerability_toggles_create_reproducible_failures(self) -> None:
        selected = (
            ("anonymous-tool", 0),
            ("expired-credential", 3),
            ("cross-user-resource", 5),
            ("session-identity-crossover", 8),
        )
        for vulnerability, case_index in selected:
            with self.subTest(vulnerability=vulnerability):
                fixture, url = self._start_lab(vulnerability)
                try:
                    result = asyncio.run(run_cases(url, (self._cases()[case_index],)))[
                        0
                    ]
                    fresh_bob_outcome = (
                        self._fresh_bob_session_outcome(url)
                        if vulnerability == "session-identity-crossover"
                        else None
                    )
                finally:
                    fixture.terminate()
                    fixture.wait(timeout=5)
                self.assertEqual(result.status, ResultStatus.FAIL)
                if vulnerability == "session-identity-crossover":
                    self.assertEqual(fresh_bob_outcome, Outcome.REJECTED)

    def _cases(self) -> tuple:
        return built_in_cases(
            alice_token=ALICE_TOKEN,
            bob_token=BOB_TOKEN,
            invalid_token="mcprift-lab-invalid",
            expired_token=EXPIRED_TOKEN,
        )

    def _registry(self):
        return default_registry(
            alice_token=ALICE_TOKEN,
            bob_token=BOB_TOKEN,
            invalid_token="mcprift-lab-invalid",
            expired_token=EXPIRED_TOKEN,
        )

    def _fresh_bob_session_outcome(self, url: str) -> Outcome:
        async def observe() -> Outcome:
            bob = Actor("bob", ActorKind.AUTHENTICATED, BOB_TOKEN)
            action = Action(ActionKind.RESOURCE_READ, "lab://users/alice")
            async with controlled_session(url, bob, legacy_protocol=True) as session:
                observation = await observe_client(session.client, bob, action)
            return observation.outcome

        return asyncio.run(observe())

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
