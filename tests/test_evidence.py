from __future__ import annotations

import json
import tempfile
import unittest

from mcprift.actors import Actor, ActorKind
from mcprift.evidence import create_evidence, read_evidence, write_evidence
from mcprift.operations import (
    Action,
    ActionKind,
    Observation,
    Outcome,
    SessionPolicy,
)
from mcprift.reporting import json_report, sarif_report, terminal_report
from mcprift.security import (
    ExpectedProperty,
    ResultStatus,
    SecurityCase,
    SecurityResult,
    built_in_cases,
)


class EvidenceTests(unittest.TestCase):
    def make_result(self, status: ResultStatus) -> SecurityResult:
        actor = Actor("alice", ActorKind.AUTHENTICATED, "secret-token")
        case = SecurityCase(
            "TEST-001",
            "controlled test",
            actor,
            Action(
                ActionKind.TOOL_CALL,
                "safe_echo",
                {"message": "secret-payload"},
                known_safe=True,
            ),
            ExpectedProperty.DENIED,
        )
        observation = Observation("alice", "authenticated", Outcome.SUCCEEDED, "test")
        return SecurityResult(case, observation, status)

    def test_evidence_excludes_url_tokens_and_argument_values(self) -> None:
        evidence = create_evidence(
            "http://127.0.0.1:8080/mcp",
            results=(self.make_result(ResultStatus.FAIL),),
        )
        serialized = json.dumps(evidence.to_dict())

        self.assertNotIn("127.0.0.1", serialized)
        self.assertNotIn("secret-token", serialized)
        self.assertNotIn("secret-payload", serialized)
        self.assertIn('"argument_names": ["message"]', serialized)

    def test_writes_reads_and_reports_evidence(self) -> None:
        evidence = create_evidence(
            "http://127.0.0.1:8080/mcp",
            results=(self.make_result(ResultStatus.FAIL),),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = write_evidence(evidence, directory)
            loaded = read_evidence(path)

        self.assertIn("1 failed", terminal_report(loaded))
        self.assertEqual(json.loads(json_report(loaded)), loaded)
        sarif = json.loads(sarif_report(loaded))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "TEST-001")
        self.assertEqual(path.name, f"mcprift-{evidence.run_id}.json")

    def test_session_evidence_records_sequence_without_credentials(self) -> None:
        case = built_in_cases(
            alice_token="session-secret-alice",
            bob_token="session-secret-bob",
            invalid_token="invalid",
            expired_token="expired",
        )[-1]
        observation = Observation(
            "bob",
            "authenticated",
            Outcome.REJECTED,
            "test",
            session_policy=SessionPolicy.REUSED,
            establishing_actor_name="alice",
            establishing_actor_kind="authenticated",
            establishing_outcome=Outcome.SUCCEEDED,
        )
        evidence = create_evidence(
            "http://127.0.0.1:8080/mcp",
            results=(SecurityResult(case, observation, ResultStatus.PASS),),
        )
        serialized = json.dumps(evidence.to_dict())

        self.assertIn('"policy": "reused"', serialized)
        self.assertIn('"establishing_outcome": "succeeded"', serialized)
        self.assertNotIn("session-secret-alice", serialized)
        self.assertNotIn("session-secret-bob", serialized)
        self.assertNotIn("127.0.0.1", serialized)
        self.assertIn("MCPRIFT-SESSION-001: PASS", terminal_report(evidence.to_dict()))
        self.assertEqual(
            json.loads(json_report(evidence.to_dict()))["results"][0]["status"], "pass"
        )
        self.assertEqual(
            json.loads(sarif_report(evidence.to_dict()))["runs"][0]["tool"]["driver"][
                "rules"
            ][0]["id"],
            "MCPRIFT-SESSION-001",
        )
