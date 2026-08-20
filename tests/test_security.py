from __future__ import annotations

import unittest

from mcprift.actors import Actor, ActorKind
from mcprift.operations import Action, ActionKind, Observation, Outcome
from mcprift.security import (
    ExpectedProperty,
    ResultStatus,
    SecurityCase,
    built_in_cases,
    evaluate,
)


class SecurityTests(unittest.TestCase):
    def test_evaluates_allowed_denied_and_transport_error(self) -> None:
        actor = Actor("anonymous", ActorKind.ANONYMOUS)
        case = SecurityCase(
            "TEST-001",
            "anonymous denied",
            actor,
            Action(ActionKind.TOOL_CALL, "safe_echo", {}, known_safe=True),
            ExpectedProperty.DENIED,
        )

        denied = Observation("anonymous", "anonymous", Outcome.REJECTED, "test")
        allowed = Observation("anonymous", "anonymous", Outcome.SUCCEEDED, "test")
        unavailable = Observation(
            "anonymous", "anonymous", Outcome.UNAVAILABLE, "unknown"
        )

        self.assertEqual(evaluate(case, denied).status, ResultStatus.PASS)
        self.assertEqual(evaluate(case, allowed).status, ResultStatus.FAIL)
        self.assertEqual(evaluate(case, unavailable).status, ResultStatus.ERROR)

    def test_built_in_suite_covers_identity_and_user_boundaries(self) -> None:
        cases = built_in_cases(
            alice_token="alice",
            bob_token="bob",
            invalid_token="invalid",
            expired_token="expired",
        )

        self.assertEqual(len(cases), 8)
        self.assertEqual(
            {case.case_id for case in cases},
            {
                "MCPRIFT-AUTH-001",
                "MCPRIFT-AUTH-002",
                "MCPRIFT-AUTH-003",
                "MCPRIFT-AUTH-004",
                "MCPRIFT-BOUNDARY-001",
                "MCPRIFT-BOUNDARY-002",
                "MCPRIFT-BOUNDARY-003",
                "MCPRIFT-BOUNDARY-004",
            },
        )

    def test_security_case_serialization_excludes_actor_token(self) -> None:
        case = built_in_cases(
            alice_token="secret-alice",
            bob_token="secret-bob",
            invalid_token="secret-invalid",
            expired_token="secret-expired",
        )[1]

        self.assertNotIn("secret-alice", str(case.to_dict()))
