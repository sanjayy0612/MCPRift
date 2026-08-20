from __future__ import annotations

import unittest

from mcprift.actors import Actor, ActorKind
from mcprift.operations import (
    Action,
    ActionKind,
    Observation,
    Outcome,
    SessionPolicy,
)
from mcprift.security import (
    SESSION_CASE_ID,
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

        self.assertEqual(len(cases), 9)
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
                SESSION_CASE_ID,
            },
        )

    def test_session_case_declares_a_sanitized_reused_actor_transition(self) -> None:
        case = built_in_cases(
            alice_token="secret-alice",
            bob_token="secret-bob",
            invalid_token="secret-invalid",
            expired_token="secret-expired",
        )[-1]

        serialized = str(case.to_dict())
        self.assertEqual(case.session_policy, SessionPolicy.REUSED)
        self.assertEqual(case.establishing_actor.name, "alice")
        self.assertEqual(case.actor.name, "bob")
        self.assertNotIn("secret-alice", serialized)
        self.assertNotIn("secret-bob", serialized)

    def test_reused_policy_requires_an_establishing_actor(self) -> None:
        with self.assertRaises(ValueError):
            SecurityCase(
                "TEST-SESSION",
                "invalid session case",
                Actor("bob", ActorKind.AUTHENTICATED, "bob"),
                Action(ActionKind.RESOURCE_READ, "lab://users/alice"),
                ExpectedProperty.DENIED,
                SessionPolicy.REUSED,
            )

    def test_security_case_serialization_excludes_actor_token(self) -> None:
        case = built_in_cases(
            alice_token="secret-alice",
            bob_token="secret-bob",
            invalid_token="secret-invalid",
            expired_token="secret-expired",
        )[1]

        self.assertNotIn("secret-alice", str(case.to_dict()))
