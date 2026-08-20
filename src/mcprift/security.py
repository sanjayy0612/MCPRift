"""Reusable security cases and result evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcprift.actors import Actor, ActorKind
from mcprift.operations import (
    Action,
    ActionKind,
    Observation,
    Outcome,
    SessionPolicy,
    compare_identities,
    observe_reused_session,
)

SESSION_CASE_ID = "MCPRIFT-SESSION-001"


class ExpectedProperty(StrEnum):
    ALLOWED = "allowed"
    DENIED = "denied"


class ResultStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


@dataclass(frozen=True)
class SecurityCase:
    """One actor, one safe action, and one expected authorization property."""

    case_id: str
    title: str
    actor: Actor
    action: Action
    expected: ExpectedProperty
    session_policy: SessionPolicy = SessionPolicy.ISOLATED
    establishing_actor: Actor | None = None

    def __post_init__(self) -> None:
        if self.session_policy is SessionPolicy.REUSED:
            if self.establishing_actor is None:
                raise ValueError("reused session case requires an establishing actor")
        elif self.establishing_actor is not None:
            raise ValueError("isolated session case cannot have an establishing actor")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "id": self.case_id,
            "title": self.title,
            "actor": self.actor.to_dict(),
            "action": self.action.to_dict(),
            "expected": self.expected.value,
            "session": {"policy": self.session_policy.value},
        }
        if self.establishing_actor is not None:
            result["session"]["establishing_actor"] = self.establishing_actor.to_dict()
        return result


@dataclass(frozen=True)
class SecurityResult:
    case: SecurityCase
    observation: Observation
    status: ResultStatus

    def to_dict(self) -> dict[str, Any]:
        return {
            "case": self.case.to_dict(),
            "observation": self.observation.to_dict(),
            "status": self.status.value,
        }


def evaluate(case: SecurityCase, observation: Observation) -> SecurityResult:
    """Evaluate only the observable authorization property."""
    if observation.outcome is Outcome.UNAVAILABLE:
        status = ResultStatus.ERROR
    else:
        allowed = observation.outcome is Outcome.SUCCEEDED
        expected_allowed = case.expected is ExpectedProperty.ALLOWED
        status = ResultStatus.PASS if allowed == expected_allowed else ResultStatus.FAIL
    return SecurityResult(case, observation, status)


async def run_cases(
    raw_url: str, cases: tuple[SecurityCase, ...]
) -> tuple[SecurityResult, ...]:
    """Run cases sequentially so fixture state changes remain reproducible."""
    results: list[SecurityResult] = []
    for case in cases:
        if case.session_policy is SessionPolicy.REUSED:
            assert case.establishing_actor is not None
            observation = await observe_reused_session(
                raw_url, case.establishing_actor, case.actor, case.action
            )
        else:
            observation = (
                await compare_identities(raw_url, case.action, (case.actor,))
            )[0]
        results.append(evaluate(case, observation))
    return tuple(results)


def built_in_cases(
    *, alice_token: str, bob_token: str, invalid_token: str, expired_token: str
) -> tuple[SecurityCase, ...]:
    """Return the bounded authorization suite supported by the disposable lab."""
    anonymous = Actor("anonymous", ActorKind.ANONYMOUS)
    alice = Actor("alice", ActorKind.AUTHENTICATED, alice_token)
    bob = Actor("bob", ActorKind.AUTHENTICATED, bob_token)
    invalid = Actor("invalid", ActorKind.INVALID, invalid_token)
    expired = Actor("expired", ActorKind.EXPIRED, expired_token)
    tool = Action(
        ActionKind.TOOL_CALL,
        "safe_echo",
        {"message": "mcprift-probe"},
        known_safe=True,
    )

    return (
        SecurityCase(
            "MCPRIFT-AUTH-001",
            "anonymous callers cannot invoke the safe fixture tool",
            anonymous,
            tool,
            ExpectedProperty.DENIED,
        ),
        SecurityCase(
            "MCPRIFT-AUTH-002",
            "authenticated callers can invoke the safe fixture tool",
            alice,
            tool,
            ExpectedProperty.ALLOWED,
        ),
        SecurityCase(
            "MCPRIFT-AUTH-003",
            "invalid credentials cannot invoke the safe fixture tool",
            invalid,
            tool,
            ExpectedProperty.DENIED,
        ),
        SecurityCase(
            "MCPRIFT-AUTH-004",
            "expired credentials cannot invoke the safe fixture tool",
            expired,
            tool,
            ExpectedProperty.DENIED,
        ),
        SecurityCase(
            "MCPRIFT-BOUNDARY-001",
            "alice can read her own resource",
            alice,
            Action(ActionKind.RESOURCE_READ, "lab://users/alice"),
            ExpectedProperty.ALLOWED,
        ),
        SecurityCase(
            "MCPRIFT-BOUNDARY-002",
            "alice cannot read bob's resource",
            alice,
            Action(ActionKind.RESOURCE_READ, "lab://users/bob"),
            ExpectedProperty.DENIED,
        ),
        SecurityCase(
            "MCPRIFT-BOUNDARY-003",
            "bob can read his own resource",
            bob,
            Action(ActionKind.RESOURCE_READ, "lab://users/bob"),
            ExpectedProperty.ALLOWED,
        ),
        SecurityCase(
            "MCPRIFT-BOUNDARY-004",
            "bob cannot read alice's resource",
            bob,
            Action(ActionKind.RESOURCE_READ, "lab://users/alice"),
            ExpectedProperty.DENIED,
        ),
        SecurityCase(
            SESSION_CASE_ID,
            "alice's credentials cannot authorize bob after session reuse",
            bob,
            Action(ActionKind.RESOURCE_READ, "lab://users/alice"),
            ExpectedProperty.DENIED,
            SessionPolicy.REUSED,
            alice,
        ),
    )
