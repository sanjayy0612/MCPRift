"""Strict, versioned authorization contracts for controlled MCP targets."""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcprift.actors import Actor, ActorKind
from mcprift.client import ConnectionFailure, validate_controlled_url
from mcprift.mutation import MutationKind
from mcprift.operations import Action, ActionKind, SessionPolicy
from mcprift.security import ExpectedProperty, SecurityCase

SCHEMA_VERSION = 2
ASSESSMENT_SCHEMA_VERSION = SCHEMA_VERSION
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SECRET_KEYS = {"access_token", "authorization", "password", "secret", "token"}
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "target",
    "actors",
    "access",
    "visibility",
    "protocol",
}


@dataclass(frozen=True)
class ActorDeclaration:
    name: str
    kind: ActorKind
    token_env: str | None = None

    def resolve(self) -> Actor:
        if self.kind is ActorKind.ANONYMOUS:
            return Actor(self.name, self.kind)
        if self.token_env is None or not os.environ.get(self.token_env):
            raise ConnectionFailure(
                "required actor credential environment variable is not set"
            )
        return Actor(self.name, self.kind, os.environ[self.token_env])


@dataclass(frozen=True)
class AccessDeclaration:
    case_id: str
    title: str
    actor_name: str
    action: Action
    expected: ExpectedProperty
    session_policy: SessionPolicy = SessionPolicy.ISOLATED
    establishing_actor_name: str | None = None


@dataclass(frozen=True)
class VisibilityDeclaration:
    case_id: str
    title: str
    actor_name: str
    capability_kind: str
    capability: str
    expected: str


@dataclass(frozen=True)
class ProtocolDeclaration:
    case_id: str
    title: str
    mutation: MutationKind
    expected: str = "rejected"


@dataclass(frozen=True)
class AssessmentPlan:
    """An operator-authored v0.4 contract with no resolved secrets."""

    target: str
    actors: dict[str, ActorDeclaration]
    access: tuple[AccessDeclaration, ...]
    visibility: tuple[VisibilityDeclaration, ...]
    protocol: tuple[ProtocolDeclaration, ...]

    @property
    def cases(self) -> tuple[AccessDeclaration, ...]:
        """Compatibility alias for callers that only knew v0.3 access cases."""
        return self.access

    def has_tool_calls(self) -> bool:
        return any(case.action.kind is ActionKind.TOOL_CALL for case in self.access)

    def resolve_actors(self) -> dict[str, Actor]:
        return {
            name: declaration.resolve() for name, declaration in self.actors.items()
        }

    def runtime_access_cases(
        self, actors: dict[str, Actor]
    ) -> tuple[SecurityCase, ...]:
        return tuple(
            SecurityCase(
                case.case_id,
                case.title,
                actors[case.actor_name],
                case.action,
                case.expected,
                case.session_policy,
                actors[case.establishing_actor_name]
                if case.establishing_actor_name is not None
                else None,
            )
            for case in self.access
        )


def load_assessment(path: str | Path) -> AssessmentPlan:
    """Load a contract strictly and offline; credentials are not resolved."""
    try:
        value = json.loads(
            Path(path).read_text(encoding="utf-8"), parse_constant=_reject_constant
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("invalid assessment file") from error
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported assessment schema")
    if set(value) != _TOP_LEVEL_FIELDS:
        raise ValueError("assessment contains unsupported or missing fields")

    target = value["target"]
    if not isinstance(target, str):
        raise ValueError("assessment target must be a string")
    try:
        validate_controlled_url(target)
    except ConnectionFailure as error:
        raise ValueError(
            "assessment target must be a controlled loopback URL"
        ) from error

    actors = _load_actor_declarations(value["actors"])
    access = tuple(
        _load_access(item, actors) for item in _list(value["access"], "access")
    )
    visibility = tuple(
        _load_visibility(item, actors)
        for item in _list(value["visibility"], "visibility")
    )
    protocol = tuple(
        _load_protocol(item) for item in _list(value["protocol"], "protocol")
    )
    all_ids = [case.case_id for case in (*access, *visibility, *protocol)]
    if not all_ids:
        raise ValueError("assessment must define at least one case")
    if len(set(all_ids)) != len(all_ids):
        raise ValueError("assessment case IDs must be unique")
    return AssessmentPlan(target, actors, access, visibility, protocol)


def validate_assessment(path: str | Path) -> AssessmentPlan:
    """Validate a contract without resolving environment variables or connecting."""
    return load_assessment(path)


def contains_safe_actions(plan: AssessmentPlan) -> bool:
    return plan.has_tool_calls()


def write_lab_template(path: str | Path) -> Path:
    """Write a non-secret, runnable contract for the disposable lab."""
    destination = Path(path)
    if destination.exists():
        raise ValueError("assessment file already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(_lab_template(), indent=2) + "\n", encoding="utf-8"
    )
    return destination


def _load_actor_declarations(value: object) -> dict[str, ActorDeclaration]:
    if not isinstance(value, dict) or not value:
        raise ValueError("assessment must define actors")
    actors: dict[str, ActorDeclaration] = {}
    for name, raw in value.items():
        if not isinstance(name, str) or not name or not isinstance(raw, dict):
            raise ValueError("invalid assessment actor")
        _reject_secret_keys(raw)
        if set(raw) - {"kind", "token_env"} or "kind" not in raw:
            raise ValueError("assessment actor contains unsupported fields")
        try:
            kind = ActorKind(raw["kind"])
        except (TypeError, ValueError) as error:
            raise ValueError("assessment actor has an invalid kind") from error
        token_env = raw.get("token_env")
        if kind is ActorKind.ANONYMOUS:
            if set(raw) != {"kind"}:
                raise ValueError("anonymous actors cannot define credentials")
        elif (
            set(raw) != {"kind", "token_env"}
            or not isinstance(token_env, str)
            or not _ENVIRONMENT_NAME.fullmatch(token_env)
        ):
            raise ValueError("credentialed actors require a valid token_env")
        actors[name] = ActorDeclaration(name, kind, token_env)
    return actors


def _load_access(
    value: object, actors: dict[str, ActorDeclaration]
) -> AccessDeclaration:
    if not isinstance(value, dict):
        raise ValueError("case contains unsupported or missing fields")
    allowed = {"id", "title", "actor", "action", "expected", "session"}
    required = {"id", "title", "actor", "action", "expected"}
    if set(value) - allowed or not required.issubset(value):
        raise ValueError("case contains unsupported or missing fields")
    _reject_secret_keys(value)
    raw = value
    case_id = _string(raw, "id")
    title = _string(raw, "title")
    actor_name = _string(raw, "actor")
    _actor_exists(actor_name, actors)
    try:
        expected = ExpectedProperty(_string(raw, "expected"))
    except ValueError as error:
        raise ValueError("access case has an invalid expected outcome") from error
    session = raw.get("session", {"policy": "isolated"})
    if not isinstance(session, dict) or set(session) - {"policy", "establishing_actor"}:
        raise ValueError("invalid access session declaration")
    try:
        policy = SessionPolicy(session.get("policy", "isolated"))
    except ValueError as error:
        raise ValueError("invalid access session policy") from error
    establishing = session.get("establishing_actor")
    if policy is SessionPolicy.REUSED:
        if not isinstance(establishing, str) or not establishing:
            raise ValueError("reused access requires establishing_actor")
        _actor_exists(establishing, actors)
    elif set(session) != {"policy"}:
        raise ValueError("isolated access cannot define establishing_actor")
    return AccessDeclaration(
        case_id,
        title,
        actor_name,
        _load_action(raw["action"]),
        expected,
        policy,
        establishing,
    )


def _load_visibility(
    value: object, actors: dict[str, ActorDeclaration]
) -> VisibilityDeclaration:
    raw = _case_object(
        value, {"id", "title", "actor", "kind", "capability", "expected"}
    )
    actor_name = _string(raw, "actor")
    _actor_exists(actor_name, actors)
    kind = _string(raw, "kind")
    if kind not in {"tool", "resource", "resource-template", "prompt"}:
        raise ValueError("visibility case has an invalid capability kind")
    expected = _string(raw, "expected")
    if expected not in {"visible", "hidden"}:
        raise ValueError("visibility cases expect visible or hidden")
    return VisibilityDeclaration(
        _string(raw, "id"),
        _string(raw, "title"),
        actor_name,
        kind,
        _string(raw, "capability"),
        expected,
    )


def _load_protocol(value: object) -> ProtocolDeclaration:
    raw = _case_object(value, {"id", "title", "mutation", "expected"})
    try:
        mutation = MutationKind(_string(raw, "mutation"))
    except ValueError as error:
        raise ValueError("protocol case has an invalid mutation") from error
    expected = _string(raw, "expected")
    if expected != "rejected":
        raise ValueError("protocol cases currently require expected=rejected")
    return ProtocolDeclaration(_string(raw, "id"), _string(raw, "title"), mutation)


def _load_action(value: object) -> Action:
    if not isinstance(value, dict):
        raise ValueError("invalid assessment action")
    _reject_secret_keys(value)
    allowed = {"kind", "target", "arguments", "known_safe", "safety_justification"}
    if set(value) - allowed:
        raise ValueError("assessment action contains unsupported fields")
    try:
        kind = ActionKind(_string(value, "kind"))
    except ValueError as error:
        raise ValueError("assessment action has an invalid kind") from error
    target = _string(value, "target")
    arguments = value.get("arguments")
    if arguments is not None and not isinstance(arguments, dict):
        raise ValueError("assessment action arguments must be an object")
    if arguments is not None:
        _validate_json_object(arguments)
    if kind is ActionKind.TOOL_CALL:
        justification = value.get("safety_justification")
        if (
            value.get("known_safe") is not True
            or not isinstance(justification, str)
            or not justification.strip()
        ):
            raise ValueError(
                "tool actions require known_safe=true and safety_justification"
            )
    elif "known_safe" in value or "safety_justification" in value:
        raise ValueError("only tool actions may declare safe-action metadata")
    if kind is ActionKind.RESOURCE_READ and arguments is not None:
        raise ValueError("resource-read actions cannot define arguments")
    return Action(
        kind,
        target,
        arguments,
        known_safe=kind is ActionKind.TOOL_CALL,
        safety_justification=value.get("safety_justification"),
    )


def _case_object(value: object, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != allowed:
        raise ValueError("case contains unsupported or missing fields")
    _reject_secret_keys(value)
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"assessment {name} must be an array")
    return value


def _actor_exists(name: str, actors: dict[str, ActorDeclaration]) -> None:
    if name not in actors:
        raise ValueError("case refers to an unknown actor")


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return item


def _reject_secret_keys(value: dict[str, Any]) -> None:
    if any(str(key).lower() in _SECRET_KEYS for key in value):
        raise ValueError("inline credentials are not allowed")


def _validate_json_object(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("action arguments must be an object")
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("action argument names must be strings")
        if key.lower() in _SECRET_KEYS:
            raise ValueError("inline credentials are not allowed")
        _validate_json_value(item)


def _validate_json_value(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite action arguments are not allowed")
    if isinstance(value, dict):
        _validate_json_object(value)
    elif isinstance(value, list):
        for item in value:
            _validate_json_value(item)


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _lab_template() -> dict[str, Any]:
    tool = {
        "kind": "tool-call",
        "target": "safe_echo",
        "arguments": {"message": "mcprift-probe"},
        "known_safe": True,
        "safety_justification": (
            "The disposable lab tool only echoes a fixed probe message."
        ),
    }
    access = [
        {
            "id": "MCPRIFT-AUTH-001",
            "title": "anonymous tool access is denied",
            "actor": "anonymous",
            "action": tool,
            "expected": "denied",
        },
        {
            "id": "MCPRIFT-AUTH-002",
            "title": "Alice can invoke the safe tool",
            "actor": "alice",
            "action": tool,
            "expected": "allowed",
        },
        {
            "id": "MCPRIFT-AUTH-003",
            "title": "invalid credentials are denied",
            "actor": "invalid",
            "action": tool,
            "expected": "denied",
        },
        {
            "id": "MCPRIFT-AUTH-004",
            "title": "expired credentials are denied",
            "actor": "expired",
            "action": tool,
            "expected": "denied",
        },
        {
            "id": "MCPRIFT-BOUNDARY-001",
            "title": "Alice can read her resource",
            "actor": "alice",
            "action": {"kind": "resource-read", "target": "lab://users/alice"},
            "expected": "allowed",
        },
        {
            "id": "MCPRIFT-BOUNDARY-002",
            "title": "Alice cannot read Bob's resource",
            "actor": "alice",
            "action": {"kind": "resource-read", "target": "lab://users/bob"},
            "expected": "denied",
        },
        {
            "id": "MCPRIFT-BOUNDARY-003",
            "title": "Bob can read his resource",
            "actor": "bob",
            "action": {"kind": "resource-read", "target": "lab://users/bob"},
            "expected": "allowed",
        },
        {
            "id": "MCPRIFT-BOUNDARY-004",
            "title": "Bob cannot read Alice's resource",
            "actor": "bob",
            "action": {"kind": "resource-read", "target": "lab://users/alice"},
            "expected": "denied",
        },
        {
            "id": "MCPRIFT-PROMPT-001",
            "title": "anonymous prompt access is denied",
            "actor": "anonymous",
            "action": {
                "kind": "prompt-get",
                "target": "review_prompt",
                "arguments": {"subject": "mcprift"},
            },
            "expected": "denied",
        },
        {
            "id": "MCPRIFT-PROMPT-002",
            "title": "Alice can retrieve the review prompt",
            "actor": "alice",
            "action": {
                "kind": "prompt-get",
                "target": "review_prompt",
                "arguments": {"subject": "mcprift"},
            },
            "expected": "allowed",
        },
        {
            "id": "MCPRIFT-SESSION-001",
            "title": "Alice's session identity cannot authorize Bob",
            "actor": "bob",
            "action": {"kind": "resource-read", "target": "lab://users/alice"},
            "expected": "denied",
            "session": {"policy": "reused", "establishing_actor": "alice"},
        },
    ]
    visibility = [
        {
            "id": "MCPRIFT-VIS-001",
            "title": "safe tool is visible anonymously",
            "actor": "anonymous",
            "kind": "tool",
            "capability": "safe_echo",
            "expected": "visible",
        },
        {
            "id": "MCPRIFT-VIS-002",
            "title": "safe tool is visible to Alice",
            "actor": "alice",
            "kind": "tool",
            "capability": "safe_echo",
            "expected": "visible",
        },
        {
            "id": "MCPRIFT-VIS-003",
            "title": "private resource template is hidden anonymously",
            "actor": "anonymous",
            "kind": "resource-template",
            "capability": "private_user_resource",
            "expected": "hidden",
        },
        {
            "id": "MCPRIFT-VIS-004",
            "title": "private resource template is visible to Alice",
            "actor": "alice",
            "kind": "resource-template",
            "capability": "private_user_resource",
            "expected": "visible",
        },
        {
            "id": "MCPRIFT-VIS-005",
            "title": "review prompt is hidden anonymously",
            "actor": "anonymous",
            "kind": "prompt",
            "capability": "review_prompt",
            "expected": "hidden",
        },
        {
            "id": "MCPRIFT-VIS-006",
            "title": "review prompt is visible to Alice",
            "actor": "alice",
            "kind": "prompt",
            "capability": "review_prompt",
            "expected": "visible",
        },
        {
            "id": "MCPRIFT-VIS-007",
            "title": "public resource is visible anonymously",
            "actor": "anonymous",
            "kind": "resource",
            "capability": "public_information",
            "expected": "visible",
        },
    ]
    protocol = [
        {
            "id": f"MCPRIFT-PROTOCOL-{index:03d}",
            "title": f"{mutation} is rejected",
            "mutation": mutation,
            "expected": "rejected",
        }
        for index, mutation in enumerate((item.value for item in MutationKind), 1)
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "target": "http://127.0.0.1:8080/mcp",
        "actors": {
            "anonymous": {"kind": "anonymous"},
            "alice": {"kind": "authenticated", "token_env": "MCPRIFT_AUTH_TOKEN"},
            "bob": {"kind": "authenticated", "token_env": "MCPRIFT_BOB_TOKEN"},
            "invalid": {"kind": "invalid", "token_env": "MCPRIFT_INVALID_TOKEN"},
            "expired": {"kind": "expired", "token_env": "MCPRIFT_EXPIRED_TOKEN"},
        },
        "access": access,
        "visibility": visibility,
        "protocol": protocol,
    }
