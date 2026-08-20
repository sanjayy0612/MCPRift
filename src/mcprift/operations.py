"""Safe operation comparison across explicit identity contexts."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from mcp import Client

from mcprift.actors import Actor
from mcprift.client import (
    controlled_client,
    controlled_session,
    validate_controlled_url,
)


class ActionKind(StrEnum):
    TOOL_CALL = "tool-call"
    RESOURCE_READ = "resource-read"
    PROMPT_GET = "prompt-get"


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class SessionPolicy(StrEnum):
    """Whether an observation gets a fresh session or reuses established state."""

    ISOLATED = "isolated"
    REUSED = "reused"


@dataclass(frozen=True)
class Action:
    """One bounded MCP operation; tool calls require an explicit safety assertion."""

    kind: ActionKind
    target: str
    arguments: dict[str, Any] | None = None
    known_safe: bool = False

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("action target cannot be empty")
        if self.kind is ActionKind.TOOL_CALL and not self.known_safe:
            raise ValueError("tool action must be explicitly marked as known-safe")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "target": self.target,
            "argument_names": sorted(self.arguments) if self.arguments else [],
            "known_safe": self.known_safe,
        }


@dataclass(frozen=True)
class Observation:
    """Outcome metadata that deliberately excludes returned server content."""

    actor_name: str
    actor_kind: str
    outcome: Outcome
    protocol_version: str
    item_count: int | None = None
    session_policy: SessionPolicy = SessionPolicy.ISOLATED
    establishing_actor_name: str | None = None
    establishing_actor_kind: str | None = None
    establishing_outcome: Outcome | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "actor": {"name": self.actor_name, "kind": self.actor_kind},
            "outcome": self.outcome.value,
            "protocol_version": self.protocol_version,
            "item_count": self.item_count,
            "session": {"policy": self.session_policy.value},
        }
        if self.establishing_actor_name is not None:
            result["session"]["establishing_actor"] = {
                "name": self.establishing_actor_name,
                "kind": self.establishing_actor_kind,
            }
            result["session"]["establishing_outcome"] = (
                self.establishing_outcome.value
                if self.establishing_outcome is not None
                else None
            )
        return result


async def compare_identities(
    raw_url: str,
    action: Action,
    actors: tuple[Actor, ...],
    *,
    timeout_seconds: float = 10,
) -> tuple[Observation, ...]:
    """Run the same operation in isolated sessions for each actor."""
    validate_controlled_url(raw_url)

    async def run(actor: Actor) -> Observation:
        try:
            return await asyncio.wait_for(
                _observe_over_http(raw_url, actor, action), timeout_seconds
            )
        except Exception:
            return Observation(
                actor.name, actor.kind.value, Outcome.UNAVAILABLE, "unknown"
            )

    return tuple([await run(actor) for actor in actors])


async def _observe_over_http(raw_url: str, actor: Actor, action: Action) -> Observation:
    async with controlled_client(raw_url, actor) as client:
        return await observe_client(client, actor, action)


async def observe_reused_session(
    raw_url: str,
    establishing_actor: Actor,
    requesting_actor: Actor,
    action: Action,
    *,
    timeout_seconds: float = 10,
) -> Observation:
    """Run one safe action before and after an actor change in one SDK session."""
    validate_controlled_url(raw_url)
    try:
        return await asyncio.wait_for(
            _observe_reused_session(
                raw_url, establishing_actor, requesting_actor, action
            ),
            timeout_seconds,
        )
    except Exception:
        return Observation(
            requesting_actor.name,
            requesting_actor.kind.value,
            Outcome.UNAVAILABLE,
            "unknown",
            session_policy=SessionPolicy.REUSED,
            establishing_actor_name=establishing_actor.name,
            establishing_actor_kind=establishing_actor.kind.value,
        )


async def _observe_reused_session(
    raw_url: str,
    establishing_actor: Actor,
    requesting_actor: Actor,
    action: Action,
) -> Observation:
    async with controlled_session(
        raw_url, establishing_actor, legacy_protocol=True
    ) as session:
        establishing = await observe_client(session.client, establishing_actor, action)
        if establishing.outcome is not Outcome.SUCCEEDED:
            return Observation(
                requesting_actor.name,
                requesting_actor.kind.value,
                Outcome.UNAVAILABLE,
                establishing.protocol_version,
                session_policy=SessionPolicy.REUSED,
                establishing_actor_name=establishing_actor.name,
                establishing_actor_kind=establishing_actor.kind.value,
                establishing_outcome=establishing.outcome,
            )
        session.bind_actor(requesting_actor)
        requesting = await observe_client(session.client, requesting_actor, action)
        return replace(
            requesting,
            session_policy=SessionPolicy.REUSED,
            establishing_actor_name=establishing_actor.name,
            establishing_actor_kind=establishing_actor.kind.value,
            establishing_outcome=establishing.outcome,
        )


async def observe_client(client: Client, actor: Actor, action: Action) -> Observation:
    """Observe one operation and retain no response payload."""
    protocol_version = client.protocol_version or "unknown"
    try:
        if action.kind is ActionKind.TOOL_CALL:
            result = await client.call_tool(action.target, action.arguments)
            outcome = Outcome.REJECTED if result.is_error else Outcome.SUCCEEDED
            count = len(result.content)
        elif action.kind is ActionKind.RESOURCE_READ:
            result = await client.read_resource(action.target)
            outcome = Outcome.SUCCEEDED
            count = len(result.contents)
        else:
            result = await client.get_prompt(action.target, action.arguments)
            outcome = Outcome.SUCCEEDED
            count = len(result.messages)
    except Exception:
        outcome = Outcome.REJECTED
        count = None
    return Observation(
        actor.name,
        actor.kind.value,
        outcome,
        protocol_version,
        item_count=count,
    )
