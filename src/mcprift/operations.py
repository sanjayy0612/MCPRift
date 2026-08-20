"""Safe operation comparison across explicit identity contexts."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from mcp import Client

from mcprift.actors import Actor
from mcprift.client import controlled_client, validate_controlled_url


class ActionKind(StrEnum):
    TOOL_CALL = "tool-call"
    RESOURCE_READ = "resource-read"
    PROMPT_GET = "prompt-get"


class Outcome(StrEnum):
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


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

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": {"name": self.actor_name, "kind": self.actor_kind},
            "outcome": self.outcome.value,
            "protocol_version": self.protocol_version,
            "item_count": self.item_count,
        }


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
