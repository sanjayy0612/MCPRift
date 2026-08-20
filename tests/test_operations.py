from __future__ import annotations

import asyncio
import unittest

from mcp import Client
from mcp.server import MCPServer

from mcprift.actors import Actor, ActorKind
from mcprift.operations import Action, ActionKind, Outcome, observe_client


class ActorTests(unittest.TestCase):
    def test_token_is_excluded_from_repr_and_serialization(self) -> None:
        actor = Actor("alice", ActorKind.AUTHENTICATED, "secret-value")

        self.assertNotIn("secret-value", repr(actor))
        self.assertEqual(actor.to_dict(), {"name": "alice", "kind": "authenticated"})

    def test_tool_action_requires_explicit_safety_assertion(self) -> None:
        with self.assertRaises(ValueError):
            Action(ActionKind.TOOL_CALL, "unknown")


class OperationTests(unittest.TestCase):
    def test_observes_success_without_retaining_response_content(self) -> None:
        server = MCPServer("operation-fixture")

        @server.tool()
        def safe_echo(message: str) -> str:
            return f"sensitive response: {message}"

        actor = Actor("anonymous", ActorKind.ANONYMOUS)
        action = Action(
            ActionKind.TOOL_CALL,
            "safe_echo",
            {"message": "secret-value"},
            known_safe=True,
        )

        async def observe() -> object:
            async with Client(server, client_info=None) as client:
                return await observe_client(client, actor, action)

        observation = asyncio.run(observe())

        self.assertEqual(observation.outcome, Outcome.SUCCEEDED)
        self.assertEqual(observation.item_count, 1)
        self.assertNotIn("secret-value", repr(observation))
