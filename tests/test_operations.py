from __future__ import annotations

import asyncio
import unittest

import httpx2
from mcp import Client
from mcp.server import MCPServer
from mcp.shared.exceptions import MCPError

from mcprift.actors import Actor, ActorKind
from mcprift.client import HTTPStatusRecorder
from mcprift.operations import (
    Action,
    ActionKind,
    Outcome,
    observe_client,
)


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

        self.assertEqual(observation.outcome, Outcome.ALLOWED)
        self.assertEqual(observation.item_count, 1)
        self.assertNotIn("secret-value", repr(observation))

    def test_tool_error_is_not_treated_as_authorization_denial(self) -> None:
        server = MCPServer("operation-error-fixture")

        @server.tool()
        def fail() -> str:
            raise ValueError("private server detail")

        actor = Actor("anonymous", ActorKind.ANONYMOUS)
        action = Action(ActionKind.TOOL_CALL, "fail", {}, known_safe=True)

        async def observe() -> object:
            async with Client(server, client_info=None) as client:
                return await observe_client(client, actor, action)

        observation = asyncio.run(observe())

        self.assertEqual(observation.outcome, Outcome.TOOL_ERROR)
        self.assertNotIn("private server detail", repr(observation))

    def test_protocol_and_unavailable_failures_remain_distinct(self) -> None:
        actor = Actor("anonymous", ActorKind.ANONYMOUS)
        action = Action(ActionKind.RESOURCE_READ, "lab://private")

        class FailingClient:
            protocol_version = "2025-06-18"

            def __init__(self, error: Exception) -> None:
                self.error = error

            async def read_resource(self, target: str) -> object:
                raise self.error

        async def observe(error: Exception) -> object:
            return await observe_client(
                FailingClient(error),
                actor,
                action,  # type: ignore[arg-type]
            )

        protocol = asyncio.run(observe(MCPError(-32601, "private protocol detail")))
        unavailable = asyncio.run(observe(httpx2.ConnectError("private target")))

        self.assertEqual(protocol.outcome, Outcome.PROTOCOL_ERROR)
        self.assertEqual(unavailable.outcome, Outcome.UNAVAILABLE)
        self.assertNotIn("private protocol detail", repr(protocol))
        self.assertNotIn("private target", repr(unavailable))

    def test_http_boundary_statuses_are_the_only_auth_denial_signals(self) -> None:
        actor = Actor("anonymous", ActorKind.ANONYMOUS)
        action = Action(ActionKind.RESOURCE_READ, "lab://private")

        class FailingClient:
            protocol_version = "2025-06-18"

            def __init__(
                self, recorder: HTTPStatusRecorder, status: int | None
            ) -> None:
                self.recorder = recorder
                self.status = status

            async def read_resource(self, target: str) -> object:
                self.recorder.status = self.status
                raise RuntimeError("private transport detail")

        async def observe(status: int | None) -> object:
            recorder = HTTPStatusRecorder()
            return await observe_client(
                FailingClient(recorder, status),
                actor,
                action,
                recorder,  # type: ignore[arg-type]
            )

        self.assertEqual(
            asyncio.run(observe(401)).outcome, Outcome.AUTHENTICATION_DENIED
        )
        self.assertEqual(
            asyncio.run(observe(403)).outcome, Outcome.AUTHORIZATION_DENIED
        )
        self.assertEqual(asyncio.run(observe(429)).outcome, Outcome.RATE_LIMITED)
        self.assertEqual(asyncio.run(observe(None)).outcome, Outcome.TRANSPORT_ERROR)
