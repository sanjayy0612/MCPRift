from __future__ import annotations

import asyncio
import unittest

from mcp import Client
from mcp.server import MCPServer

from mcprift.capabilities import inspect_client


class CapabilityTests(unittest.TestCase):
    def test_skips_unadvertised_capability_methods(self) -> None:
        """A server that has no prompts must not receive prompts/list."""
        server = MCPServer("no-prompts-fixture", version="1.0")

        @server.tool()
        def whoami() -> str:
            return "alice"

        async def inspect() -> object:
            async with Client(server, client_info=None) as client:
                return await inspect_client(client)

        inventory = asyncio.run(inspect())

        self.assertEqual(
            [(item.kind, item.name) for item in inventory.capabilities],
            [("tool", "whoami")],
        )

    def test_inspects_capabilities_without_invoking_them(self) -> None:
        server = MCPServer("capability-fixture", version="1.0")
        invoked = False

        @server.tool()
        def safe_echo(message: str) -> str:
            nonlocal invoked
            invoked = True
            return message

        @server.resource("lab://public")
        def public_resource() -> str:
            return "public"

        @server.resource("lab://users/{user}")
        def user_resource(user: str) -> str:
            return user

        @server.prompt()
        def review_prompt(subject: str) -> str:
            return f"Review {subject}"

        async def inspect() -> object:
            async with Client(server, client_info=None) as client:
                return await inspect_client(client)

        inventory = asyncio.run(inspect())

        self.assertFalse(invoked)
        self.assertEqual(inventory.connection.server_name, "capability-fixture")
        self.assertEqual(
            [(item.kind, item.name) for item in inventory.capabilities],
            [
                ("tool", "safe_echo"),
                ("resource", "public_resource"),
                ("resource-template", "user_resource"),
                ("prompt", "review_prompt"),
            ],
        )
        self.assertEqual(
            inventory.capabilities[0].input_schema["required"], ["message"]
        )
