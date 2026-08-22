"""Bounded MCP capability inspection."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from mcp import Client

from mcprift.actors import Actor
from mcprift.client import (
    ConnectionFailure,
    ConnectionResult,
    controlled_client,
    validate_controlled_url,
)

MAX_PAGES = 100
MAX_CAPABILITIES = 1_000


@dataclass(frozen=True)
class Capability:
    """A small, transport-independent description of one server capability."""

    kind: str
    name: str
    title: str | None = None
    description: str | None = None
    uri: str | None = None
    input_schema: dict[str, Any] | None = None


@dataclass(frozen=True)
class CapabilityInventory:
    """Connection metadata and the capabilities visible in that session."""

    connection: ConnectionResult
    capabilities: tuple[Capability, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Page(Protocol):
    next_cursor: str | None


PageFetcher = Callable[..., Awaitable[_Page]]


async def inspect_capabilities(
    raw_url: str, actor: Actor | None = None, *, timeout_seconds: float = 10
) -> CapabilityInventory:
    """Inspect a controlled server without invoking any listed capability."""
    url = validate_controlled_url(raw_url)
    try:
        return await asyncio.wait_for(
            _inspect_with_sdk(url, actor), timeout=timeout_seconds
        )
    except (ConnectionFailure, TimeoutError):
        raise
    except Exception as error:
        raise ConnectionFailure("MCP capability inspection failed") from error


async def _inspect_with_sdk(url: str, actor: Actor | None) -> CapabilityInventory:
    async with controlled_client(url, actor) as client:
        return await inspect_client(client)


async def inspect_client(client: Client) -> CapabilityInventory:
    """Build an inventory from an already connected SDK client."""
    server_info = client.server_info
    connection = ConnectionResult(
        protocol_version=client.protocol_version or "unknown",
        server_name=server_info.name if server_info else "unknown",
        server_version=server_info.version if server_info else "unknown",
    )

    # MCP servers advertise the list methods they implement during initialization.
    # Calling an unadvertised method is a protocol error, not an empty result.
    capabilities = client.server_capabilities
    tools = (
        await _all_pages(client.list_tools, "tools") if capabilities.tools else []
    )
    resources = (
        await _all_pages(client.list_resources, "resources")
        if capabilities.resources
        else []
    )
    resource_templates = (
        await _all_pages(client.list_resource_templates, "resource_templates")
        if capabilities.resources
        else []
    )
    prompts = (
        await _all_pages(client.list_prompts, "prompts")
        if capabilities.prompts
        else []
    )

    capabilities = [
        Capability(
            kind="tool",
            name=tool.name,
            title=tool.title,
            description=tool.description,
            input_schema=tool.input_schema,
        )
        for tool in tools
    ]
    capabilities.extend(
        Capability(
            kind="resource",
            name=resource.name,
            title=resource.title,
            description=resource.description,
            uri=str(resource.uri),
        )
        for resource in resources
    )
    capabilities.extend(
        Capability(
            kind="resource-template",
            name=template.name,
            title=template.title,
            description=template.description,
            uri=template.uri_template,
        )
        for template in resource_templates
    )
    capabilities.extend(
        Capability(
            kind="prompt",
            name=prompt.name,
            title=prompt.title,
            description=prompt.description,
        )
        for prompt in prompts
    )
    return CapabilityInventory(connection, tuple(capabilities))


async def _all_pages(fetch: PageFetcher, item_attribute: str) -> list[Any]:
    """Read a paginated listing with hard limits for hostile servers."""
    items: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    for _ in range(MAX_PAGES):
        page = await fetch(cursor=cursor, cache_mode="refresh")
        page_items: Sequence[Any] = getattr(page, item_attribute)
        if len(items) + len(page_items) > MAX_CAPABILITIES:
            raise ValueError("server capability limit exceeded")
        items.extend(page_items)

        cursor = page.next_cursor
        if cursor is None:
            return items
        if cursor in seen_cursors:
            raise ValueError("server returned a repeated capability cursor")
        seen_cursors.add(cursor)

    raise ValueError("server capability page limit exceeded")
