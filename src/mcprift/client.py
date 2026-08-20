"""Safe, SDK-managed baseline connections to controlled MCP endpoints."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

if TYPE_CHECKING:
    from mcprift.actors import Actor

TRANSPORT = "streamable-http"


class _SuppressTargetLog(logging.Filter):
    """Prevent the HTTP client from logging credential-bearing target URLs."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not (
            record.name == "httpx2"
            and isinstance(record.msg, str)
            and record.msg.startswith("HTTP Request:")
        )


logging.getLogger("httpx2").addFilter(_SuppressTargetLog())


class ConnectionFailure(Exception):
    """A connection failure whose text never includes target or server data."""


@dataclass(frozen=True)
class ConnectionResult:
    """The small, safe metadata set negotiated during a baseline connection."""

    protocol_version: str
    server_name: str
    server_version: str
    transport: str = TRANSPORT


def validate_controlled_url(raw_url: str) -> str:
    """Accept only a credential-free, absolute loopback HTTP(S) URL."""
    try:
        target = urlsplit(raw_url)
    except ValueError as error:
        raise ConnectionFailure(
            "target must be a controlled loopback HTTP URL"
        ) from error

    if (
        target.scheme not in {"http", "https"}
        or not target.hostname
        or target.username is not None
        or target.password is not None
        or target.query
        or target.fragment
    ):
        raise ConnectionFailure("target must be a controlled loopback HTTP URL")

    host = target.hostname.rstrip(".").lower()
    if host == "localhost":
        return raw_url

    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise ConnectionFailure("target must be a controlled loopback HTTP URL")
    return raw_url


async def connect(raw_url: str, *, timeout_seconds: float = 10) -> ConnectionResult:
    """Perform only the SDK-managed MCP lifecycle and return safe metadata."""
    url = validate_controlled_url(raw_url)
    try:
        return await asyncio.wait_for(_connect_with_sdk(url), timeout=timeout_seconds)
    except (ConnectionFailure, TimeoutError):
        raise
    except Exception as error:
        raise ConnectionFailure("baseline MCP connection failed") from error


async def _connect_with_sdk(url: str) -> ConnectionResult:
    # Entering this context performs discovery/initialization; redirects are
    # disabled so a loopback endpoint cannot bounce credentials off-host.
    async with controlled_client(url) as client:
        server_info = client.server_info
        return ConnectionResult(
            protocol_version=client.protocol_version or "unknown",
            server_name=server_info.name if server_info else "unknown",
            server_version=server_info.version if server_info else "unknown",
        )


@asynccontextmanager
async def controlled_client(
    raw_url: str, actor: Actor | None = None
) -> AsyncIterator[Client]:
    """Open an SDK client with optional in-memory actor credentials."""
    url = validate_controlled_url(raw_url)
    headers = actor.headers if actor is not None else {}
    async with httpx2.AsyncClient(
        headers=headers, follow_redirects=False
    ) as http_client:
        transport = streamable_http_client(url, http_client=http_client)
        async with Client(transport, client_info=None) as client:
            yield client
