"""Safe, SDK-managed baseline connections to controlled MCP endpoints."""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp import Client

TRANSPORT = "streamable-http"


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
    # A URL selects the SDK's Streamable HTTP transport. Entering this context
    # performs discovery/initialization; no capabilities are inspected here.
    async with Client(url, client_info=None) as client:
        server_info = client.server_info
        return ConnectionResult(
            protocol_version=client.protocol_version or "unknown",
            server_name=server_info.name if server_info else "unknown",
            server_version=server_info.version if server_info else "unknown",
        )
