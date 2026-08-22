"""Deterministic raw JSON-RPC mutations kept separate from SDK operations."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

import httpx2

from mcprift.client import ConnectionFailure, validate_controlled_url

MAX_RESPONSE_BYTES = 1_000_000


class MutationKind(StrEnum):
    INVALID_JSON = "invalid-json"
    MISSING_JSONRPC = "missing-jsonrpc"
    UNKNOWN_METHOD = "unknown-method"
    EMPTY_BATCH = "empty-batch"


@dataclass(frozen=True)
class MutationObservation:
    kind: MutationKind
    http_status: int
    content_type: str
    response_bytes: int
    response_sha256: str
    json_rpc_error: bool
    session_established: bool

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["kind"] = self.kind.value
        return result


def mutation_body(kind: MutationKind) -> bytes:
    """Return a byte-exact, credential-free mutation body."""
    if kind is MutationKind.INVALID_JSON:
        return b"{"
    if kind is MutationKind.MISSING_JSONRPC:
        value: Any = {
            "id": "mcprift-mutation",
            "method": "ping",
            "params": {},
        }
    elif kind is MutationKind.UNKNOWN_METHOD:
        value = {
            "jsonrpc": "2.0",
            "id": "mcprift-mutation",
            "method": "mcprift/unknown",
            "params": {},
        }
    else:
        value = []
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


async def run_mutation(
    raw_url: str, kind: MutationKind, *, timeout_seconds: float = 10
) -> MutationObservation:
    """Send one unusual request and retain no server response content."""
    url = validate_controlled_url(raw_url)
    try:
        return await asyncio.wait_for(
            _post_mutation(url, kind), timeout=timeout_seconds
        )
    except (ConnectionFailure, TimeoutError):
        raise
    except Exception as error:
        raise ConnectionFailure("raw protocol mutation failed") from error


async def _post_mutation(url: str, kind: MutationKind) -> MutationObservation:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    async with httpx2.AsyncClient(follow_redirects=False, timeout=10) as client:
        async with client.stream(
            "POST", url, headers=headers, content=mutation_body(kind)
        ) as response:
            content = bytearray()
            async for chunk in response.aiter_bytes():
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError("mutation response limit exceeded")
                content.extend(chunk)
    content_type = response.headers.get("content-type", "").split(";", 1)[0]
    body = bytes(content)
    return MutationObservation(
        kind=kind,
        http_status=response.status_code,
        content_type=content_type,
        response_bytes=len(content),
        response_sha256=hashlib.sha256(body).hexdigest(),
        json_rpc_error=_contains_json_rpc_error(body, content_type),
        # A rejected request may still receive an implementation-specific
        # session header. It is not a usable MCP session until the request was
        # accepted by the protocol endpoint.
        session_established=(
            response.status_code < 400 and "mcp-session-id" in response.headers
        ),
    )


def _contains_json_rpc_error(body: bytes, content_type: str) -> bool:
    """Derive an error bit in memory without retaining the response body."""
    try:
        if content_type == "text/event-stream":
            values = []
            for line in body.decode("utf-8", "replace").splitlines():
                if line.startswith("data:"):
                    values.append(json.loads(line[5:].strip()))
        else:
            values = [json.loads(body)]
    except (UnicodeError, json.JSONDecodeError):
        return False
    return any(
        isinstance(value, dict) and isinstance(value.get("error"), dict)
        for value in values
    )
