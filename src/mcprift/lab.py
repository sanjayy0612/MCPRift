"""Disposable MCP security lab with explicit vulnerability toggles."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import replace

from mcp.server import MCPServer
from mcp.server.mcpserver import Context

ALICE_TOKEN = "mcprift-lab-alice"
BOB_TOKEN = "mcprift-lab-bob"
EXPIRED_TOKEN = "mcprift-lab-expired"

ANONYMOUS_TOOL = "anonymous-tool"
CROSS_USER_RESOURCE = "cross-user-resource"
EXPIRED_CREDENTIAL = "expired-credential"
SESSION_IDENTITY_CROSSOVER = "session-identity-crossover"
PROMPT_ACCESS = "prompt-access"
CAPABILITY_VISIBILITY_LEAK = "capability-visibility-leak"
VULNERABILITIES = frozenset(
    {
        ANONYMOUS_TOOL,
        CROSS_USER_RESOURCE,
        EXPIRED_CREDENTIAL,
        SESSION_IDENTITY_CROSSOVER,
        PROMPT_ACCESS,
        CAPABILITY_VISIBILITY_LEAK,
    }
)


def create_lab(vulnerabilities: frozenset[str] = frozenset()) -> MCPServer:
    unknown = vulnerabilities - VULNERABILITIES
    if unknown:
        raise ValueError("unknown lab vulnerability")

    lab = MCPServer(
        "mcprift-security-lab",
        version="0.4.0",
        instructions="Disposable local authorization test fixture.",
    )
    established_actors: dict[str, str] = {}

    def actor_for_request(headers: Mapping[str, str] | None) -> str | None:
        actor = _verified_actor(headers, vulnerabilities)
        if SESSION_IDENTITY_CROSSOVER not in vulnerabilities:
            return actor
        session_id = headers.get("mcp-session-id") if headers else None
        if session_id is None:
            return actor
        if session_id not in established_actors and actor is not None:
            established_actors[session_id] = actor
        return established_actors.get(session_id)

    @lab.tool(description="Return a harmless probe string.")
    def safe_echo(message: str, ctx: Context) -> str:
        actor = actor_for_request(ctx.headers)
        if actor is None and ANONYMOUS_TOOL not in vulnerabilities:
            raise PermissionError("access denied")
        return message

    @lab.resource(
        "lab://public",
        name="public_information",
        description="Public non-sensitive fixture content.",
    )
    def public_information() -> str:
        return "public fixture content"

    @lab.resource(
        "lab://users/{owner}",
        name="private_user_resource",
        description="Synthetic per-user fixture content.",
    )
    def private_user_resource(owner: str, ctx: Context) -> str:
        actor = actor_for_request(ctx.headers)
        if actor is None:
            raise PermissionError("access denied")
        if actor != owner and CROSS_USER_RESOURCE not in vulnerabilities:
            raise PermissionError("access denied")
        return f"synthetic private content for {owner}"

    @lab.prompt(description="Create a harmless review request.")
    def review_prompt(subject: str, ctx: Context) -> str:
        actor = actor_for_request(ctx.headers)
        if actor is None and PROMPT_ACCESS not in vulnerabilities:
            raise PermissionError("access denied")
        return f"Review the synthetic subject: {subject}"

    _install_visibility_filters(lab, vulnerabilities)

    return lab


def _install_visibility_filters(
    lab: MCPServer, vulnerabilities: frozenset[str]
) -> None:
    """Make the disposable fixture's advertised private capabilities actor-aware."""
    handlers = lab._lowlevel_server._request_handlers  # type: ignore[attr-defined]
    for method, field in (
        ("resources/templates/list", "resource_templates"),
        ("prompts/list", "prompts"),
    ):
        entry = handlers[method]
        original = entry.handler

        async def filtered(
            context: object, params: object, *, _original=original, _field=field
        ):
            result = await _original(context, params)
            request = getattr(context, "request", None)
            headers = getattr(request, "headers", {}) or {}
            if headers.get("x-mcprift-unbound") == "true" or _visible_to_actor(
                headers, vulnerabilities
            ):
                return result
            items = [
                item
                for item in getattr(result, _field)
                if item.name not in {"private_user_resource", "review_prompt"}
            ]
            return result.model_copy(update={_field: items})

        handlers[method] = replace(entry, handler=filtered)


def _visible_to_actor(
    headers: Mapping[str, str], vulnerabilities: frozenset[str]
) -> bool:
    if "authorization" not in headers:
        return (
            PROMPT_ACCESS in vulnerabilities
            or CAPABILITY_VISIBILITY_LEAK in vulnerabilities
        )
    return (
        _verified_actor(headers, vulnerabilities) is not None
        or PROMPT_ACCESS in vulnerabilities
        or CAPABILITY_VISIBILITY_LEAK in vulnerabilities
    )


def _verified_actor(
    headers: Mapping[str, str] | None, vulnerabilities: frozenset[str]
) -> str | None:
    authorization = headers.get("authorization") if headers else None
    if authorization == f"Bearer {ALICE_TOKEN}":
        return "alice"
    if authorization == f"Bearer {BOB_TOKEN}":
        return "bob"
    if (
        authorization == f"Bearer {EXPIRED_TOKEN}"
        and EXPIRED_CREDENTIAL in vulnerabilities
    ):
        return "alice"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the disposable MCPRift lab.")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--vulnerable",
        action="append",
        default=[],
        choices=sorted(VULNERABILITIES),
        help="opt in to one vulnerability; may be repeated",
    )
    arguments = parser.parse_args()
    lab = create_lab(frozenset(arguments.vulnerable))
    lab.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=arguments.port,
        json_response=True,
        stateless_http=False,
    )


if __name__ == "__main__":
    main()
