"""Bounded OAuth and protected-resource checks for the disposable lab."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlsplit

import httpx2

from mcprift.actors import Actor, ActorKind
from mcprift.client import controlled_client, validate_controlled_url
from mcprift.oauth_lab import (
    CLIENT_ID,
    EXPIRED_TOKEN,
    INSUFFICIENT_SCOPE_TOKEN,
    REDIRECT_URI,
    REQUIRED_SCOPE,
    VALID_TOKEN,
    WRONG_AUDIENCE_TOKEN,
)


@dataclass(frozen=True)
class OAuthCheckResult:
    check_id: str
    title: str
    passed: bool
    observed: str
    expected: str

    def to_dict(self) -> dict[str, str | bool]:
        return asdict(self)


async def run_oauth_checks(raw_url: str) -> tuple[OAuthCheckResult, ...]:
    """Run exact, non-destructive checks against the local OAuth lab."""
    resource_url = validate_controlled_url(raw_url)
    parsed = urlsplit(resource_url)
    issuer_url = f"{parsed.scheme}://{parsed.netloc}"
    results: list[OAuthCheckResult] = []
    async with httpx2.AsyncClient(follow_redirects=False, timeout=10) as client:
        metadata = await client.get(
            f"{issuer_url}/.well-known/oauth-protected-resource{parsed.path}"
        )
        metadata_value = metadata.json() if metadata.status_code == 200 else {}
        metadata_ok = (
            metadata_value.get("resource") == resource_url
            and issuer_url in metadata_value.get("authorization_servers", [])
            and REQUIRED_SCOPE in metadata_value.get("scopes_supported", [])
        )
        results.append(
            OAuthCheckResult(
                "MCPRIFT-OAUTH-001",
                "protected-resource metadata identifies this MCP server",
                metadata_ok,
                f"HTTP {metadata.status_code}",
                "HTTP 200 with matching resource, issuer, and scope",
            )
        )

        authorization_metadata = await client.get(
            f"{issuer_url}/.well-known/oauth-authorization-server"
        )
        authorization_value = (
            authorization_metadata.json()
            if authorization_metadata.status_code == 200
            else {}
        )
        authorization_ok = (
            authorization_value.get("issuer") == issuer_url
            and authorization_value.get("authorization_endpoint")
            == f"{issuer_url}/authorize"
            and authorization_value.get("token_endpoint") == f"{issuer_url}/token"
            and "S256"
            in authorization_value.get("code_challenge_methods_supported", [])
        )
        results.append(
            OAuthCheckResult(
                "MCPRIFT-OAUTH-009",
                "authorization-server metadata advertises endpoints and S256 PKCE",
                authorization_ok,
                f"HTTP {authorization_metadata.status_code}",
                "HTTP 200 with matching issuer, endpoints, and S256",
            )
        )

        cases = (
            ("MCPRIFT-OAUTH-002", "anonymous requests receive 401", None, 401),
            (
                "MCPRIFT-OAUTH-003",
                "invalid tokens receive 401",
                "mcprift-oauth-invalid",
                401,
            ),
            (
                "MCPRIFT-OAUTH-004",
                "expired tokens receive 401",
                EXPIRED_TOKEN,
                401,
            ),
            (
                "MCPRIFT-OAUTH-005",
                "wrong-audience tokens receive 401",
                WRONG_AUDIENCE_TOKEN,
                401,
            ),
            (
                "MCPRIFT-OAUTH-006",
                "insufficient scopes receive 403",
                INSUFFICIENT_SCOPE_TOKEN,
                403,
            ),
        )
        for check_id, title, token, expected_status in cases:
            response = await _post_probe(client, resource_url, token)
            challenge = response.headers.get("www-authenticate", "")
            challenge_ok = challenge.lower().startswith("bearer ")
            if expected_status == 403:
                challenge_ok = (
                    challenge_ok and 'error="insufficient_scope"' in challenge
                )
            else:
                challenge_ok = (
                    challenge_ok
                    and 'error="invalid_token"' in challenge
                    and "resource_metadata=" in challenge
                )
            results.append(
                OAuthCheckResult(
                    check_id,
                    title,
                    response.status_code == expected_status and challenge_ok,
                    f"HTTP {response.status_code}",
                    f"HTTP {expected_status} with Bearer challenge",
                )
            )

        valid_response = await _post_probe(client, resource_url, VALID_TOKEN)
        results.append(
            OAuthCheckResult(
                "MCPRIFT-OAUTH-007",
                "a valid audience-bound token passes the HTTP auth boundary",
                valid_response.status_code not in {401, 403},
                f"HTTP {valid_response.status_code}",
                "a non-401/403 MCP protocol response",
            )
        )
        results.extend(await _check_pkce(client, issuer_url, resource_url))

    results.append(await _check_token_passthrough(resource_url))
    return tuple(results)


async def _post_probe(
    client: httpx2.AsyncClient, resource_url: str, token: str | None
) -> httpx2.Response:
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
    }
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return await client.post(resource_url, headers=headers, content=b"{}")


async def _check_pkce(
    client: httpx2.AsyncClient, issuer_url: str, resource_url: str
) -> tuple[OAuthCheckResult, ...]:
    verifier = "mcprift-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    wrong_target = await client.get(
        f"{issuer_url}/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "wrong-target-state",
            "scope": REQUIRED_SCOPE,
            "resource": f"{issuer_url}/different-resource",
        },
    )
    wrong_target_values = parse_qs(
        urlsplit(wrong_target.headers.get("location", "")).query
    )
    target_rejection = OAuthCheckResult(
        "MCPRIFT-OAUTH-010",
        "authorization rejects a resource indicator for another audience",
        wrong_target.status_code == 302
        and wrong_target_values.get("error") == ["invalid_target"]
        and wrong_target_values.get("state") == ["wrong-target-state"],
        f"authorize HTTP {wrong_target.status_code}",
        "redirect with invalid_target and matching state",
    )
    authorize = await client.get(
        f"{issuer_url}/authorize",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "mcprift-state",
            "scope": REQUIRED_SCOPE,
            "resource": resource_url,
        },
    )
    location = authorize.headers.get("location", "")
    values = parse_qs(urlsplit(location).query)
    code = values.get("code", [""])[0]
    state_ok = values.get("state") == ["mcprift-state"]

    wrong = await client.post(
        f"{issuer_url}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": "wrong-pkce-verifier-0123456789-abcdefghijk",
            "resource": resource_url,
        },
    )
    wrong_value = (
        wrong.json()
        if wrong.headers.get("content-type", "").startswith("application/json")
        else {}
    )
    rejection = OAuthCheckResult(
        "MCPRIFT-PKCE-001",
        "an incorrect PKCE verifier is rejected",
        authorize.status_code == 302
        and bool(code)
        and state_ok
        and wrong.status_code == 400
        and wrong_value.get("error") == "invalid_grant",
        f"authorize HTTP {authorize.status_code}; token HTTP {wrong.status_code}",
        "redirect with matching state, then invalid_grant",
    )

    correct = await client.post(
        f"{issuer_url}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
            "resource": resource_url,
        },
    )
    correct_value = (
        correct.json()
        if correct.headers.get("content-type", "").startswith("application/json")
        else {}
    )
    issued_token = correct_value.get("access_token")
    issued_response = (
        await _post_probe(client, resource_url, issued_token)
        if isinstance(issued_token, str)
        else None
    )
    exchange = OAuthCheckResult(
        "MCPRIFT-PKCE-002",
        "the correct PKCE verifier produces a usable audience-bound token",
        correct.status_code == 200
        and issued_response is not None
        and issued_response.status_code not in {401, 403},
        f"token HTTP {correct.status_code}",
        "HTTP 200 token response accepted by the MCP resource",
    )
    return target_rejection, rejection, exchange


async def _check_token_passthrough(resource_url: str) -> OAuthCheckResult:
    actor = Actor("oauth-alice", ActorKind.AUTHENTICATED, VALID_TOKEN)
    try:
        async with controlled_client(resource_url, actor) as client:
            response = await client.call_tool("downstream_probe", {})
        content = response.structured_content
        passed = bool(
            isinstance(content, dict)
            and content.get("downstream_authorized") is True
            and content.get("client_token_forwarded") is False
        )
        observed = (
            "downstream authorized without forwarding client token"
            if passed
            else "client token forwarded or downstream call failed"
        )
    except Exception:
        passed = False
        observed = "tool call unavailable"
    return OAuthCheckResult(
        "MCPRIFT-OAUTH-008",
        "the MCP access token is not passed to a downstream API",
        passed,
        observed,
        "separate downstream credential used",
    )
