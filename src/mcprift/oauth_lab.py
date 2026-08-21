"""Disposable OAuth-protected MCP lab for authorization boundary tests."""

from __future__ import annotations

import argparse
import secrets
import time
from dataclasses import dataclass, field

import httpx2
from mcp.server import MCPServer
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver import Context
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import JSONResponse

CLIENT_ID = "mcprift-oauth-lab-client"
REDIRECT_URI = "http://127.0.0.1/callback"
VALID_TOKEN = "mcprift-oauth-valid"
WRONG_AUDIENCE_TOKEN = "mcprift-oauth-wrong-audience"
EXPIRED_TOKEN = "mcprift-oauth-expired"
INSUFFICIENT_SCOPE_TOKEN = "mcprift-oauth-insufficient-scope"
DOWNSTREAM_TOKEN = "mcprift-downstream-service-token"
REQUIRED_SCOPE = "mcp:access"

WRONG_AUDIENCE = "wrong-audience"
TOKEN_PASSTHROUGH = "token-passthrough"
VULNERABILITIES = frozenset({WRONG_AUDIENCE, TOKEN_PASSTHROUGH})


@dataclass
class LabOAuthProvider:
    """Minimal in-memory provider built only for the disposable local lab."""

    issuer_url: str
    resource_url: str
    vulnerabilities: frozenset[str] = frozenset()
    authorization_codes: dict[str, AuthorizationCode] = field(default_factory=dict)
    access_tokens: dict[str, AccessToken] = field(default_factory=dict)

    def __post_init__(self) -> None:
        now = int(time.time())
        common = {
            "client_id": CLIENT_ID,
            "scopes": [REQUIRED_SCOPE],
            "subject": "alice",
            "claims": {"iss": self.issuer_url},
        }
        self.access_tokens.update(
            {
                VALID_TOKEN: AccessToken(
                    token=VALID_TOKEN,
                    resource=self.resource_url,
                    expires_at=now + 3600,
                    **common,
                ),
                WRONG_AUDIENCE_TOKEN: AccessToken(
                    token=WRONG_AUDIENCE_TOKEN,
                    resource=f"{self.issuer_url}/different-resource",
                    expires_at=now + 3600,
                    **common,
                ),
                EXPIRED_TOKEN: AccessToken(
                    token=EXPIRED_TOKEN,
                    resource=self.resource_url,
                    expires_at=now - 60,
                    **common,
                ),
                INSUFFICIENT_SCOPE_TOKEN: AccessToken(
                    token=INSUFFICIENT_SCOPE_TOKEN,
                    client_id=CLIENT_ID,
                    scopes=["mcp:inspect"],
                    resource=self.resource_url,
                    subject="alice",
                    expires_at=now + 3600,
                    claims={"iss": self.issuer_url},
                ),
            }
        )

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        if client_id != CLIENT_ID:
            return None
        return OAuthClientInformationFull(
            client_id=CLIENT_ID,
            client_name="MCPRift OAuth lab client",
            redirect_uris=[REDIRECT_URI],
            scope=REQUIRED_SCOPE,
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",
            application_type="native",
        )

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        raise NotImplementedError("dynamic registration is disabled")

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        if params.resource != self.resource_url:
            raise AuthorizeError(
                "invalid_target", "the authorization target is not this MCP server"
            )
        code = secrets.token_urlsafe(24)
        self.authorization_codes[code] = AuthorizationCode(
            code=code,
            scopes=params.scopes or [REQUIRED_SCOPE],
            expires_at=time.time() + 60,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject="alice",
        )
        return construct_redirect_uri(
            str(params.redirect_uri), code=code, state=params.state
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self.authorization_codes.get(authorization_code)
        return code if code and code.client_id == client.client_id else None

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        stored = self.authorization_codes.pop(authorization_code.code, None)
        if stored is None:
            raise TokenError("invalid_grant", "authorization code was already used")
        token_value = f"mcprift-oauth-issued-{secrets.token_urlsafe(18)}"
        self.access_tokens[token_value] = AccessToken(
            token=token_value,
            client_id=client.client_id,
            scopes=stored.scopes,
            expires_at=int(time.time()) + 300,
            resource=stored.resource,
            subject=stored.subject,
            claims={"iss": self.issuer_url},
        )
        return OAuthToken(
            access_token=token_value,
            expires_in=300,
            scope=" ".join(stored.scopes),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise TokenError("unsupported_grant_type", "refresh tokens are disabled")

    async def load_access_token(self, token: str) -> AccessToken | None:
        candidate = self.access_tokens.get(token)
        if candidate is None:
            return None
        if (
            candidate.resource != self.resource_url
            and WRONG_AUDIENCE not in self.vulnerabilities
        ):
            return None
        return candidate

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.access_tokens.pop(token.token, None)


def create_oauth_lab(
    port: int, vulnerabilities: frozenset[str] = frozenset()
) -> MCPServer:
    unknown = vulnerabilities - VULNERABILITIES
    if unknown:
        raise ValueError("unknown OAuth lab vulnerability")

    issuer_url = f"http://127.0.0.1:{port}"
    resource_url = f"{issuer_url}/mcp"
    provider = LabOAuthProvider(issuer_url, resource_url, vulnerabilities)
    auth = AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=resource_url,
        required_scopes=[REQUIRED_SCOPE],
        client_registration_options=ClientRegistrationOptions(enabled=False),
    )
    lab = MCPServer(
        "mcprift-oauth-lab",
        version="0.3.0",
        auth_server_provider=provider,
        auth=auth,
    )

    @lab.tool(description="Call a synthetic downstream API without side effects.")
    async def downstream_probe(ctx: Context) -> dict[str, bool]:
        inbound = (ctx.headers or {}).get("authorization", "")
        outbound = (
            inbound
            if TOKEN_PASSTHROUGH in vulnerabilities
            else f"Bearer {DOWNSTREAM_TOKEN}"
        )
        async with httpx2.AsyncClient(follow_redirects=False) as client:
            response = await client.get(
                f"{issuer_url}/downstream", headers={"Authorization": outbound}
            )
        payload = response.json()
        return {
            "downstream_authorized": response.status_code == 200,
            "client_token_forwarded": bool(payload["client_token_forwarded"]),
        }

    @lab.custom_route("/downstream", methods=["GET"])
    async def downstream(request: Request) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        client_token_forwarded = (
            authorization.removeprefix("Bearer ") in provider.access_tokens
        )
        accepted = authorization == f"Bearer {DOWNSTREAM_TOKEN}"
        if TOKEN_PASSTHROUGH in vulnerabilities and client_token_forwarded:
            accepted = True
        return JSONResponse(
            {
                "authorized": accepted,
                "client_token_forwarded": client_token_forwarded,
            },
            status_code=200 if accepted else 401,
        )

    return lab


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the disposable OAuth MCP lab.")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument(
        "--vulnerable",
        action="append",
        default=[],
        choices=sorted(VULNERABILITIES),
    )
    arguments = parser.parse_args()
    lab = create_oauth_lab(arguments.port, frozenset(arguments.vulnerable))
    lab.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=arguments.port,
        json_response=True,
        stateless_http=True,
    )


if __name__ == "__main__":
    main()
