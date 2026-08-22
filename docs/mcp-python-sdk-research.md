# MCP Python SDK research (2026-08-18)

## Decision

Use the official `mcp` package at the exact stable release `mcp==2.0.0`.
The package requires Python 3.10 or newer, so the project requirement of Python
3.12+ is compatible.  An exact pin makes the Phase 0/1 protocol behavior and
the fixture reproducible; update it only as an intentional, tested dependency
change.

Evidence:

- [PyPI package metadata](https://pypi.org/project/mcp/) lists version 2.0.0
  and Python >=3.10.
- The [official SDK repository](https://github.com/modelcontextprotocol/python-sdk)
  describes v2 as the current stable line and says a plain `pip install mcp`
  selects 2.x.

## Recommended client lifecycle

Use the v2 high-level client, not hand-written JSON-RPC and not the lower-level
transport/session API:

```python
from mcp import Client


async def connect(url: str) -> tuple[str | None, str | None, str | None]:
    async with Client(url) as client:
        server_info = client.server_info
        return (
            client.protocol_version,
            server_info.name if server_info else None,
            server_info.version if server_info else None,
        )
```

For a URL, `Client` selects Streamable HTTP. Entering the async context connects
and negotiates; leaving it disconnects. The SDK probes the modern discovery
flow and falls back to the older `initialize` handshake, so this remains a
valid lifecycle with both protocol eras. Phase 1 should report only the
negotiated protocol version and optional server name/version. Do not print
`server_capabilities`, enumerate tools/resources/prompts, or make any further
MCP request.

Sources: [client lifecycle](https://py.sdk.modelcontextprotocol.io/client/),
[client transport behavior](https://py.sdk.modelcontextprotocol.io/client/transports/),
and the [SDK client source](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/client.py).

### Lower-level API (not selected)

The supported lower-level v2 sequence is:

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

async with streamable_http_client(url) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
```

It is unnecessary for Phase 1. In v2 `streamable_http_client` yields exactly
two streams; the former third session-ID value was removed. Its current
signature accepts `url`, optional `httpx2.AsyncClient`, and
`terminate_on_close`; headers and timeouts belong on an explicitly owned HTTP
client, not on this function. The high-level `Client` avoids coupling this
small implementation to that transport detail.

Source: [Streamable HTTP transport source](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/client/streamable_http.py).

## Disposable fixture

Create a fixture with no registered tools, resources, or prompts:

```python
from mcp.server.mcpserver import MCPServer

fixture = MCPServer("phase-1-fixture", version="0.0.1")

if __name__ == "__main__":
    fixture.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8080,
        json_response=True,
        stateless_http=True,
    )
```

`MCPServer.run("streamable-http", ...)` is synchronous and serves the
Streamable HTTP endpoint at `/mcp`. Keeping the fixture on `127.0.0.1` makes it
disposable and matches Phase 1's loopback-only target policy. A subprocess test
can select a free loopback port and start this fixture; a CLI test then connects
only to `http://127.0.0.1:<port>/mcp` and asserts the three safe metadata
fields. Do not use the fixture to exercise tools or capabilities.

For an ASGI-hosted fixture, `fixture.streamable_http_app(json_response=True)`
returns an app with `/mcp` and its own lifespan. If it is mounted inside another
ASGI app, the outer lifespan must enter `fixture.session_manager.run()`;
therefore the direct `run()` fixture is smaller and less error-prone here.

Sources: [running a Streamable HTTP server](https://py.sdk.modelcontextprotocol.io/run/),
[ASGI fixture/lifespan behavior](https://py.sdk.modelcontextprotocol.io/run/asgi/),
and the [MCPServer source](https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/mcpserver/server.py).

## Safety boundary outside the SDK

The SDK performs MCP protocol lifecycle, not MCPRift's target safety policy.
Validate before constructing `Client`: require an absolute `http` or `https`
URL, reject user-info, and accept only `localhost` or an IP address whose
`ipaddress.ip_address(host).is_loopback` is true. Return generic failures and
never include the submitted URL, headers, or server response body in stdout,
stderr, or exceptions.
