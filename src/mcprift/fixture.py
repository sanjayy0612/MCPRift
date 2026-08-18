"""A disposable, tool-free MCP server for the Phase 1 manual demo."""

from __future__ import annotations

import argparse

from mcp.server import MCPServer


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the disposable Phase 1 fixture.")
    parser.add_argument("--port", type=int, default=8080)
    arguments = parser.parse_args()
    fixture = MCPServer("phase-1-fixture", version="0.0.1")
    fixture.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=arguments.port,
        json_response=True,
        stateless_http=True,
    )


if __name__ == "__main__":
    main()
