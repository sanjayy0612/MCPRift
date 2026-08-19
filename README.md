# MCPRift

MCPRift is an authorized security-testing framework for checking whether an MCP (Model Context Protocol) server's security boundary holds when a client behaves adversarially.

It is not an MCP inventory scanner. Its central question is:

> Does the security boundary actually hold when an MCP client behaves adversarially?

## Safety

Use MCPRift only on systems you are authorized to test.

Early development focuses on controlled, disposable test servers and safe, reproducible checks. MCPRift will not automatically invoke arbitrary tools, perform destructive actions, or attempt exploitation.

## Status

MCPRift implements **Phase 0 and Phase 1** in Python. It can make one valid
baseline interaction with a controlled MCP Streamable HTTP server.

The current work is deliberately limited to establishing a safe, reproducible connection before capability inspection or security testing is added.

## Roadmap

The project will grow one reviewed phase at a time:

1. Connect to a controlled MCP server using a valid baseline interaction.
2. Inspect available capabilities such as tools, resources, and prompts.
3. Run the same safe operations under different identity contexts.
4. Test explicit security rules, starting with anonymous tool access.
5. Add reproducible evidence, replay, reporting, and later extensibility.

See `PLAN.md` for the local working plan and phase exit conditions.

## Available commands

The following commands are available:

```sh
uv run mcprift version
uv run mcprift help
uv run mcprift connect http://127.0.0.1:8080/mcp
```

`connect` uses the official MCP Python SDK to establish a baseline MCP session.
The SDK owns the valid lifecycle exchange for the negotiated protocol version.
It supports only credential-free loopback Streamable HTTP targets during Phase 1
and reports the negotiated protocol version and server identity. Diagnostics
never print the target URL, request headers, or response body.

For a reproducible local demonstration, run the [Phase 1 manual demo](docs/phase-1-manual-demo.md).

## Development

This is a Python 3.12+ project. Install the project environment and run the
checks with:

```sh
uv sync
uv run ruff format --check .
uv run ruff check .
uv run python -m unittest discover -s tests -v
```

For the manual demo, start the disposable fixture in one terminal and connect
from another:

```sh
uv run python -m mcprift.fixture
uv run mcprift connect http://127.0.0.1:8080/mcp
```

The previous Go implementation is retained unchanged in `legacy-go/`; it is
not part of the Python build or test commands.

## First transport decision

Phase 1 will support only a controlled MCP Streamable HTTP URL. Stdio support will come later as a separate, explicit transport because it launches a local server process and has different safety and lifecycle requirements.

## Development approach

- Start small; do not implement a later phase early.
- Prefer standard-library code and focused changes. `argparse` provides the
  small command-line parser needed here; a CLI framework would add no value.
- Separate normal MCP requests from deliberately malformed protocol requests.
- Store sanitized evidence for any future failed security test.
- Record the MCP protocol version and transport used by each interaction.
