# Phase 1 manual demo

This disposable fixture exposes no tools, resources, or prompts. It listens only on the loopback interface.

In one terminal, start the fixture:

```sh
uv sync
uv run python -m mcprift.fixture
```

In a second terminal, establish the Phase 1 baseline connection:

```sh
uv run mcprift connect http://127.0.0.1:8080/mcp
```

Expected output:

```text
connected to phase-1-fixture 0.0.1 using streamable-http (protocol <negotiated-version>)
```

Stop the fixture with `Ctrl-C`. The `connect` command only establishes the SDK-managed MCP session; it does not list or invoke any server capability.
