# MCPRift

MCPRift is an authorized security-testing framework for checking whether an MCP (Model Context Protocol) server's security boundary holds when a client behaves adversarially.

It is not an MCP inventory scanner. Its central question is:

> Does the security boundary actually hold when an MCP client behaves adversarially?

## Safety

Use MCPRift only on systems you are authorized to test.

Early development focuses on controlled, disposable test servers and safe, reproducible checks. MCPRift will not automatically invoke arbitrary tools, perform destructive actions, or attempt exploitation.

## Status

MCPRift is in **Phase 0: repository foundation**. There is no working CLI or MCP connectivity yet.

The current work is deliberately limited to creating a small Go project that can be understood and verified before protocol code is added.

## Roadmap

The project will grow one reviewed phase at a time:

1. Connect to a controlled MCP server using a valid baseline interaction.
2. Inspect available capabilities such as tools, resources, and prompts.
3. Run the same safe operations under different identity contexts.
4. Test explicit security rules, starting with anonymous tool access.
5. Add reproducible evidence, replay, reporting, and later extensibility.

See `PLAN.md` for the local working plan and phase exit conditions.

## Planned Phase 0 commands

Once Phase 0 is implemented, these commands will be available:

```sh
go run ./cmd/mcprift version
go run ./cmd/mcprift help
```

Phase 0 will be accepted only after the project builds, unit tests pass, code is formatted with `gofmt`, and `go vet ./...` succeeds.

## First transport decision

Phase 1 will support only a controlled MCP Streamable HTTP URL. Stdio support will come later as a separate, explicit transport because it launches a local server process and has different safety and lifecycle requirements.

## Development approach

- Start small; do not implement a later phase early.
- Prefer standard library code and focused changes.
- Separate normal MCP requests from deliberately malformed protocol requests.
- Store sanitized evidence for any future failed security test.
- Record the MCP protocol version and transport used by each interaction.
