# MCPRift

MCPRift is an experimental framework for checking whether an MCP (Model
Context Protocol) server's security boundary holds when a client behaves
adversarially. It is for authorized testing against controlled targets.

Version 0.2.0 implements the planned framework slices from connection through
capability discovery, identity comparison, authorization invariants, raw
protocol mutation, sanitized evidence, replay, reporting, a bounded case
registry, and a disposable vulnerable lab. It is not a broad scanner or a
stable release; see [MATURITY.md](MATURITY.md) for the release assessment.

## Safety boundary

- Only credential-free `http` or `https` URLs on a loopback host are accepted.
- Redirects are disabled, so a loopback server cannot redirect traffic or
  credentials to another host.
- Tool calls require an explicit known-safe assertion. The built-in suite calls
  only the lab's side-effect-free `safe_echo` tool.
- Bearer tokens are read from environment variables, never URL or CLI token
  arguments.
- Evidence excludes target URLs, token values, server response bodies, and
  action argument values.
- Raw mutations are deterministic, response-size bounded, and isolated from
  normal SDK-managed requests.

Use MCPRift only on systems you are authorized to assess.

## Commands

```sh
uv run mcprift version
uv run mcprift help
uv run mcprift connect http://127.0.0.1:8080/mcp
uv run mcprift inspect http://127.0.0.1:8080/mcp
uv run mcprift compare http://127.0.0.1:8080/mcp \
  --safe-tool safe_echo --arguments '{"message":"probe"}'
uv run mcprift test http://127.0.0.1:8080/mcp
uv run mcprift mutate http://127.0.0.1:8080/mcp unknown-method
uv run mcprift report mcprift-evidence/RECORD.json --format sarif
uv run mcprift replay http://127.0.0.1:8080/mcp \
  mcprift-evidence/RECORD.json --case MCPRIFT-AUTH-001
```

`inspect` lists tools, resources, resource templates, and prompts but does not
invoke them. Listings are capped at 100 pages and 1,000 capabilities.

`test` runs eight controlled checks: anonymous, valid, invalid, and expired
tool access plus both directions of an Alice/Bob resource boundary. It writes
a private JSON evidence record and returns 0 for a clean run, 1 for a security
failure, or 2 for an execution error. Terminal, JSON, and SARIF output are
supported.

## Disposable lab

Start the secure lab:

```sh
uv run python -m mcprift.lab
```

In another terminal, set the lab-only credentials and run the suite:

```sh
export MCPRIFT_AUTH_TOKEN=mcprift-lab-alice
export MCPRIFT_BOB_TOKEN=mcprift-lab-bob
export MCPRIFT_INVALID_TOKEN=mcprift-lab-invalid
export MCPRIFT_EXPIRED_TOKEN=mcprift-lab-expired
uv run mcprift test http://127.0.0.1:8080/mcp
```

The lab can opt into reproducible failures, one or more at a time:

```sh
uv run python -m mcprift.lab --vulnerable anonymous-tool
uv run python -m mcprift.lab --vulnerable expired-credential
uv run python -m mcprift.lab --vulnerable cross-user-resource
```

The older tool-free Phase 1 fixture remains available with
`uv run python -m mcprift.fixture`.

## What is intentionally not claimed

MCPRift 0.2.0 does not implement full OAuth conformance, audience validation,
authorization-server discovery, PKCE, token-passthrough detection, stdio
targets, stateful session binding, broad network scanning, exploit automation,
or arbitrary third-party plugins. The lab uses fixed synthetic bearer values
to exercise authorization outcomes; it is not an OAuth authorization server.

The current primary-source coverage and gaps are recorded in
[RESEARCH-MAPPING.md](RESEARCH-MAPPING.md).

## Development

This is a Python 3.12+ project using the official MCP Python SDK 2.0.0.

```sh
uv sync
uv run ruff format --check .
uv run ruff check .
uv run python -m unittest discover -s tests -v
```

The previous Go implementation is retained unchanged in `legacy-go/`; it is
not part of the Python build or test commands.
