# MCPRift 0.4

<p align="center">
  <img src="assets/mcprift-logo.png" alt="MCPRift logo" width="180">
</p>

> Find the seam before someone crosses it.

MCPRift is an experimental, bounded authorization-contract runner for [Model
Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. It checks
whether a controlled server's authorization boundary behaves as expected when
the client presents different identities or sends unusual protocol requests.

It is designed for authorized testing of local or otherwise controlled targets.
It is not a network scanner, exploit framework, complete OAuth certification
suite, or general-purpose MCP client.

Licensed under [Apache-2.0](LICENSE).

## What it does

MCPRift currently provides:

- **Baseline connection** using the official MCP Python SDK over Streamable HTTP.
- **Capability inspection** for tools, resources, resource templates, and
  prompts without invoking them.
- **Identity comparison** across anonymous, authenticated, invalid, and expired
  credential contexts for one explicitly acknowledged-safe action.
- **Authorization checks** for allowed and denied tool calls and per-user
  resource access.
- **Session/state checks** that change actors inside one reused SDK/HTTP session
  and verify that the first actor's credentials do not authorize the second.
- **OAuth boundary checks** for discovery metadata, exact 401/403 challenges,
  expiry, scopes, token audience, S256 PKCE, resource indicators, and token
  passthrough to a synthetic downstream API.
- **Deterministic protocol mutations** for malformed JSON-RPC and unknown or
  incomplete requests.
- **Sanitized evidence** written as private JSON records, with terminal, JSON,
  and SARIF reporting.
- **Replay** of a recorded built-in case against a controlled target.
- **A disposable local lab** with opt-in vulnerability toggles for reproducible
  tests.

The primary CI workflow is contract-driven:

```sh
mcprift init assessment.json --lab
mcprift validate assessment.json
mcprift run assessment.json --acknowledge-safe-actions
```

`init` writes a runnable, non-secret JSON contract. `validate` performs only
offline structural and safety checks and does not need credential variables.
`run` resolves credentials from the declared environment-variable names,
executes access, visibility, session, and protocol cases, and writes sanitized
terminal, JSON, or SARIF evidence. It returns `0` for passing verdicts, `1`
for security-policy failures, and `2` for invalid configuration or execution
errors.

## Safety boundary

Safety constraints are part of the implementation, not just usage advice:

- Targets must be absolute, credential-free `http` or `https` URLs on a
  loopback host such as `127.0.0.1` or `localhost`.
- Redirects are disabled for SDK-managed requests and raw mutations.
- Tool calls require `known_safe: true`, a non-empty safety justification, and
  the run-time `--acknowledge-safe-actions` flag. The lab contract invokes only
  the side-effect-free `safe_echo` tool.
- Bearer tokens are read from environment variables, never URL or CLI token
  arguments.
- Evidence stores a target fingerprint rather than the target URL.
- Evidence excludes token values, server response bodies, and action argument
  values. Raw mutation evidence retains only status, content type, response
  size, and a response hash.
- Response and evidence sizes are bounded.

Use MCPRift only against systems and data you are authorized to assess.

## Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/)
- An MCP server reachable through controlled Streamable HTTP

The project currently depends on `mcp==2.0.0` and `httpx2`.

## Quick start: disposable lab and CI contract

The fastest way to try MCPRift is the one-command demo:

```sh
uv sync
uv run mcprift demo
```

It starts the disposable lab on a temporary loopback port, runs the 22-case
contract, and removes the lab and temporary contract afterward. To retain
sanitized evidence, add `--evidence-dir mcprift-evidence`.

To see the individual steps, start the local lab yourself. The lab binds to
`127.0.0.1:8080` by default and serves synthetic, side-effect-free data.

In terminal one:

```sh
uv sync
uv run python -m mcprift.lab
```

In terminal two:

```sh
export MCPRIFT_AUTH_TOKEN=mcprift-lab-alice
export MCPRIFT_BOB_TOKEN=mcprift-lab-bob
export MCPRIFT_INVALID_TOKEN=mcprift-lab-invalid
export MCPRIFT_EXPIRED_TOKEN=mcprift-lab-expired

uv run mcprift init assessment.json --lab
uv run mcprift validate assessment.json
uv run mcprift run assessment.json --acknowledge-safe-actions
```

The secure lab should produce 22 passing contract cases. The command writes a
private evidence file under `mcprift-evidence/` and returns:

- `0` when all selected checks pass;
- `1` when a security check fails;
- `2` when execution or configuration fails.

## CI

The checked-in [authorization-contract workflow](.github/workflows/authorization-contract.yml)
is the reference CI integration. It runs the unit suite and Ruff, starts the
disposable lab, validates and runs the secure contract, uploads its private
evidence, and confirms that a seeded cross-tenant regression returns exit code
`1`. The seeded failure is uploaded as SARIF so a pull request receives an
actionable annotation.

Run the same checks locally:

```sh
uv sync
uv run python -m unittest discover -s tests -v
uv run ruff check .
```

The workflow intentionally tests only the bundled loopback lab. A remote
staging target and a real identity provider are later, explicitly controlled
integration phases; a passing local workflow is not evidence about production.

For CI, keep credentials in the job's secret environment and make the
evidence directory an explicit artifact path:

```sh
uv run mcprift validate assessment.json
uv run mcprift run assessment.json \
  --acknowledge-safe-actions --format sarif --evidence-dir artifacts/mcprift
```

Contracts contain `access`, `visibility`, and `protocol` cases. Access actions
are `tool-call`, `resource-read`, or `prompt-get`; visibility cases assert
whether one tool, resource, resource template, or prompt is visible to one
actor; protocol cases select one deterministic mutation. Credentialed actors
contain only a `token_env` name, never a token value.

For a step-by-step guide to writing a contract for your own MCP server, see
[Writing an MCPRift authorization contract](docs/writing-contracts.md).

## OAuth and PKCE lab

The separate OAuth lab is a protected MCP resource and a minimal local
authorization server. Start it in terminal one:

```sh
uv run python -m mcprift.oauth_lab
```

Run its twelve checks in terminal two:

```sh
uv run mcprift oauth-test http://127.0.0.1:8090/mcp
```

This verifies protected-resource and authorization-server discovery, Bearer
challenges, expiry, insufficient scope, audience rejection, resource
indicators, S256 PKCE failure and success, and use of a separate credential for
the synthetic downstream API.

## Reproduce controlled failures

The lab can intentionally enable one or more known vulnerabilities. This is
useful for testing MCPRift's detection and reporting behavior:

```sh
uv run python -m mcprift.lab --vulnerable anonymous-tool
uv run python -m mcprift.lab --vulnerable expired-credential
uv run python -m mcprift.lab --vulnerable cross-user-resource
uv run python -m mcprift.lab --vulnerable session-identity-crossover
uv run python -m mcprift.lab --vulnerable prompt-access
uv run python -m mcprift.lab --vulnerable capability-visibility-leak
uv run python -m mcprift.oauth_lab --vulnerable wrong-audience
uv run python -m mcprift.oauth_lab --vulnerable token-passthrough
```

Available toggles:

| Toggle | Simulated failure |
| --- | --- |
| `anonymous-tool` | Anonymous callers can invoke `safe_echo`. |
| `expired-credential` | The expired lab credential is accepted. |
| `cross-user-resource` | A user can read another user's synthetic resource. |
| `session-identity-crossover` | A reused session keeps Alice's established identity after its request credentials change to Bob. |
| `prompt-access` | Anonymous callers can retrieve the protected review prompt. |
| `capability-visibility-leak` | Anonymous capability listings expose protected templates and prompts. |

OAuth-lab toggles:

| Toggle | Simulated failure |
| --- | --- |
| `wrong-audience` | The MCP resource accepts a token intended for another resource. |
| `token-passthrough` | The MCP access token is forwarded to and accepted by a downstream API. |

The toggles may be repeated to combine failures. They affect only the
disposable local lab.

## CLI

Show the available commands:

```sh
uv run mcprift help
uv run mcprift version
```

Connect and inspect a controlled server:

```sh
uv run mcprift connect http://127.0.0.1:8080/mcp
uv run mcprift inspect http://127.0.0.1:8080/mcp
uv run mcprift inspect http://127.0.0.1:8080/mcp --json
```

`inspect` lists capabilities but does not invoke tools, read resources, or run
prompts. To inspect what a credentialed test identity can see, provide a name
and token environment variable; the token itself is never accepted on the
command line or written to the output:

```sh
export TEST_ALICE_TOKEN='...'
uv run mcprift inspect http://127.0.0.1:8080/mcp \
  --actor alice --token-env TEST_ALICE_TOKEN --json > alice-inventory.json
```

Compare one explicitly safe tool across identity contexts. The three token
variables below are required; their values never appear in output or evidence:

```sh
uv run mcprift compare http://127.0.0.1:8080/mcp \
  --safe-tool safe_echo \
  --arguments '{"message":"probe"}'
```

Run the complete bounded authorization suite, or select individual cases:

```sh
uv run mcprift test http://127.0.0.1:8080/mcp
uv run mcprift test http://127.0.0.1:8080/mcp \
  --case MCPRIFT-AUTH-001 \
  --case MCPRIFT-BOUNDARY-002
```

Run only the bounded session/state invariant. MCPRift opens one controlled
session as Alice, reads Alice's synthetic resource, changes that same session's
request credentials to Bob, and verifies that Bob is denied. This command pins
the SDK to its handshake-era `legacy` mode so the server supplies an MCP
session ID:

```sh
uv run mcprift session-test http://127.0.0.1:8080/mcp
```

Run the bounded OAuth suite against the disposable OAuth lab:

```sh
uv run mcprift oauth-test http://127.0.0.1:8090/mcp
uv run mcprift oauth-test http://127.0.0.1:8090/mcp --format sarif
```

Send one deterministic raw JSON-RPC mutation. Valid kinds are
`invalid-json`, `missing-jsonrpc`, `unknown-method`, and `empty-batch`:

```sh
uv run mcprift mutate http://127.0.0.1:8080/mcp unknown-method
```

Render an existing evidence record in terminal, JSON, or SARIF format, or
replay one canonical case:

```sh
uv run mcprift report mcprift-evidence/mcprift-<run-id>.json --format sarif
uv run mcprift replay http://127.0.0.1:8080/mcp \
  mcprift-evidence/mcprift-<run-id>.json \
  --case MCPRIFT-AUTH-001
```

Commands that execute the built-in suite, the session test, or replay a case
require all four lab credential variables: `MCPRIFT_AUTH_TOKEN`,
`MCPRIFT_BOB_TOKEN`, `MCPRIFT_INVALID_TOKEN`, and
`MCPRIFT_EXPIRED_TOKEN`.

## Built-in cases

The default registry contains nine stable cases:

- `MCPRIFT-AUTH-001` — anonymous tool access is denied.
- `MCPRIFT-AUTH-002` — an authenticated caller can use the safe tool.
- `MCPRIFT-AUTH-003` — invalid credentials are denied.
- `MCPRIFT-AUTH-004` — expired credentials are denied.
- `MCPRIFT-BOUNDARY-001` — Alice can read Alice's resource.
- `MCPRIFT-BOUNDARY-002` — Alice cannot read Bob's resource.
- `MCPRIFT-BOUNDARY-003` — Bob can read Bob's resource.
- `MCPRIFT-BOUNDARY-004` — Bob cannot read Alice's resource.
- `MCPRIFT-SESSION-001` — Alice's credentials cannot authorize Bob's request
  after the controlled SDK/HTTP session is reused and rebound to Bob.

These cases exercise observable authorization outcomes. They do not establish
full OAuth behavior or prove that an arbitrary production deployment is secure.

## Development

Install the locked development environment and run formatting, linting, and
tests:

```sh
uv sync
uv run ruff format --check .
uv run ruff check .
uv run python -m unittest discover -s tests -v
```

The Python implementation lives in `src/mcprift/`. The previous Go
implementation is retained in `legacy-go/` and is not part of the Python build
or test commands.

## Current scope and limitations

MCPRift 0.4.0 does not claim complete OAuth conformance, stdio target support,
broad network scanning, exploit automation, or arbitrary third-party plugins.
The OAuth suite remains explicitly lab-only and uses a disposable HTTP-only
local provider; production TLS,
external identity providers, dynamic client registration, refresh-token
rotation, revocation, and browser interaction are outside the tested boundary.
Session testing remains limited to one deterministic actor change in one
reused, handshake-era Streamable HTTP session. Modern sessionless endpoints,
cookies, concurrent sessions, server restarts, and replayed protocol messages
remain outside that invariant.

The project is experimental. Treat its results as bounded evidence for the
tested target and configuration, not as a certification or a guarantee of
security.

## License

No license file is currently included in the repository.
