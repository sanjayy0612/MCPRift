# Writing an MCPRift authorization contract

An MCPRift contract is a versioned test plan for the authorization rules your
team owns. It is not a server configuration file, and MCPRift cannot infer the
rules correctly from the server alone.

Use the contract to state properties such as:

| Actor | Operation | Expected result |
| --- | --- | --- |
| Anonymous caller | Call `create_ticket` | Denied |
| Alice | Read `invoice://alice/2026-001` | Allowed |
| Alice | Read `invoice://bob/2026-001` | Denied |
| Support agent | See `lookup_customer` | Visible |

The server supplies the available tools, resources, prompts, and input
schemas. Your team supplies the intended business policy. Keep the contract
next to the MCP server and change both in the same pull request when an
intentional authorization rule changes.

## Authoring workflow

1. Start with a controlled local or CI-started server. MCPRift currently
   accepts loopback HTTP(S) targets only.
2. Inspect the server without invoking a capability:

   ```sh
   uv run mcprift inspect http://127.0.0.1:8080/mcp --json > inventory.json
   ```

   To inspect an authenticated actor's capability view, pass an actor name and
   the environment-variable name containing its bearer token:

   ```sh
   export TEST_ALICE_TOKEN='...'
   uv run mcprift inspect http://127.0.0.1:8080/mcp \
     --actor alice --token-env TEST_ALICE_TOKEN --json > alice-inventory.json
   ```

   Inspect Alice and Bob separately before writing visibility cases. The server
   owner must still supply concrete synthetic resource URIs for access cases,
   because resource listings do not necessarily reveal every private resource.
   Never put a token in an MCPRift URL, a contract, a shell argument, or an
   inventory file.

3. Write the policy table above with the server owner or security reviewer.
   Start with one allowed and one denied case at the tenant boundary that
   matters most.
4. Create `assessment.json` using the example below.
5. Validate the file without resolving credentials or sending network traffic:

   ```sh
   uv run mcprift validate assessment.json
   ```

6. Run it only against the controlled target and only after reviewing every
   declared tool call:

   ```sh
   uv run mcprift run assessment.json --acknowledge-safe-actions
   ```

## Smallest useful contract

Replace the target, identity names, token-variable names, and resource URIs
with values from your controlled test environment. This example deliberately
contains no tool calls, so it does not require the safe-action acknowledgement.

```json
{
  "schema_version": 2,
  "target": "http://127.0.0.1:8080/mcp",
  "actors": {
    "anonymous": {
      "kind": "anonymous"
    },
    "alice": {
      "kind": "authenticated",
      "token_env": "TEST_ALICE_TOKEN"
    },
    "bob": {
      "kind": "authenticated",
      "token_env": "TEST_BOB_TOKEN"
    }
  },
  "access": [
    {
      "id": "TENANT-001",
      "title": "Alice can read her invoice",
      "actor": "alice",
      "action": {
        "kind": "resource-read",
        "target": "invoice://alice/2026-001"
      },
      "expected": "allowed"
    },
    {
      "id": "TENANT-002",
      "title": "Alice cannot read Bob's invoice",
      "actor": "alice",
      "action": {
        "kind": "resource-read",
        "target": "invoice://bob/2026-001"
      },
      "expected": "denied"
    }
  ],
  "visibility": [],
  "protocol": []
}
```

Set the token values only in the environment used for the run:

```sh
export TEST_ALICE_TOKEN='...'
export TEST_BOB_TOKEN='...'
uv run mcprift validate assessment.json
uv run mcprift run assessment.json
```

## Contract fields

### Actors

An actor is a test identity. An anonymous actor has no credentials. A
credentialed actor contains only a `token_env` name; the token value remains in
the environment. The actor `kind` is descriptive evidence metadata, not a
claim that the server has validated an OAuth flow.

### Access cases

An access case is one identity performing one action with an expected result:

* `tool-call` invokes a named tool. It requires `known_safe: true`, a non-empty
  `safety_justification`, and `--acknowledge-safe-actions` at run time. Use
  only a side-effect-free or otherwise reviewed test action.
* `resource-read` reads one concrete resource URI. A resource template is not
  itself a readable resource: choose a synthetic, concrete URI for the test.
* `prompt-get` fetches a named prompt, optionally with a JSON arguments object.

Use `allowed` when the action must succeed and `denied` when the action must be
rejected. An unavailable server is an execution error, not a successful denial.

### Visibility cases

Visibility cases check whether a capability appears in an actor's capability
listing. They can assert `visible` or `hidden` for a tool, resource,
resource-template, or prompt. Visibility is useful because revealing a private
tenant template or prompt name can itself be a boundary failure.

### Protocol cases

Protocol cases select a bounded built-in malformed-request mutation. They are
not a general fuzzer. Use them to check that the controlled server rejects the
listed malformed request categories.

## Review checklist

Before committing a contract, answer all of these:

- Is the target a disposable local/CI target with synthetic data?
- Does each credentialed actor have a distinct, least-privileged test identity?
- Does every allowed case have a corresponding cross-user or lower-privilege
  denied case where that distinction matters?
- Are all resource URIs synthetic and stable?
- Is every tool action actually safe, idempotent, and justified in the file?
- Does the contract contain environment-variable names only, never secret
  values?
- Does `mcprift validate assessment.json` pass before CI runs it?

## Drafting with an AI assistant

You can use any code assistant to draft most of an `assessment.json` today.
MCPRift does not need to call an LLM itself: the assistant writes a proposed
file, then MCPRift validates and runs the reviewed file deterministically.

Give the assistant only:

1. a sanitized `mcprift inspect --json` inventory;
2. a plain-language policy table written by the server owner; and
3. concrete, synthetic resource URIs for the cases to test.

For example, ask it to generate schema version 2 JSON with these explicit
rules: Alice may read `pilot://users/alice`, Alice must not read
`pilot://users/bob`, Bob may read `pilot://users/bob`, and Bob must not read
`pilot://users/alice`. Ask it to use the documented schema and output only a
proposed JSON file. Save the result as `assessment.draft.json`, review it, then
rename or copy it to `assessment.json` only after validation.

The assistant can save typing, but it cannot discover the intended business
policy from the server. Do not give it bearer tokens. Do not let it silently
mark tools safe, invent tenant identifiers, choose allow/deny outcomes, or
overwrite the reviewed contract. Always run:

```sh
uv run mcprift validate assessment.json
uv run mcprift run assessment.json
```
