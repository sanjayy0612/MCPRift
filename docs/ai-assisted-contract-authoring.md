# AI-assisted MCPRift contract authoring

Use this guide when you want ChatGPT, Claude, Codex, Cursor, or another coding
assistant to help author an MCPRift authorization contract. The assistant can
organize information and write a draft; the server owner remains responsible
for every authorization rule.

MCPRift does not send data to an LLM and does not require an LLM API key. You
use your preferred assistant outside MCPRift, review its draft, then use the
normal deterministic commands to validate and run it.

## Safe workflow

```text
sanitized server inventory + developer answers
                    ↓
             AI-written draft
                    ↓
           human policy review
                    ↓
      mcprift validate assessment.json
                    ↓
         mcprift run assessment.json
```

Never give an assistant bearer tokens, real customer data, production URLs, or
unreviewed tool permission. Use a controlled loopback target and synthetic
test identities and resource URIs.

## Reusable prompt

Copy the following prompt into your preferred coding assistant. Replace the
bracketed sections with your own information. Give it a sanitized inspection
file only; it does not need credentials.

```text
You are helping me author an MCPRift authorization contract for a controlled
MCP server. Your job is to interview me about the intended authorization
policy, then create a proposed `assessment.draft.json`.

You are NOT the security authority. Do not guess allow/deny decisions, tenant
relationships, roles, safe tool calls, concrete resource URIs, or credentials.
When information is missing or ambiguous, ask a clear question and wait for my
answer.

Safety rules:
- Never ask for, repeat, or place bearer tokens, API keys, passwords, or real
  customer data in the contract or chat output.
- The contract may contain environment-variable NAMES such as
  `TEST_ALICE_TOKEN`, but never their values.
- Use only a controlled loopback target such as http://127.0.0.1:8080/mcp.
- Do not mark a tool call safe unless I explicitly confirm that it is
  side-effect-free and safe to run in this test environment.
- Do not invent test resources. Ask me for stable, synthetic concrete URIs.
- Do not run commands, change files, or contact a server unless I explicitly
  ask you to do so.

MCPRift contract requirements:
- Use schema_version 2.
- Top-level fields are exactly: schema_version, target, actors, access,
  visibility, protocol.
- An access case has: id, title, actor, action, expected.
- Expected access outcomes are `allowed` or `denied`.
- Resource-read actions need a concrete URI.
- Tool-call actions require explicit safe-action metadata; omit tool calls if
  I have not explicitly approved them.
- Use environment-variable names, never credential values.

Interview process:
1. Read the supplied server inventory and summarize only what it explicitly
   shows: tools, resources, templates, prompts, and schemas.
2. Ask for the controlled loopback target, test actors, each actor's token
   environment-variable name, and synthetic test data/URIs.
3. Ask which actor may and may not perform each important action. For each
   important allowed tenant or role case, ask for a corresponding denied case.
4. Ask separately whether any tool call is safe to execute. Never infer this
   from a tool name or description.
5. Before generating JSON, show a compact policy table and a list of every
   unanswered or assumed question. Do not generate executable cases for an
   unanswered rule.
6. After I confirm the policy table, output:
   a. `assessment.draft.json` as one JSON code block;
   b. a short review checklist; and
   c. the exact commands `mcprift validate assessment.json` and
      `mcprift run assessment.json`.

Here is the sanitized MCP capability inventory:
[PASTE INVENTORY JSON HERE]

Here is any known policy or source-code context:
[PASTE POLICY NOTES HERE]
```

## Complete example

This example uses the public pilot server. First inspect the server as Alice;
the token remains in the local environment and is not part of the JSON output.

```sh
export PILOT_ALICE_TOKEN=pilot-alice-token
uv run mcprift inspect http://127.0.0.1:3000/mcp \
  --actor alice --token-env PILOT_ALICE_TOKEN --json > alice-inventory.json
```

The relevant sanitized inventory is:

```json
{
  "capabilities": [
    {
      "kind": "tool",
      "name": "whoami",
      "description": "Return the identity associated with the bearer token."
    },
    {
      "kind": "resource",
      "name": "alice",
      "uri": "pilot://users/alice"
    },
    {
      "kind": "resource",
      "name": "bob",
      "uri": "pilot://users/bob"
    }
  ]
}
```

The inventory does **not** establish who may read each resource. The developer
must answer the policy questions:

| Question | Developer answer |
| --- | --- |
| Controlled target? | `http://127.0.0.1:3000/mcp` |
| Test actors and credential variables? | Alice → `PILOT_ALICE_TOKEN`; Bob → `PILOT_BOB_TOKEN` |
| May Alice read Alice's profile? | Yes |
| May Alice read Bob's profile? | No |
| May Bob read Bob's profile? | Yes |
| May Bob read Alice's profile? | No |
| Are tool calls approved for this contract? | No; test only resource reads |

After the developer confirms those answers, the assistant may produce this
draft:

```json
{
  "schema_version": 2,
  "target": "http://127.0.0.1:3000/mcp",
  "actors": {
    "alice": {
      "kind": "authenticated",
      "token_env": "PILOT_ALICE_TOKEN"
    },
    "bob": {
      "kind": "authenticated",
      "token_env": "PILOT_BOB_TOKEN"
    }
  },
  "access": [
    {
      "id": "PILOT-AUTH-001",
      "title": "Alice can read her pilot profile",
      "actor": "alice",
      "action": {
        "kind": "resource-read",
        "target": "pilot://users/alice"
      },
      "expected": "allowed"
    },
    {
      "id": "PILOT-AUTH-002",
      "title": "Alice cannot read Bob's pilot profile",
      "actor": "alice",
      "action": {
        "kind": "resource-read",
        "target": "pilot://users/bob"
      },
      "expected": "denied"
    },
    {
      "id": "PILOT-AUTH-003",
      "title": "Bob can read his pilot profile",
      "actor": "bob",
      "action": {
        "kind": "resource-read",
        "target": "pilot://users/bob"
      },
      "expected": "allowed"
    },
    {
      "id": "PILOT-AUTH-004",
      "title": "Bob cannot read Alice's pilot profile",
      "actor": "bob",
      "action": {
        "kind": "resource-read",
        "target": "pilot://users/alice"
      },
      "expected": "denied"
    }
  ],
  "visibility": [],
  "protocol": []
}
```

Save the reviewed draft as `assessment.json`. In the terminal that has the two
token environment variables set, validate it before running it:

```sh
uv run mcprift validate assessment.json
uv run mcprift run assessment.json
```

The first command checks the contract structure without connecting to the
server. The second command tests the actual authorization boundary and writes
sanitized evidence.

## Review before committing

- Every important allowed case has a relevant denied counterpart.
- All actors, resource URIs, and data are synthetic and stable.
- The draft contains only token environment-variable names, not secrets.
- Every tool call was explicitly approved as safe, or tool calls are absent.
- The developer, not the AI, confirmed all expected outcomes.
- `mcprift validate assessment.json` passes before CI runs the contract.
