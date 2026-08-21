"""The small command-line interface for MCPRift."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from typing import Any

from mcprift import __version__
from mcprift.actors import standard_actors
from mcprift.capabilities import inspect_capabilities
from mcprift.client import ConnectionFailure, connect
from mcprift.evidence import create_evidence, read_evidence, write_evidence
from mcprift.mutation import MutationKind, run_mutation
from mcprift.oauth_checks import run_oauth_checks
from mcprift.operations import Action, ActionKind, Outcome, compare_identities
from mcprift.registry import CaseRegistry, default_registry
from mcprift.replay import replay_case
from mcprift.reporting import json_report, sarif_report, terminal_report
from mcprift.security import (
    SESSION_CASE_ID,
    ResultStatus,
    SecurityCase,
    SecurityResult,
    run_cases,
)


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser(
        prog="mcprift",
        description="Authorized, controlled MCP security checks.",
    )
    command_parser.add_argument(
        "--version", action="version", version=f"mcprift {__version__}"
    )
    subcommands = command_parser.add_subparsers(dest="command")
    subcommands.add_parser("version", help="show the MCPRift version")
    subcommands.add_parser("help", help="show this help message")
    connect_parser = subcommands.add_parser(
        "connect",
        help="make a baseline connection to a controlled Streamable HTTP URL",
    )
    connect_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    inspect_parser = subcommands.add_parser(
        "inspect",
        help="list capabilities without invoking them",
    )
    inspect_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    inspect_parser.add_argument(
        "--json", action="store_true", help="write the inventory as JSON"
    )
    compare_parser = subcommands.add_parser(
        "compare",
        help="compare one acknowledged-safe tool across four identity contexts",
    )
    compare_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    compare_parser.add_argument("--safe-tool", required=True, metavar="NAME")
    compare_parser.add_argument("--arguments", default="{}", metavar="JSON_OBJECT")
    compare_parser.add_argument(
        "--authenticated-token-env", default="MCPRIFT_AUTH_TOKEN", metavar="NAME"
    )
    compare_parser.add_argument(
        "--invalid-token-env", default="MCPRIFT_INVALID_TOKEN", metavar="NAME"
    )
    compare_parser.add_argument(
        "--expired-token-env", default="MCPRIFT_EXPIRED_TOKEN", metavar="NAME"
    )
    compare_parser.add_argument(
        "--json", action="store_true", help="write observations as JSON"
    )
    test_parser = subcommands.add_parser(
        "test", help="run the bounded built-in authorization suite"
    )
    test_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    test_parser.add_argument("--case", action="append", dest="case_ids", metavar="ID")
    _add_report_arguments(test_parser)
    session_parser = subcommands.add_parser(
        "session-test",
        help="test actor binding while one controlled session is reused",
    )
    session_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    _add_report_arguments(session_parser)
    oauth_parser = subcommands.add_parser(
        "oauth-test",
        help="run bounded OAuth, PKCE, audience, and passthrough checks",
    )
    oauth_parser.add_argument("url", metavar="CONTROLLED_OAUTH_LAB_URL")
    _add_report_arguments(oauth_parser)

    mutation_parser = subcommands.add_parser(
        "mutate", help="send one deterministic raw JSON-RPC mutation"
    )
    mutation_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    mutation_parser.add_argument("kind", choices=[kind.value for kind in MutationKind])
    mutation_parser.add_argument(
        "--evidence-dir", default="mcprift-evidence", metavar="PATH"
    )
    mutation_parser.add_argument("--json", action="store_true")

    report_parser = subcommands.add_parser(
        "report", help="render an existing evidence record"
    )
    report_parser.add_argument("evidence", metavar="EVIDENCE_JSON")
    report_parser.add_argument(
        "--format", choices=("terminal", "json", "sarif"), default="terminal"
    )

    replay_parser = subcommands.add_parser(
        "replay", help="replay one canonical safe case from evidence"
    )
    replay_parser.add_argument("url", metavar="CONTROLLED_STREAMABLE_HTTP_URL")
    replay_parser.add_argument("evidence", metavar="EVIDENCE_JSON")
    replay_parser.add_argument("--case", required=True, dest="case_id", metavar="ID")
    _add_report_arguments(replay_parser)
    return command_parser


def _add_report_arguments(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--format", choices=("terminal", "json", "sarif"), default="terminal"
    )
    command_parser.add_argument(
        "--evidence-dir", default="mcprift-evidence", metavar="PATH"
    )


def main(argv: Sequence[str] | None = None) -> int:
    command_parser = parser()
    arguments = command_parser.parse_args(argv)
    if arguments.command in {None, "help"}:
        command_parser.print_help()
        return 0
    if arguments.command == "version":
        print(f"mcprift {__version__}")
        return 0

    if arguments.command == "inspect":
        try:
            inventory = asyncio.run(inspect_capabilities(arguments.url))
        except ConnectionFailure as error:
            print(f"mcprift: {error}", file=sys.stderr)
            return 1
        if arguments.json:
            print(json.dumps(inventory.to_dict(), indent=2, sort_keys=True))
        else:
            print(
                f"{inventory.connection.server_name} "
                f"{inventory.connection.server_version} capabilities:"
            )
            for capability in inventory.capabilities:
                location = f" ({capability.uri})" if capability.uri else ""
                print(f"- {capability.kind}: {capability.name}{location}")
        return 0

    if arguments.command == "compare":
        try:
            action_arguments = json.loads(arguments.arguments)
            if not isinstance(action_arguments, dict):
                raise ValueError
        except (json.JSONDecodeError, ValueError):
            print("mcprift: --arguments must be a JSON object", file=sys.stderr)
            return 2

        try:
            tokens = tuple(
                _required_token(name)
                for name in (
                    arguments.authenticated_token_env,
                    arguments.invalid_token_env,
                    arguments.expired_token_env,
                )
            )
        except ConnectionFailure as error:
            print(
                f"mcprift: {error}",
                file=sys.stderr,
            )
            return 2
        action = Action(
            ActionKind.TOOL_CALL,
            arguments.safe_tool,
            action_arguments,
            known_safe=True,
        )
        actors = standard_actors(
            authenticated_token=tokens[0],
            invalid_token=tokens[1],
            expired_token=tokens[2],
        )
        try:
            observations = asyncio.run(
                compare_identities(arguments.url, action, actors)
            )
        except ConnectionFailure as error:
            print(f"mcprift: {error}", file=sys.stderr)
            return 1
        if arguments.json:
            print(
                json.dumps(
                    [observation.to_dict() for observation in observations],
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for observation in observations:
                print(
                    f"{observation.actor_name} ({observation.actor_kind}): "
                    f"{observation.outcome.value}"
                )
        return (
            2
            if any(
                observation.outcome is Outcome.UNAVAILABLE
                for observation in observations
            )
            else 0
        )

    if arguments.command in {"test", "session-test"}:
        try:
            registry = _registry_from_environment()
            if arguments.command == "session-test":
                cases = (registry.get(SESSION_CASE_ID),)
            else:
                cases = _selected_cases(registry, arguments.case_ids)
            results = asyncio.run(run_cases(arguments.url, cases))
            evidence = create_evidence(arguments.url, results=results)
            evidence_path = write_evidence(evidence, arguments.evidence_dir)
        except (ConnectionFailure, OSError, ValueError) as error:
            print(f"mcprift: {error}", file=sys.stderr)
            return 2
        print(_render(evidence.to_dict(), arguments.format))
        print(f"evidence: {evidence_path}", file=sys.stderr)
        return _result_exit_code(results)

    if arguments.command == "oauth-test":
        try:
            oauth_checks = asyncio.run(run_oauth_checks(arguments.url))
            evidence = create_evidence(arguments.url, oauth_checks=oauth_checks)
            evidence_path = write_evidence(evidence, arguments.evidence_dir)
        except (ConnectionFailure, OSError, ValueError):
            print("mcprift: OAuth checks failed", file=sys.stderr)
            return 2
        except Exception:
            print("mcprift: OAuth checks failed", file=sys.stderr)
            return 2
        print(_render(evidence.to_dict(), arguments.format))
        print(f"evidence: {evidence_path}", file=sys.stderr)
        return 0 if all(check.passed for check in oauth_checks) else 1

    if arguments.command == "mutate":
        try:
            observation = asyncio.run(
                run_mutation(arguments.url, MutationKind(arguments.kind))
            )
            evidence = create_evidence(arguments.url, mutations=(observation,))
            evidence_path = write_evidence(evidence, arguments.evidence_dir)
        except (ConnectionFailure, OSError, ValueError) as error:
            print(f"mcprift: {error}", file=sys.stderr)
            return 1
        if arguments.json:
            print(json.dumps(observation.to_dict(), indent=2, sort_keys=True))
        else:
            print(
                f"{observation.kind.value}: HTTP {observation.http_status}, "
                f"{observation.response_bytes} response bytes, "
                f"sha256 {observation.response_sha256}"
            )
        print(f"evidence: {evidence_path}", file=sys.stderr)
        return 0

    if arguments.command == "report":
        try:
            evidence = read_evidence(arguments.evidence)
            print(_render(evidence, arguments.format))
        except (OSError, ValueError, KeyError, TypeError) as error:
            print(f"mcprift: cannot render evidence: {error}", file=sys.stderr)
            return 2
        return 0

    if arguments.command == "replay":
        try:
            recorded = read_evidence(arguments.evidence)
            registry = _registry_from_environment()
            result = asyncio.run(
                replay_case(arguments.url, recorded, arguments.case_id, registry)
            )
            evidence = create_evidence(arguments.url, results=(result,))
            evidence_path = write_evidence(evidence, arguments.evidence_dir)
        except (ConnectionFailure, OSError, ValueError) as error:
            print(f"mcprift: cannot replay evidence: {error}", file=sys.stderr)
            return 2
        print(_render(evidence.to_dict(), arguments.format))
        print(f"evidence: {evidence_path}", file=sys.stderr)
        return _result_exit_code((result,))

    try:
        result = asyncio.run(connect(arguments.url))
    except ConnectionFailure as error:
        print(f"mcprift: {error}", file=sys.stderr)
        return 1

    print(
        f"connected to {result.server_name} {result.server_version} using "
        f"{result.transport} (protocol {result.protocol_version})"
    )
    return 0


def _required_token(variable: str) -> str:
    token = os.environ.get(variable)
    if not token:
        raise ConnectionFailure(
            "required actor credential environment variable is not set"
        )
    return token


def _registry_from_environment() -> CaseRegistry:
    return default_registry(
        alice_token=_required_token("MCPRIFT_AUTH_TOKEN"),
        bob_token=_required_token("MCPRIFT_BOB_TOKEN"),
        invalid_token=_required_token("MCPRIFT_INVALID_TOKEN"),
        expired_token=_required_token("MCPRIFT_EXPIRED_TOKEN"),
    )


def _selected_cases(
    registry: CaseRegistry, case_ids: list[str] | None
) -> tuple[SecurityCase, ...]:
    if not case_ids:
        return registry.all()
    return tuple(registry.get(case_id) for case_id in case_ids)


def _render(evidence: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json_report(evidence)
    if output_format == "sarif":
        return sarif_report(evidence)
    return terminal_report(evidence)


def _result_exit_code(results: tuple[SecurityResult, ...]) -> int:
    if any(result.status is ResultStatus.ERROR for result in results):
        return 2
    if any(result.status is ResultStatus.FAIL for result in results):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
