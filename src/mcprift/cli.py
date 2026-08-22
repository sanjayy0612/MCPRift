"""The small command-line interface for MCPRift."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from mcprift import __version__
from mcprift.actors import Actor, ActorKind, actor_from_environment, standard_actors
from mcprift.assessment import (
    contains_safe_actions,
    load_assessment,
    write_lab_template,
)
from mcprift.capabilities import inspect_capabilities
from mcprift.client import ConnectionFailure, connect
from mcprift.contract_runner import run_contract
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
from mcprift.terminal import color_enabled, green, yellow


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
    demo_parser = subcommands.add_parser(
        "demo", help="run the disposable local lab with no setup"
    )
    demo_parser.add_argument(
        "--evidence-dir",
        metavar="PATH",
        help="optionally save sanitized demo evidence in this directory",
    )
    init_parser = subcommands.add_parser(
        "init", help="create a non-secret authorization contract"
    )
    init_parser.add_argument("path", metavar="ASSESSMENT_JSON")
    init_parser.add_argument(
        "--lab", action="store_true", required=True, help="use the disposable local lab"
    )
    validate_parser = subcommands.add_parser(
        "validate", help="validate a contract without credentials or network access"
    )
    validate_parser.add_argument("path", metavar="ASSESSMENT_JSON")
    run_parser = subcommands.add_parser(
        "run", help="run a declared authorization contract"
    )
    run_parser.add_argument("path", metavar="ASSESSMENT_JSON")
    run_parser.add_argument(
        "--acknowledge-safe-actions",
        action="store_true",
        help="confirm that declared tool calls are reviewed safe actions",
    )
    _add_report_arguments(run_parser)
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
        "--actor",
        metavar="NAME",
        help="inspect capabilities visible to this named actor",
    )
    inspect_parser.add_argument(
        "--actor-kind",
        choices=tuple(kind.value for kind in ActorKind),
        default=ActorKind.AUTHENTICATED.value,
        help="actor kind when --actor is set (default: authenticated)",
    )
    inspect_parser.add_argument(
        "--token-env",
        metavar="NAME",
        help="environment variable holding the actor bearer token",
    )
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

    if arguments.command == "demo":
        return _run_demo(arguments.evidence_dir)

    if arguments.command == "init":
        try:
            path = write_lab_template(arguments.path)
        except (OSError, ValueError) as error:
            print(f"mcprift: {error}", file=sys.stderr)
            return 2
        print(_green(f"created lab contract: {path}"))
        return 0

    if arguments.command == "validate":
        try:
            plan = load_assessment(arguments.path)
        except (OSError, ValueError) as error:
            print(f"mcprift: invalid assessment: {error}", file=sys.stderr)
            return 2
        print(
            _green("valid assessment")
            + f": {len(plan.access)} access, {len(plan.visibility)} visibility, "
            f"{len(plan.protocol)} protocol cases"
        )
        return 0

    if arguments.command == "run":
        try:
            plan = load_assessment(arguments.path)
            if contains_safe_actions(plan) and not arguments.acknowledge_safe_actions:
                raise ValueError("tool-call cases require --acknowledge-safe-actions")
            contract_results = asyncio.run(run_contract(plan))
            evidence = create_evidence(
                plan.target,
                contract_results=contract_results,
                safe_action_acknowledged=arguments.acknowledge_safe_actions,
                safe_action_justifications=tuple(
                    case.action.safety_justification
                    for case in plan.access
                    if case.action.safety_justification is not None
                ),
            )
            evidence_path = write_evidence(evidence, arguments.evidence_dir)
        except (ConnectionFailure, OSError, ValueError) as error:
            print(f"mcprift: {error}", file=sys.stderr)
            return 2
        print(_render(evidence.to_dict(), arguments.format))
        print(f"evidence: {evidence_path}", file=sys.stderr)
        return _contract_exit_code(contract_results)

    if arguments.command == "inspect":
        try:
            actor = _inspection_actor(arguments)
            inventory = asyncio.run(inspect_capabilities(arguments.url, actor))
        except (ConnectionFailure, ValueError) as error:
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


def _run_demo(evidence_dir: str | None) -> int:
    """Run the bundled lab in a temporary workspace, then clean it up."""
    lab: subprocess.Popen[bytes] | None = None
    try:
        port = _available_loopback_port()
        target = f"http://127.0.0.1:{port}/mcp"
        lab = subprocess.Popen(
            [sys.executable, "-m", "mcprift.lab", "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_for_lab(port, lab)
        with tempfile.TemporaryDirectory(prefix="mcprift-demo-") as directory:
            assessment_path = _demo_assessment(Path(directory), target)
            with _demo_credentials():
                plan = load_assessment(assessment_path)
                contract_results = asyncio.run(run_contract(plan))
            exit_code = _contract_exit_code(contract_results)
            passed = sum(item["verdict"] == "pass" for item in contract_results)
            failed = [
                item["case_id"]
                for item in contract_results
                if item["verdict"] != "pass"
            ]
            print(_green("MCPRift demo: bundled local authorization lab"))
            print(
                f"checked {len(contract_results)} cases: "
                f"{_green(f'{passed} passed')}"
            )
            if failed:
                print(_yellow(f"needs attention: {', '.join(failed)}"))
            else:
                print(_green("result: all expected access boundaries held"))
            if evidence_dir is not None:
                evidence = create_evidence(
                    target,
                    contract_results=contract_results,
                    safe_action_acknowledged=True,
                    safe_action_justifications=(
                        "The bundled lab safe_echo tool only echoes a fixed "
                        "probe message.",
                    ),
                )
                evidence_path = write_evidence(evidence, evidence_dir)
                print(_yellow(f"sanitized evidence: {evidence_path}"))
            print(
                _yellow(
                    "next: inspect your controlled MCP server, then write its contract"
                )
            )
            return exit_code
    except (ConnectionFailure, OSError, ValueError) as error:
        print(f"mcprift: demo could not run: {error}", file=sys.stderr)
        return 2
    finally:
        if lab is not None and lab.poll() is None:
            lab.terminate()
            try:
                lab.wait(timeout=5)
            except subprocess.TimeoutExpired:
                lab.kill()
                lab.wait(timeout=5)


def _available_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _wait_for_lab(port: int, lab: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if lab.poll() is not None:
            raise ConnectionFailure("bundled lab exited before accepting connections")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            if client.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise ConnectionFailure("bundled lab did not start within 10 seconds")


def _demo_assessment(directory: Path, target: str) -> Path:
    path = write_lab_template(directory / "assessment.json")
    contract = json.loads(path.read_text(encoding="utf-8"))
    contract["target"] = target
    path.write_text(json.dumps(contract), encoding="utf-8")
    return path


@contextmanager
def _demo_credentials() -> Iterator[None]:
    credentials = {
        "MCPRIFT_AUTH_TOKEN": "mcprift-lab-alice",
        "MCPRIFT_BOB_TOKEN": "mcprift-lab-bob",
        "MCPRIFT_INVALID_TOKEN": "mcprift-lab-invalid",
        "MCPRIFT_EXPIRED_TOKEN": "mcprift-lab-expired",
    }
    previous = {name: os.environ.get(name) for name in credentials}
    os.environ.update(credentials)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                del os.environ[name]
            else:
                os.environ[name] = value


def _inspection_actor(arguments: argparse.Namespace) -> Actor | None:
    """Resolve an optional inspect identity without exposing its credential."""
    if arguments.actor is None:
        if arguments.token_env is not None:
            raise ValueError("--token-env requires --actor")
        return None
    kind = ActorKind(arguments.actor_kind)
    if kind is ActorKind.ANONYMOUS:
        if arguments.token_env is not None:
            raise ValueError("anonymous --actor cannot define --token-env")
        return Actor(arguments.actor, kind)
    if arguments.token_env is None:
        raise ValueError("credentialed --actor requires --token-env")
    return actor_from_environment(arguments.actor, kind, arguments.token_env)


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
    return terminal_report(evidence, color=color_enabled(sys.stdout))


def _green(text: str) -> str:
    return green(text, enabled=color_enabled(sys.stdout))


def _yellow(text: str) -> str:
    return yellow(text, enabled=color_enabled(sys.stdout))


def _result_exit_code(results: tuple[SecurityResult, ...]) -> int:
    if any(result.status is ResultStatus.ERROR for result in results):
        return 2
    if any(result.status is ResultStatus.FAIL for result in results):
        return 1
    return 0


def _contract_exit_code(results: tuple[dict[str, Any], ...]) -> int:
    if any(result["verdict"] == "error" for result in results):
        return 2
    return 1 if any(result["verdict"] == "fail" for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
