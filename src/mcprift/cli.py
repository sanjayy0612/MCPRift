"""The small command-line interface for MCPRift."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

from mcprift import __version__
from mcprift.client import ConnectionFailure, connect


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser(
        prog="mcprift",
        description="Authorized, controlled MCP connectivity checks.",
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
    return command_parser


def main(argv: Sequence[str] | None = None) -> int:
    command_parser = parser()
    arguments = command_parser.parse_args(argv)
    if arguments.command in {None, "help"}:
        command_parser.print_help()
        return 0
    if arguments.command == "version":
        print(f"mcprift {__version__}")
        return 0

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


if __name__ == "__main__":
    raise SystemExit(main())
