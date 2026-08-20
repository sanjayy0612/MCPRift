"""Canonical replay of built-in safe security cases."""

from __future__ import annotations

from typing import Any

from mcprift.registry import CaseRegistry
from mcprift.security import SecurityResult, run_cases


async def replay_case(
    raw_url: str,
    evidence: dict[str, Any],
    case_id: str,
    registry: CaseRegistry,
) -> SecurityResult:
    """Replay registry code, never executable actions supplied by evidence."""
    recorded = {
        item.get("case", {}).get("id")
        for item in evidence["results"]
        if isinstance(item, dict) and isinstance(item.get("case"), dict)
    }
    if case_id not in recorded:
        raise ValueError("case is not present in evidence")
    case = registry.get(case_id)
    return (await run_cases(raw_url, (case,)))[0]
