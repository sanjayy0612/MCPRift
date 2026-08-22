"""Execution and verdict evaluation for v0.4 authorization contracts."""

from __future__ import annotations

import asyncio
from typing import Any

from mcprift.assessment import AssessmentPlan
from mcprift.capabilities import CapabilityInventory, inspect_capabilities
from mcprift.mutation import run_mutation
from mcprift.operations import Outcome
from mcprift.security import run_cases


async def run_contract(
    plan: AssessmentPlan, *, timeout_seconds: float = 10
) -> tuple[dict[str, Any], ...]:
    """Run every declared family sequentially and return sanitized verdicts."""
    actors = plan.resolve_actors()
    results: list[dict[str, Any]] = []

    access_cases = plan.runtime_access_cases(actors)
    if access_cases:
        access_results = await run_cases(plan.target, access_cases)
        results.extend(_access_result(result) for result in access_results)

    for case in plan.visibility:
        actor = actors[case.actor_name]
        try:
            inventory = await asyncio.wait_for(
                inspect_capabilities(plan.target, actor), timeout=timeout_seconds
            )
            observed = (
                "visible"
                if _capability_present(inventory, case.capability_kind, case.capability)
                else "hidden"
            )
            verdict = "pass" if observed == case.expected else "fail"
        except Exception:
            observed, verdict = "error", "error"
        results.append(
            _base_result(
                case_id=case.case_id,
                title=case.title,
                family="visibility",
                identity=actor.to_dict(),
                probe={"kind": case.capability_kind},
                expected=case.expected,
                observed=observed,
                verdict=verdict,
            )
        )

    for case in plan.protocol:
        try:
            observation = await run_mutation(plan.target, case.mutation)
            rejected = (
                observation.http_status >= 400 or observation.json_rpc_error
            ) and not observation.session_established
            observed = "rejected" if rejected else "accepted"
            verdict = "pass" if observed == case.expected else "fail"
            probe = {
                "kind": "protocol-mutation",
                "mutation": case.mutation.value,
                "http_status": observation.http_status,
                "content_type": observation.content_type,
                "response_bytes": observation.response_bytes,
                "response_sha256": observation.response_sha256,
                "json_rpc_error": observation.json_rpc_error,
                "session_established": observation.session_established,
            }
        except Exception:
            observed, verdict = "error", "error"
            probe = {"kind": "protocol-mutation", "mutation": case.mutation.value}
        results.append(
            _base_result(
                case_id=case.case_id,
                title=case.title,
                family="protocol",
                identity=None,
                probe=probe,
                expected=case.expected,
                observed=observed,
                verdict=verdict,
            )
        )
    return tuple(results)


def _access_result(result: Any) -> dict[str, Any]:
    case = result.case
    observation = result.observation
    if observation.outcome is Outcome.SUCCEEDED:
        observed = "allowed"
    elif observation.outcome is Outcome.REJECTED:
        observed = "denied"
    else:
        observed = "error"
    return _base_result(
        case_id=case.case_id,
        title=case.title,
        family="session" if case.session_policy.value == "reused" else "access",
        identity={"name": observation.actor_name, "kind": observation.actor_kind},
        probe={"kind": case.action.kind.value},
        expected=case.expected.value,
        observed=observed,
        verdict=result.status.value,
        session={
            "policy": case.session_policy.value,
            **(
                {
                    "establishing_actor": case.establishing_actor.name,
                    "establishing_outcome": (
                        observation.establishing_outcome.value
                        if observation.establishing_outcome is not None
                        else None
                    ),
                }
                if case.establishing_actor is not None
                else {}
            ),
        },
    )


def _base_result(
    *,
    case_id: str,
    title: str,
    family: str,
    identity: dict[str, str] | None,
    probe: dict[str, Any],
    expected: str,
    observed: str,
    verdict: str,
    session: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "case_id": case_id,
        "title": title,
        "family": family,
        "identity": identity,
        "probe": probe,
        "expected": expected,
        "observed": observed,
        "verdict": verdict,
    }
    if session is not None:
        result["session"] = session
    return result


def _capability_present(
    inventory: CapabilityInventory, kind: str, capability: str
) -> bool:
    return any(
        item.kind == kind and (item.name == capability or item.uri == capability)
        for item in inventory.capabilities
    )
