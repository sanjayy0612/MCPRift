"""Terminal, JSON, and SARIF rendering for evidence records."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any


def terminal_report(evidence: dict[str, Any]) -> str:
    contract_results = evidence.get("contract_results", [])
    if contract_results:
        return _contract_terminal_report(evidence, contract_results)
    results = evidence["results"]
    oauth_checks = evidence.get("oauth_checks", [])
    lines = []
    for result in results:
        case = result["case"]
        lines.append(
            f"{_plain(case['id'])}: {_plain(result['status']).upper()} - "
            f"{_plain(case['title'])}"
        )
    for check in oauth_checks:
        status = "PASS" if check["passed"] else "FAIL"
        lines.append(
            f"{_plain(check['check_id'])}: {status} - {_plain(check['title'])}"
        )
    statuses = [result["status"] for result in results]
    statuses.extend("pass" if check["passed"] else "fail" for check in oauth_checks)
    counts = Counter(statuses)
    lines.append(
        "summary: "
        f"{counts['pass']} passed, {counts['fail']} failed, "
        f"{counts['error']} errors"
    )
    return "\n".join(lines)


def json_report(evidence: dict[str, Any]) -> str:
    return json.dumps(evidence, indent=2, sort_keys=True)


def sarif_report(evidence: dict[str, Any]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    findings = []
    for item in evidence.get("contract_results", []):
        case_id = item["case_id"]
        family = item["family"]
        title = item["title"]
        rules[case_id] = {
            "id": case_id,
            "shortDescription": {"text": title},
            "properties": {"family": family, "expected": item["expected"]},
            "help": {
                "text": (
                    f"Review the declared {family} boundary and make the target "
                    "match the contract, or update the contract after review."
                )
            },
        }
        if item["verdict"] == "pass":
            continue
        findings.append(
            {
                "ruleId": case_id,
                "level": "error" if item["verdict"] == "fail" else "warning",
                "message": {
                    "text": (
                        f"{title}: expected {item['expected']}, "
                        f"observed {item['observed']}"
                    )
                },
                "properties": {
                    "family": family,
                    "identity": item.get("identity"),
                    "verdict": item["verdict"],
                },
            }
        )
    for item in evidence["results"]:
        case = item["case"]
        case_id = case["id"]
        rules[case_id] = {
            "id": case_id,
            "shortDescription": {"text": case["title"]},
            "properties": {"expected": case["expected"]},
        }
        if item["status"] == "pass":
            continue
        findings.append(
            {
                "ruleId": case_id,
                "level": "error" if item["status"] == "fail" else "warning",
                "message": {
                    "text": (
                        f"{case['title']}: observed {item['observation']['outcome']}"
                    )
                },
                "properties": {
                    "actor": item["observation"]["actor"],
                    "status": item["status"],
                },
            }
        )
    for check in evidence.get("oauth_checks", []):
        check_id = check["check_id"]
        rules[check_id] = {
            "id": check_id,
            "shortDescription": {"text": check["title"]},
            "properties": {"expected": check["expected"]},
        }
        if check["passed"]:
            continue
        findings.append(
            {
                "ruleId": check_id,
                "level": "error",
                "message": {"text": f"{check['title']}: observed {check['observed']}"},
            }
        )
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPRift",
                        "version": evidence["tool"]["version"],
                        "rules": list(rules.values()),
                    }
                },
                "results": findings,
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def _contract_terminal_report(
    evidence: dict[str, Any], results: list[dict[str, Any]]
) -> str:
    lines = ["case_id | identity | capability/probe | expected | observed | verdict"]
    for item in results:
        identity = item.get("identity") or {"name": "protocol"}
        identity_text = identity.get("name", "protocol")
        probe = item.get("probe", {})
        probe_text = probe.get("kind", "unknown")
        lines.append(
            f"{_plain(item['case_id'])} | {_plain(identity_text)} | "
            f"{_plain(probe_text)} | {_plain(item['expected'])} | "
            f"{_plain(item['observed'])} | {_plain(item['verdict']).upper()}"
        )
    counts = Counter(item["verdict"] for item in results)
    lines.append(
        f"summary: {counts['pass']} passed, {counts['fail']} failed, "
        f"{counts['error']} errors"
    )
    return "\n".join(lines)


def _plain(value: object) -> str:
    """Keep tampered evidence from injecting terminal control sequences."""
    return "".join(character for character in str(value) if character.isprintable())
