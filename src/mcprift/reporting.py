"""Terminal, JSON, and SARIF rendering for evidence records."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import PurePosixPath
from typing import Any

from mcprift.terminal import green, verdict, yellow


def terminal_report(evidence: dict[str, Any], *, color: bool = False) -> str:
    contract_results = evidence.get("contract_results", [])
    if contract_results:
        return _contract_terminal_report(evidence, contract_results, color=color)
    results = evidence["results"]
    oauth_checks = evidence.get("oauth_checks", [])
    lines = []
    for result in results:
        case = result["case"]
        status = verdict(
            _plain(result["status"]).upper(), result["status"], enabled=color
        )
        lines.append(f"{_plain(case['id'])}: {status} - {_plain(case['title'])}")
    for check in oauth_checks:
        raw_status = "pass" if check["passed"] else "fail"
        status = verdict(raw_status.upper(), raw_status, enabled=color)
        lines.append(
            f"{_plain(check['check_id'])}: {status} - {_plain(check['title'])}"
        )
    statuses = [result["status"] for result in results]
    statuses.extend("pass" if check["passed"] else "fail" for check in oauth_checks)
    counts = Counter(statuses)
    lines.append(_summary(counts, color=color))
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
        finding = {
            "ruleId": case_id,
            "level": "error" if item["verdict"] == "fail" else "warning",
            "message": {
                "text": (
                    f"{title}: expected {item['expected']}, observed {item['observed']}"
                )
            },
            "properties": {
                "family": family,
                "identity": item.get("identity"),
                "verdict": item["verdict"],
            },
        }
        location = _sarif_location(item.get("source"))
        if location is not None:
            finding["locations"] = [location]
        findings.append(finding)
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
                "level": (
                    "warning"
                    if item["status"] in {"error", "rate-limited"}
                    else "error"
                ),
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
        rate_limited = "HTTP 429" in check["observed"]
        findings.append(
            {
                "ruleId": check_id,
                "level": "warning" if rate_limited else "error",
                "message": {"text": f"{check['title']}: observed {check['observed']}"},
                "properties": {"rate_limited": rate_limited},
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
                        "informationUri": "https://github.com/sanjayy0612/MCPRift",
                        "rules": list(rules.values()),
                    }
                },
                "results": findings,
            }
        ],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def _sarif_location(source: object) -> dict[str, Any] | None:
    """Render only portable, repository-relative source locations."""
    if not isinstance(source, dict):
        return None
    uri = source.get("uri")
    line = source.get("line")
    if (
        not isinstance(uri, str)
        or not uri
        or uri != uri.strip()
        or "\\" in uri
        or ":" in uri
        or PurePosixPath(uri).is_absolute()
        or ".." in PurePosixPath(uri).parts
        or not isinstance(line, int)
        or isinstance(line, bool)
        or line < 1
    ):
        return None
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }
    }


def _contract_terminal_report(
    evidence: dict[str, Any], results: list[dict[str, Any]], *, color: bool
) -> str:
    lines = [
        green(
            "case_id | identity | capability/probe | expected | observed | verdict",
            enabled=color,
        )
    ]
    for item in results:
        identity = item.get("identity") or {"name": "protocol"}
        identity_text = identity.get("name", "protocol")
        probe = item.get("probe", {})
        probe_text = probe.get("kind", "unknown")
        status = verdict(
            _plain(item["verdict"]).upper(), item["verdict"], enabled=color
        )
        lines.append(
            f"{_plain(item['case_id'])} | {_plain(identity_text)} | "
            f"{_plain(probe_text)} | {_plain(item['expected'])} | "
            f"{_plain(item['observed'])} | {status}"
        )
    counts = Counter(item["verdict"] for item in results)
    lines.append(_summary(counts, color=color))
    return "\n".join(lines)


def _plain(value: object) -> str:
    """Keep tampered evidence from injecting terminal control sequences."""
    return "".join(character for character in str(value) if character.isprintable())


def _summary(counts: Counter[str], *, color: bool) -> str:
    passed = green(f"{counts['pass']} passed", enabled=color)
    failed = yellow(f"{counts['fail']} failed", enabled=color)
    errors = yellow(f"{counts['error']} errors", enabled=color)
    rate_limited = yellow(f"{counts['rate-limited']} rate-limited", enabled=color)
    return f"summary: {passed}, {failed}, {errors}, {rate_limited}"
