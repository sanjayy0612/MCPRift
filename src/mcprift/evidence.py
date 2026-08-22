"""Sanitized, reproducible evidence records."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcprift import __version__
from mcprift.client import TRANSPORT, validate_controlled_url
from mcprift.mutation import MutationObservation
from mcprift.oauth_checks import OAuthCheckResult
from mcprift.security import SecurityResult

SCHEMA_VERSION = "2"
EVIDENCE_SCHEMA_VERSION = SCHEMA_VERSION
SUPPORTED_SCHEMA_VERSIONS = {"1", "2"}
MAX_EVIDENCE_BYTES = 2_000_000


@dataclass(frozen=True)
class EvidenceRun:
    run_id: str
    created_at: str
    target_fingerprint: str
    results: tuple[SecurityResult, ...] = ()
    mutations: tuple[MutationObservation, ...] = ()
    oauth_checks: tuple[OAuthCheckResult, ...] = ()
    contract_results: tuple[dict[str, Any], ...] = ()
    safe_action_acknowledged: bool = False
    safe_action_justifications: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "tool": {"name": "mcprift", "version": __version__},
            "target": {
                "fingerprint": self.target_fingerprint,
                "transport": TRANSPORT,
            },
            "results": [result.to_dict() for result in self.results],
            "mutations": [mutation.to_dict() for mutation in self.mutations],
            "oauth_checks": [check.to_dict() for check in self.oauth_checks],
            "contract_results": list(self.contract_results),
            "safety": {
                "safe_action_acknowledged": self.safe_action_acknowledged,
                "safe_action_justifications": list(self.safe_action_justifications),
            },
        }


def create_evidence(
    raw_url: str,
    *,
    results: tuple[SecurityResult, ...] = (),
    mutations: tuple[MutationObservation, ...] = (),
    oauth_checks: tuple[OAuthCheckResult, ...] = (),
    contract_results: tuple[dict[str, Any], ...] = (),
    safe_action_acknowledged: bool = False,
    safe_action_justifications: tuple[str, ...] = (),
) -> EvidenceRun:
    """Create evidence without retaining the target URL or credentials."""
    url = validate_controlled_url(raw_url)
    return EvidenceRun(
        run_id=str(uuid.uuid4()),
        created_at=datetime.now(UTC).isoformat(),
        target_fingerprint=hashlib.sha256(url.encode()).hexdigest(),
        results=results,
        mutations=mutations,
        oauth_checks=oauth_checks,
        contract_results=contract_results,
        safe_action_acknowledged=safe_action_acknowledged,
        safe_action_justifications=safe_action_justifications,
    )


def write_evidence(evidence: EvidenceRun, directory: str | Path) -> Path:
    """Atomically write a private JSON evidence file."""
    target_directory = Path(directory)
    target_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = target_directory / f"mcprift-{evidence.run_id}.json"
    payload = json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n"

    descriptor, temporary_name = tempfile.mkstemp(
        dir=target_directory, prefix=".mcprift-", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def read_evidence(path: str | Path) -> dict[str, Any]:
    evidence_path = Path(path)
    if evidence_path.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence file exceeds size limit")
    try:
        value = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid evidence file") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS
    ):
        raise ValueError("unsupported evidence schema")
    if (
        not isinstance(value.get("results", []), list)
        or not isinstance(value.get("mutations", []), list)
        or not isinstance(value.get("oauth_checks", []), list)
        or not isinstance(value.get("contract_results", []), list)
    ):
        raise ValueError("unsupported evidence schema")
    return value
