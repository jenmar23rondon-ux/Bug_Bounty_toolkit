"""Versioned schema for offline verified research dossiers.

A dossier links claims in a review draft to ledger-recorded evidence. It never
mutates candidate states and never invents reproduction steps, impact, or
confirmations. Expected behavior must come from an explicit lab/spec source.
"""

from __future__ import annotations

from typing import Any, Final

SCHEMA_VERSION: Final[str] = "bbtk-verified-dossier/1"
SUPPORTED_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset({SCHEMA_VERSION})

# Outcome of claim-to-evidence verification (dossier review states).
DOSSIER_STATES: Final[tuple[str, ...]] = (
    "complete_for_review",
    "missing_evidence",
    "stale_evidence",
    "contradictory_evidence",
    "unsupported_claim",
    "human_validation_required",
    "invalid_provenance",
)

CLAIM_KINDS: Final[tuple[str, ...]] = (
    "ledger_state",
    "evidence_reference",
    "expected_behavior",
    "observed_behavior",
    "control_result",
    "ownership",
    "impact",
    "reproduction_step",
    "confirmation",
    "ai_conclusion",
    "classification",
    "severity",
)

# Sources allowed for expected_behavior (never inferred from endpoint names).
EXPECTED_BEHAVIOR_SOURCES: Final[frozenset[str]] = frozenset(
    {"lab_spec", "program_policy", "explicit_declaration", "human_declared"}
)

REPRODUCIBILITY_STATUSES: Final[tuple[str, ...]] = (
    "reproducible_with_recorded_evidence",
    "partial_evidence",
    "not_demonstrated",
    "steps_invented",
    "blocked",
)

DOSSIER_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": ("https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/docs/schemas/verified-dossier-v1.schema.json"),
    "title": "bbtk verified research dossier",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "candidate_id",
        "category",
        "ledger_state",
        "evidence_inventory",
        "source_refs",
        "control_summary",
        "expected_behavior",
        "observed_behavior",
        "comparison",
        "contradictions",
        "unsupported_claims",
        "missing_evidence",
        "reviewer_requirements",
        "reproducibility_status",
        "limitations",
        "validation_result",
        "finding_confirmed",
        "ledger_mutated",
        "network_requests_sent",
        "auto_confirmations",
    ],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "candidate_id": {"type": "string", "minLength": 1, "maxLength": 128},
        "category": {"type": "string", "maxLength": 80},
        "ledger_state": {"enum": ["candidate", "requires_validation", "rejected", "confirmed", "unknown"]},
        "evidence_inventory": {"type": "array", "maxItems": 200},
        "source_refs": {"type": "array", "maxItems": 100},
        "control_summary": {"type": "object"},
        "expected_behavior": {"type": "object"},
        "observed_behavior": {"type": "object"},
        "comparison": {"type": "object"},
        "contradictions": {"type": "array", "maxItems": 100},
        "unsupported_claims": {"type": "array", "maxItems": 100},
        "missing_evidence": {"type": "array", "maxItems": 100},
        "reviewer_requirements": {"type": "array", "maxItems": 50},
        "reproducibility_status": {"enum": list(REPRODUCIBILITY_STATUSES)},
        "limitations": {"type": "array", "maxItems": 50},
        "validation_result": {"enum": list(DOSSIER_STATES)},
        "finding_confirmed": {"type": "boolean"},
        "claim_audit": {"type": "array", "maxItems": 500},
        "metrics": {"type": "object"},
        "private": {"type": "boolean"},
        "notice": {"type": "string", "maxLength": 1000},
        "ledger_mutated": {"const": False},
        "network_requests_sent": {"const": 0},
        "auto_confirmations": {"const": 0},
    },
}

DOSSIER_NOTICE: Final[str] = (
    "Verified research dossier (offline). Claims are audited against the evidence "
    "ledger and local digests only. This module does not confirm vulnerabilities, "
    "invent reproduction steps or payloads, interpret HTTP 200 as unauthorized "
    "access, infer impact from endpoint names, or mutate ledger states."
)
