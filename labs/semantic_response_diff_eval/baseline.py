"""Phase 0: measure naive status+content-type+exact-body comparison on the corpus."""

from __future__ import annotations

import json
from typing import Any

from bugbounty_toolkit.analysis.semantic_response_diff import naive_baseline_diff

from .fixtures import CORPUS_VERSION, corpus

BASE_SHA_PINNED = "bd289808600d57983f1dcacaa9b68c0d7eea0d18"


def measure() -> dict[str, Any]:
    rows = corpus()
    true_diff_scenarios = 0
    baseline_reported_diff = 0
    true_positive_diff = 0
    false_positive_diff = 0
    false_negative_diff = 0
    false_equivalences = 0
    details: list[dict[str, Any]] = []
    for row in rows:
        has_relevant = bool(row["relevant_kinds"]) or row["must_preserve_authz"]
        # Ground truth: a relevant difference exists when relevant_kinds nonempty
        # OR must_preserve_authz with expect_structural_equal False.
        expect_diff = bool(row["relevant_kinds"]) or (row["must_preserve_authz"] and not row["expect_structural_equal"])
        if expect_diff:
            true_diff_scenarios += 1
        base = naive_baseline_diff(row["left"], row["right"])
        reported = bool(base["reports_difference"])
        if reported:
            baseline_reported_diff += 1
        if expect_diff and reported:
            true_positive_diff += 1
        elif expect_diff and not reported:
            false_negative_diff += 1
            false_equivalences += 1
        elif not expect_diff and reported:
            false_positive_diff += 1
        details.append(
            {
                "scenario": row["name"],
                "expect_diff": expect_diff,
                "baseline_reports_difference": reported,
                "has_relevant_annotation": has_relevant,
            }
        )
    precision = true_positive_diff / baseline_reported_diff if baseline_reported_diff else 1.0
    recall = true_positive_diff / true_diff_scenarios if true_diff_scenarios else 1.0
    return {
        "schema_version": "bbtk-semantic-response-diff-baseline/1",
        "corpus_version": CORPUS_VERSION,
        "base_sha_pinned": BASE_SHA_PINNED,
        "measurement": "naive status+content-type+exact-body equality",
        "scenarios": len(rows),
        "true_diff_scenarios": true_diff_scenarios,
        "metrics": {
            "precision_relevant_diff": round(precision, 4),
            "recall_field_changes": round(recall, 4),
            "false_equivalences": false_equivalences,
            "false_positive_diffs": false_positive_diff,
            "true_positive_diffs": true_positive_diff,
            "dangerous_normalizations": 0,
            "network_requests_sent": 0,
            "secrets_leaked": 0,
        },
        "details": details,
        "confirmed": False,
        "finding_confirmed": False,
        "notes": [
            "No semantic JSON/HTML engine existed on main at branch time.",
            "response_analyzer extracts status/size/content-type/markers only.",
            "access_control.comparison.exact is exact-value match, not a response diff.",
            "PR #52 denial classifier is authority for denials and is not modified.",
        ],
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2, sort_keys=True))
