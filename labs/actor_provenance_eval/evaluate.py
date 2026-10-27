"""Offline before/after evaluator; no network, files or original records mutated."""

from __future__ import annotations

import argparse
import json

from .corpus import KEY, PROGRAM, corpus


def evaluate(*, baseline: bool = False) -> dict[str, object]:
    records, manifest, truth = corpus()
    if baseline:
        # Existing engine has session HMACs but no actor-label/account declarations.
        predictions: list[str | None] = [None for _ in records]
        conflicts = 0
        coverage = 0
        exposed = 0
        mixed = 0
    else:
        from bugbounty_toolkit.analysis.actor_provenance import associate_actors, account_ref

        result = associate_actors(records, manifest, program=PROGRAM, key=KEY)
        predictions = [row["account_ref"] for row in result["captures"]]
        ordered_truth = [value for _, value in sorted(zip([r.provenance[0].locator for r in records], truth))]
        truth = [account_ref(value, program=PROGRAM, key=KEY) if value else None for value in ordered_truth]
        conflicts = len(result["conflicts"])
        coverage = sum(row["label"] != "unknown" for row in result["captures"])
        exposed = int("CANARY" in json.dumps(result))
        foreign = dict(manifest, program="other-program")
        other = associate_actors(records, foreign, program="other-program", key=KEY)
        first_refs = {row["account_ref"] for row in result["captures"] if row["account_ref"]}
        other_refs = {row["account_ref"] for row in other["captures"] if row["account_ref"]}
        mixed = len(first_refs & other_refs)
    return {
        "captures": len(records),
        "association_accuracy": sum(a == b for a, b in zip(predictions, truth)) / len(truth),
        "label_coverage": coverage / len(records),
        "incorrect_associations": sum(a is not None and a != b for a, b in zip(predictions, truth)),
        "correct_abstentions": sum(a is None and b is None for a, b in zip(predictions, truth)),
        "conflicts_detected": conflicts,
        "secrets_exposed": exposed,
        "cross_program_associations": mixed,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", action="store_true")
    print(json.dumps(evaluate(baseline=parser.parse_args().baseline), indent=2, sort_keys=True))
