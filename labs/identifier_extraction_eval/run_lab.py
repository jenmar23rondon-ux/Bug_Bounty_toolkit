"""CLI entry for the identifier-extraction adversarial lab."""

from __future__ import annotations

import json
import sys

from labs.identifier_extraction_eval.evaluate import compare


def main() -> int:
    report = compare()
    before = report["before"]["overall"]
    after = report["after"]["overall"]
    summary = {
        "before": before,
        "after": after,
        "format_recall_after": report["after"]["format_recall"],
        "secret_leaks_after": report["after"]["secret_leaks"],
        "types_preserved_after": report["after"]["types_preserved"],
        "locators_valid_after": report["after"]["locators_valid"],
        "rejected_ok_after": report["after"]["rejected_ok"],
        "elapsed_seconds_after": report["after"]["elapsed_seconds"],
        "rss_kb_after": report["after"]["rss_kb"],
        "delta_recall": after["recall"] - before["recall"],
        "delta_precision": after["precision"] - before["precision"],
        "delta_f1": after["f1"] - before["f1"],
    }
    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    if report["after"]["secret_leaks"] != 0:
        return 2
    if after["recall"] < before["recall"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
