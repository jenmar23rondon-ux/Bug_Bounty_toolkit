"""CLI for the review-only investigation workflow lab: python -m labs.investigation_workflow_eval.run_lab"""

from __future__ import annotations

import json
import sys

from .metrics import evaluate


def main() -> int:
    result = evaluate()
    print(json.dumps(result, indent=2, sort_keys=True))
    m = result["metrics"]
    bad = (
        m["network_requests_sent"]
        or m["executions"]
        or m["auto_confirmations"]
        or m["ai_inventions_accepted"]
        or m["unauthorized_modifications"]
        or m["inconsistent_states"]
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
