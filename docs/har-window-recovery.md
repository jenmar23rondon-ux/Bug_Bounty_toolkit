# Recovering valid observations after damaged HAR entries

This describes the default importer fix in PR #93. The later, separately bounded
end-to-end research profile is documented in
[stress-evidence-recovery.md](stress-evidence-recovery.md); its new STRESS results
supersede the historical limitations below. Default discovery limits remain unchanged.

## Reproduction and acceptance criteria

On main `bd99e94`, prepend 300 HAR entries with a missing request URL to a
valid owner/actor capture. The end-to-end importer rejects the entire file
with `entries_over_limit`, even though only the valid entries would consume
the 256 accepted-observation budget. The graph regression was run before the
fix and reproduced that exception.

Acceptance criteria established for this fix:

- Recover the valid entries using the existing independent-window mode.
- Preserve original source commitments and HAR entry locators.
- Reject more than 256 accepted observations across the capture set.
- Preserve strict rejection and the default 32-entry import cap.
- Preserve declared-entry, file-byte, JSON-depth and graph-size limits.
- Send no requests and confirm no vulnerabilities.

## Change and measured result

Independent-window import scans the declared entries within the existing HAR
hard ceiling of 4096. Invalid entries retain their rejection reasons but do
not consume the accepted-observation budget. Graph construction and handoff
indexing continue to enforce the existing 256 accepted-capture ceiling.
This is bounded recovery, not truncation or repair of damaged exchanges.

| Synthetic regression | Before | After |
|---|---|---|
| 300 invalid entries followed by 2 valid observations | Whole-file rejection | 2 accepted, 300 rejected |
| Original valid-entry locators | No output | `/log/entries[300]`, `/log/entries[301]` |
| Full frozen E2E fixture with 300 invalid entries prepended | Import blocked | Reviewable cases retained |
| 257 valid observations | Rejected | Rejected |
| Strict import with invalid entries | Rejected | Rejected |
| Network requests / automatic confirmations | 0 / 0 | 0 / 0 |

Regression commands:

```bash
python -m unittest tests.test_object_relationships tests.test_har_partial_recovery tests.test_idor_e2e_research tests.test_object_handoff -q
python labs/independent_research_eval/build_corpus.py --check
```

## Historical benchmark limitations

Frozen independent DEV/FINAL/STRESS outcomes remain 6/6, 38/45 and 3/6.
No frozen input, manifest or label changes. Snapshots are regenerated to bind
them to the changed source, not to claim an improved historical score.

The remaining STRESS cases are not solved by this fix:

- S01 has 302 valid entries and still exceeds the accepted-observation budget.
- S03 exceeds the JSON-body depth guard; its owner observation is rejected.
- S04 retains two valid exchanges, but sensitive identifier/kind filtering
  suppresses candidates involving the token-like resource names.

The limits and secret filters require separate designs and adversarial tests;
they must not be relaxed merely to improve these frozen scores. The corpus is
a reused regression set, not a blinded independent evaluation or a measurement
of real bug-bounty performance. Real model and human-study metrics remain
NOT_MEASURED. Version 0.2.2 is unchanged.
