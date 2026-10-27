# Unified security-research triage

`bugbounty_toolkit/analysis/unified_security_triage.py`
(`unified-security-research-triage-v1`) extends the existing read-only dashboard
triage, evidence-gap planner, investigation workflow and dossier verifier into
one view for IDOR, XSS and disclosure candidates.

```bash
# Via dashboard (loopback only)
bbtk dashboard <program>
# GET /api/triage/security-research?family=idor|xss|disclosure|correlation|other
```

## Security states (read-only)

`idor_candidate` · `xss_candidate` · `disclosure_candidate` ·
`correlation_candidate` · `gap_blocked` · `integrity_blocked` · `duplicate` ·
`positive_control` · `negative_control` · `inconclusive` ·
`review_ready_dossier` · `other_candidate`

Each row carries `classification_reasons`, evidence status, missing controls /
blockers, uncertainty (`low|medium|high`), and optional dossier summary.
`finding_confirmed` is always `false` in this view; `ai_may_confirm` is always
`false`. Session data and executable HTML are excluded by construction.

## Ranking (not invented severity)

1. Review-ready dossiers with valid evidence and complete controls
2. Correlation / IDOR / XSS / disclosure candidates with usable evidence
3. Gap / integrity blockers
4. Inconclusive, duplicates, then pos/neg controls
5. Lower uncertainty first; stable candidate id as tie-break

## Forbidden actions

Extends dashboard `FORBIDDEN_ACTIONS` with `exploit`, `run_exploit`,
`send_payload`, `ai_approve_finding`, `ai_confirm_vulnerability`,
`show_session_data`, `render_executable_html`.
