# HTTP indicators and proof of impact

The native CORS, redirect and SQLi probes retain their bounded requests.
They do not promote an unreplicated observation to a confirmed finding.
Command flags stay compatible. The SQLi `--deep` group is 11 requests so the
boolean control can be repeated; `--bypass` adds at most 15 further payloads
and is off by default.

* CORS: an arbitrary Cookie plus a non-empty 2xx body does not establish private
  data or an attacker-origin browser read. `private_body_readable` remains false;
  reflected policy is a candidate. ACAC must be the case-sensitive value `true`.
  Truncated responses and server failures are inconclusive.
* Redirects: matching the injected hostname is recorded separately from causality.
  A server that always redirects to that host may ignore the parameter. Native
  probes require baseline and independent destination controls before promotion;
  they never follow the destination.
* SQLi: confirmed only when the boolean true and false responses differ, that
  same pair of bodies is observed again, and the baseline request between the
  pairs matches the first baseline (status, size, and body hash). A baseline
  that changes is **inconclusive** and is not confirmed. A first delta that
  does not reproduce is **inconclusive** and is not confirmed. Timing candidates
  still require at least 2500 ms **above** the measured baseline, not an
  absolute 2500 ms threshold. A delay, a SQL error, a UNION-shaped difference,
  or a DBMS fingerprint (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) stays a
  candidate. The fingerprint is stored on the check and never confirms by
  itself. An error that is not part of the repeated boolean proof stays a
  candidate. Invalid baselines stop the group. `--bypass` is explicit and
  capped at 15 packaged payloads (alternating case, comments, URL encoding,
  alternate whitespace). It does not extract data and cannot confirm. No
  extraction is added.

Legacy `classification` strings such as `VULNERABLE` describe header/Location
signals only. Consumers should use `finding_state`, `confirmed` and
`confirmation_gap` for the evidence verdict. Candidate does not mean safe, and
does not authorize reporting a confirmed vulnerability.

Regression fixtures use synthetic HTTP responses, including an analytics cookie
on public content, request counters, a 2 ms timing change and a constant external
redirect. These are targeted regressions, not real-world precision estimates.
No frozen benchmark labels or real-model quality claims are changed.

The existing information-disclosure v1/v2 and AI evidence-contract v2 components
already distinguish own/public/cross-actor data, suppress examples and request
echoes, minimize secrets, and reject invented model references or confirmations.
They were reused without reconstruction: 49 tests covering these paths passed.
This is mock/offline validation, not measurement of a real Ollama model.

[Linux measurement run 41118537804](https://github.com/jenmar23rondon-ux/Bug_Bounty_toolkit/actions/runs/41118537804)
evaluated base `d7973ef` and proposed `9441722`, including the aggregate-state fix. Frozen IDOR pipeline outcome
accuracy stayed 100% DEV (6), 84.44% FINAL (45), and 100% STRESS (6). These suites
do not measure CORS/SQLi/redirect precision; their unchanged results show no
observed IDOR regression. The targeted HTTP fixtures exercise those separate
proof-attribution failures. Snapshots for that revision came from that run; later
integration recalculates the shared results directory against the combined code.
