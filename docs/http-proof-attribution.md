# HTTP indicators and proof of impact

The native CORS, redirect and SQLi probes retain their bounded requests and
candidate evidence. They no longer promote an unreplicated observation to a
confirmed finding. Existing command signatures and request-group sizes remain.

* CORS: an arbitrary Cookie plus a non-empty 2xx body does not establish private
  data or an attacker-origin browser read. `private_body_readable` remains false;
  reflected policy is a candidate. ACAC must be the case-sensitive value `true`.
  Truncated responses and server failures are inconclusive.
* Redirects: matching the injected hostname is recorded separately from causality.
  A server that always redirects to that host may ignore the parameter. Native
  probes require baseline and independent destination controls before promotion;
  they never follow the destination.
* SQLi: timing candidates require at least 2500 ms **above** the measured baseline,
  not merely crossing an absolute 2500 ms threshold. Even a large delay, boolean
  body difference or UNION-shaped difference remains a candidate until stable
  repeated controls and independent execution proof exist. Invalid baselines stop
  the group. No extraction is added.

Legacy `classification` strings such as `VULNERABLE` describe header/Location
signals only. Consumers should use `finding_state`, `confirmed` and
`confirmation_gap` for the evidence verdict. Candidate does not mean safe, and
does not authorize reporting a confirmed vulnerability.

Regression fixtures use synthetic HTTP responses, including an analytics cookie
on public content, request counters, a 2 ms timing change and a constant external
redirect. These are targeted regressions, not real-world precision estimates.
No frozen benchmark labels or real-model quality claims are changed.
