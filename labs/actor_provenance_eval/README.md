# Actor provenance offline evaluation

See `docs/actor-session-provenance.md` for audit, semantics and commands.
`corpus.py` freezes eleven scenarios. Canary credential values are generated only in
memory. Baseline is the existing engine's lack of actor declarations; expected account
relations are human declarations, and contradictory relations must abstain.
No benchmark reads credentials from disk or sends HTTP.
