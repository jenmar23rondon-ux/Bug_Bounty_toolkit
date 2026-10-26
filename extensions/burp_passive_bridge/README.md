# Minimal Burp passive extension

Load `BurpExtender.py` with the legacy Python/Jython 2.7 Extender API on POSIX.
Only a context-menu factory is registered. Nothing scans, listens, sends or replays.
Selected messages alone are exported after project/scope selection and explicit review.

See [installation, protocol, privacy and limitations](../../docs/burp-passive-bridge.md).
The output contains credentials: never put it in Git or attach it to a public report.
Burp is optional for the offline mock adapter and tests.
