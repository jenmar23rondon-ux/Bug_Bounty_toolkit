"""Loopback stored-XSS lifecycle lab.

Reuses ``bugbounty_toolkit.xss.stored_local.run_stored_local`` for the
write → store → render → browser chain. It does not reimplement that chain
and it does not modify DOM hooks.
"""

LAB_NAME = "stored-xss-lifecycle"
