"""Compatibility exports for existing ffuf wordlist call sites."""

from .wordlist_manager import preview_wordlist, require_wordlist

__all__ = ["preview_wordlist", "require_wordlist"]
