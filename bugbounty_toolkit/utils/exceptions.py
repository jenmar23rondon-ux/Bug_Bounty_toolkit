from __future__ import annotations


class ToolkitError(Exception):
    """Base exception for user-facing toolkit failures."""


class ScopeError(ToolkitError):
    """Raised when a target is outside authorized scope."""


class RequestBuildError(ToolkitError):
    """Raised when a request cannot be built from user input."""


class ExternalToolError(ToolkitError):
    """Raised when an external tool cannot run successfully."""
