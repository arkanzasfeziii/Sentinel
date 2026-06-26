"""Custom exception hierarchy for Sentinel."""

from __future__ import annotations


class SentinelError(Exception):
    """Base exception."""


class ModuleError(SentinelError):
    """Module runtime error."""


class DependencyError(SentinelError):
    def __init__(self, package: str) -> None:
        super().__init__(f"Missing: {package}. Install with: pip install {package}")
