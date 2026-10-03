"""Native Kingfisher secret detection, validation, and revocation.

Install with ``uv add kingfisher-secret-scanner``; import as ``kingfisher_sdk``.
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
Source and examples: https://github.com/mongodb/kingfisher
"""
from ._native import __version__
from .core import Finding, shannon_entropy
from .rules import Rules
from .scanner import CancellationToken, Scanner
from .validation import Validator, ValidationResult
from .revocation import Revoker, RevocationResult

__all__ = ["__version__", "Finding", "shannon_entropy", "Rules", "Scanner", "CancellationToken",
           "Validator", "ValidationResult", "Revoker", "RevocationResult"]
