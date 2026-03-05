"""
CoreRecon Error Classification
Provides typed error classes so module failures are explicit and categorized.
"""
from dataclasses import dataclass, field
from typing import Optional


class SoftFailError(Exception):
    """
    Module failed but the overall scan can continue.
    Examples: timeout on external API, rate limit, empty response.
    The module returns a failure record; other modules proceed normally.
    """
    def __init__(self, message: str, module: str, reason: str = ""):
        super().__init__(message)
        self.module = module
        self.reason = reason or message


class HardFailError(Exception):
    """
    Scan cannot meaningfully continue.
    Examples: domain does not exist (NXDOMAIN), invalid input.
    The full scan is aborted with an appropriate error response.
    """
    def __init__(self, message: str, code: str = "SCAN_FAILED"):
        super().__init__(message)
        self.code = code


@dataclass
class FailureRecord:
    """Structured failure metadata attached to module result on soft failure."""
    module: str
    status: str = "SOFT_FAIL"
    reason: str = ""
    error_type: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "error_type": self.error_type,
        }
