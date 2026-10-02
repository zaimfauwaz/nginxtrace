from enum import StrEnum


class Confidence(StrEnum):
    """How certain a static rule is that a pattern represents the issue.

    Ordered from least to most certain, mirroring ``Severity``.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
