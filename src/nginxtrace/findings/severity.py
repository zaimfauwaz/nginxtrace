from enum import StrEnum

class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

def meets_threshold(severity: Severity, threshold: Severity) -> bool:
    levels = list(Severity)
    return levels.index(severity) >= levels.index(threshold)