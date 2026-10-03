import tomllib
from pathlib import Path

from nginxtrace.findings.severity import Severity
from nginxtrace.policy.models import Policy, Suppression
from nginxtrace.rules.registry import default_rules
from nginxtrace.utils.paths import UnsafePathError, allowed_base_dir, resolve_within

POLICY_KEYS = {"min_severity", "disable", "severity", "suppress"}
SUPPRESSION_KEYS = {"rule", "file", "line", "reason"}

class PolicyLoadError(ValueError):
    """Raised when loading or validating a policy file fails"""

def load_policy(file: Path) -> Policy:
    try:
        safe_file = resolve_within(file, allowed_base_dir())
    except UnsafePathError as err:
        raise PolicyLoadError(str(err)) from err

    try:
        data = tomllib.loads(safe_file.read_text(encoding="utf-8"))
    except OSError as err:
        raise PolicyLoadError(f"Could not read policy file {file}: {err}") from err
    except tomllib.TOMLDecodeError as err:
        raise PolicyLoadError(f"Invalid TOML in policy file {file}: {err}") from err

    unknown_keys = set(data) - POLICY_KEYS
    if unknown_keys:
        raise PolicyLoadError(f"Unknown policy keys: {', '.join(sorted(unknown_keys))}")

    known_rule_ids = {rule.rule_id for rule in default_rules()}

    min_severity = None
    if "min_severity" in data:
        min_severity = parse_severity(data["min_severity"], "min_severity")

    disable = data.get("disable", [])
    if not isinstance(disable, list):
        raise PolicyLoadError("disable must be a list of rule IDs")

    severity = data.get("severity", {})
    if not isinstance(severity, dict):
        raise PolicyLoadError("severity must be a table of rule IDs to severities")

    suppress = data.get("suppress", [])
    if not isinstance(suppress, list):
        raise PolicyLoadError("suppress must be an array of tables")

    return Policy(
        min_severity=min_severity,
        disabled_rules=frozenset(
            check_rule_id(rule_id, "disable", known_rule_ids) for rule_id in disable
        ),
        severity_overrides={
            check_rule_id(rule_id, "severity", known_rule_ids): parse_severity(value, f"severity.{rule_id}")
            for rule_id, value in severity.items()
        },
        suppressions=tuple(
            parse_suppression(entry, index, known_rule_ids)
            for index, entry in enumerate(suppress, start=1)
        ),
    )

def parse_severity(value: object, where: str) -> Severity:
    try:
        return Severity(value)
    except ValueError as err:
        raise PolicyLoadError(f"Invalid severity {value!r} in {where}") from err

def check_rule_id(rule_id: object, where: str, known_rule_ids: set[str]) -> str:
    if not isinstance(rule_id, str) or rule_id not in known_rule_ids:
        raise PolicyLoadError(f"Unknown rule ID {rule_id!r} in {where}")
    return rule_id

def parse_suppression(entry: object, index: int, known_rule_ids: set[str]) -> Suppression:
    where = f"suppress entry {index}"

    if not isinstance(entry, dict):
        raise PolicyLoadError(f"{where} must be a table")

    unknown_keys = set(entry) - SUPPRESSION_KEYS
    if unknown_keys:
        raise PolicyLoadError(f"Unknown keys in {where}: {', '.join(sorted(unknown_keys))}")

    file = entry.get("file")
    if not isinstance(file, str) or not file:
        raise PolicyLoadError(f"{where} needs a file")

    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise PolicyLoadError(f"{where} needs a reason")

    line = entry.get("line")
    if line is not None and not isinstance(line, int):
        raise PolicyLoadError(f"line in {where} must be a number")

    return Suppression(
        rule_id=check_rule_id(entry.get("rule"), where, known_rule_ids),
        file=file,
        reason=reason,
        line=line,
    )
