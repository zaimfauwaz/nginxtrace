from pathlib import Path

import pytest

from nginxtrace.findings.severity import Severity
from nginxtrace.policy.loader import PolicyLoadError, load_policy
from nginxtrace.policy.models import Suppression


def write_policy(tmp_path: Path, text: str) -> Path:
    policy_file = tmp_path / "nginxtrace.toml"
    policy_file.write_text(text, encoding="utf-8")
    return policy_file


def test_load_policy_reads_every_section(tmp_path: Path) -> None:
    policy_file = write_policy(
        tmp_path,
        'min_severity = "medium"\n'
        'disable = ["NGX-PROXY-ERR-001"]\n'
        "\n"
        "[severity]\n"
        '"NGX-MAP-001" = "high"\n'
        "\n"
        "[[suppress]]\n"
        'rule = "NGX-SECRET-001"\n'
        'file = "nginx.conf"\n'
        "line = 7\n"
        'reason = "Blocked at the CDN"\n',
    )

    policy = load_policy(policy_file)

    assert policy.min_severity == Severity.MEDIUM
    assert policy.disabled_rules == frozenset({"NGX-PROXY-ERR-001"})
    assert policy.severity_overrides == {"NGX-MAP-001": Severity.HIGH}
    assert policy.suppressions == (
        Suppression("NGX-SECRET-001", "nginx.conf", "Blocked at the CDN", line=7),
    )


def test_load_policy_accepts_empty_file(tmp_path: Path) -> None:
    policy = load_policy(write_policy(tmp_path, ""))

    assert policy.min_severity is None
    assert policy.suppressions == ()


def test_load_policy_accepts_suppression_without_line(tmp_path: Path) -> None:
    policy = load_policy(write_policy(
        tmp_path,
        '[[suppress]]\nrule = "NGX-MAP-001"\nfile = "nginx.conf"\nreason = "Accepted"\n',
    ))

    assert policy.suppressions[0].line is None


@pytest.mark.usefixtures("allow_repository")
def test_load_policy_example_file_is_valid() -> None:
    example = Path(__file__).parent.parent.parent / "examples" / "nginxtrace.toml"

    policy = load_policy(example)

    assert policy.suppressions[0].rule_id == "NGX-SECRET-001"


@pytest.mark.parametrize(
    ("text", "message"),
    (
        ('min_severity = "urgent"\n', r"Invalid severity 'urgent' in min_severity"),
        ('disable = ["NGX-NOPE-001"]\n', r"Unknown rule ID 'NGX-NOPE-001' in disable"),
        ('disable = "NGX-MAP-001"\n', r"disable must be a list of rule IDs"),
        ('[severity]\n"NGX-MAP-001" = "huge"\n', r"Invalid severity 'huge' in severity.NGX-MAP-001"),
        ('[severity]\n"NGX-NOPE-001" = "high"\n', r"Unknown rule ID 'NGX-NOPE-001' in severity"),
        ('unknown = 1\n', r"Unknown policy keys: unknown"),
        ('[[suppress]]\nrule = "NGX-MAP-001"\nfile = "nginx.conf"\n', r"suppress entry 1 needs a reason"),
        ('[[suppress]]\nrule = "NGX-MAP-001"\nfile = "nginx.conf"\nreason = "  "\n', r"suppress entry 1 needs a reason"),
        ('[[suppress]]\nrule = "NGX-MAP-001"\nreason = "Accepted"\n', r"suppress entry 1 needs a file"),
        ('[[suppress]]\nfile = "nginx.conf"\nreason = "Accepted"\n', r"Unknown rule ID None in suppress entry 1"),
        ('[[suppress]]\nrule = "NGX-MAP-001"\nfile = "a"\nreason = "b"\nline = "7"\n', r"line in suppress entry 1 must be a number"),
        ('[[suppress]]\nrule = "NGX-MAP-001"\nfile = "a"\nreason = "b"\nlines = 7\n', r"Unknown keys in suppress entry 1: lines"),
        ("min_severity = \n", r"Invalid TOML in policy file"),
    ),
)
def test_load_policy_rejects_invalid_policy(
        tmp_path: Path,
        text: str,
        message: str,
) -> None:
    policy_file = write_policy(tmp_path, text)

    with pytest.raises(PolicyLoadError, match=message):
        load_policy(policy_file)


def test_load_policy_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(PolicyLoadError, match=r"Could not read policy file"):
        load_policy(tmp_path / "missing.toml")


def test_load_policy_rejects_path_outside_base_dir(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside_file = write_policy(tmp_path, "")
    monkeypatch.setenv("NGINXTRACE_BASE_DIR", str(allowed))

    with pytest.raises(PolicyLoadError, match=r"Path is outside the allowed directory"):
        load_policy(outside_file)
