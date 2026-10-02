import pytest

from nginxtrace.findings.confidence import Confidence


def test_confidence_defines_low_medium_and_high() -> None:
    assert [confidence.value for confidence in Confidence] == [
        "low",
        "medium",
        "high",
    ]


def test_confidence_values_are_lowercase_strings() -> None:
    assert Confidence.MEDIUM == "medium"
    assert str(Confidence.HIGH) == "high"


def test_confidence_can_be_created_from_valid_value() -> None:
    assert Confidence("low") is Confidence.LOW


def test_confidence_rejects_invalid_value() -> None:
    with pytest.raises(ValueError):
        Confidence("meduim")
