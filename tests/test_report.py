import pytest

from malforge.report.generator import classify, risk_score


def test_risk_score_weights() -> None:
    assert risk_score(0.0, 0, 0) == 0.0
    assert risk_score(10.0, 0, 0) == 60.0
    assert risk_score(0.0, 3, 1) == 23.0


def test_risk_score_caps_each_component() -> None:
    assert risk_score(0.0, 50, 0) == 30.0
    assert risk_score(0.0, 0, 50) == 10.0
    assert risk_score(10.0, 50, 50) == 100.0


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, "BENIGN"), (24.9, "BENIGN"), (25, "SUSPICIOUS"), (59.9, "SUSPICIOUS"), (60, "MALICIOUS")],
)
def test_classify(score: float, expected: str) -> None:
    assert classify(score) == expected
