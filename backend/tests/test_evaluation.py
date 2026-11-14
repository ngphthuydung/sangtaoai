import pytest

from app.evaluation import calculate_metrics, read_predictions


def test_scam_metrics_count_unresolved_as_false_negative():
    result = calculate_metrics(
        [
            {"case_id": "scam-hit", "expected": "SCAM", "predicted": "HIGH_RISK"},
            {"case_id": "scam-review", "expected": "SCAM", "predicted": "INSUFFICIENT_DATA"},
            {"case_id": "legitimate-hit", "expected": "NOT_SCAM", "predicted": "LOW_RISK"},
            {"case_id": "false-alarm", "expected": "NOT_SCAM", "predicted": "SUSPICIOUS"},
        ]
    )

    assert result["cases"] == 4
    assert result["scam_precision"] == 0.5
    assert result["scam_recall"] == 0.5
    assert result["false_negative_rate"] == 0.5
    assert result["false_positive_rate"] == 0.5
    assert result["insufficient_data_cases"] == 1
    assert result["confusion_matrix"] == {
        "SCAM": {"SCAM": 1, "NOT_SCAM": 0, "UNRESOLVED": 1},
        "NOT_SCAM": {"SCAM": 1, "NOT_SCAM": 1, "UNRESOLVED": 0},
    }


def test_evaluation_reports_zero_false_positive_rate_without_legitimate_cases():
    result = calculate_metrics(
        [{"case_id": "scam", "expected": "SCAM", "predicted": "HIGH_RISK"}]
    )

    assert result["false_positive_rate"] == 0.0
    assert result["insufficient_data_cases"] == 0


@pytest.mark.parametrize(
    "records",
    [
        [],
        [{"case_id": "bad-label", "expected": "MAYBE", "predicted": "LOW_RISK"}],
        [{"case_id": "bad-prediction", "expected": "SCAM", "predicted": "UNKNOWN"}],
    ],
)
def test_evaluation_rejects_empty_or_unknown_labels(records):
    with pytest.raises(ValueError):
        calculate_metrics(records)


def test_evaluation_reads_only_labeled_predictions(tmp_path):
    source = tmp_path / "predictions.jsonl"
    source.write_text(
        '{"case_id":"case-1","expected":"SCAM","predicted":"SUSPICIOUS"}\n',
        encoding="utf-8",
    )

    assert read_predictions(source) == [
        {"case_id": "case-1", "expected": "SCAM", "predicted": "SUSPICIOUS"}
    ]
