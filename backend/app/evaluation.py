"""Offline metrics for labeled scam-analysis predictions."""

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import TypedDict


EXPECTED_LABELS = {"SCAM", "NOT_SCAM"}
PREDICTION_LABELS = {"HIGH_RISK", "SUSPICIOUS", "LOW_RISK", "INSUFFICIENT_DATA"}
PREDICTION_TO_CLASS = {
    "HIGH_RISK": "SCAM",
    "SUSPICIOUS": "SCAM",
    "LOW_RISK": "NOT_SCAM",
    "INSUFFICIENT_DATA": "UNRESOLVED",
}


class EvaluationRecord(TypedDict):
    case_id: str
    expected: str
    predicted: str


def calculate_metrics(records: Iterable[EvaluationRecord]) -> dict[str, object]:
    matrix = {
        actual: {predicted: 0 for predicted in ("SCAM", "NOT_SCAM", "UNRESOLVED")}
        for actual in ("SCAM", "NOT_SCAM")
    }
    count = 0
    for record in records:
        expected = record["expected"]
        predicted = record["predicted"]
        if expected not in EXPECTED_LABELS:
            raise ValueError(f"Unsupported expected label for {record['case_id']}")
        if predicted not in PREDICTION_LABELS:
            raise ValueError(f"Unsupported prediction for {record['case_id']}")
        matrix[expected][PREDICTION_TO_CLASS[predicted]] += 1
        count += 1
    if count == 0:
        raise ValueError("Evaluation input contains no labeled predictions")

    true_positive = matrix["SCAM"]["SCAM"]
    false_positive = matrix["NOT_SCAM"]["SCAM"]
    false_negative = matrix["SCAM"]["NOT_SCAM"] + matrix["SCAM"]["UNRESOLVED"]
    actual_scams = true_positive + false_negative
    return {
        "cases": count,
        "scam_precision": (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        ),
        "scam_recall": true_positive / actual_scams if actual_scams else 0.0,
        "false_negative_rate": false_negative / actual_scams if actual_scams else 0.0,
        "confusion_matrix": matrix,
        "unresolved_is_counted_as_false_negative": True,
    }


def read_predictions(path: Path) -> list[EvaluationRecord]:
    records: list[EvaluationRecord] = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                case_id = record["case_id"]
                expected = record["expected"]
                predicted = record["predicted"]
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise ValueError(
                    f"Invalid evaluation record on line {line_number}"
                ) from error
            if not all(isinstance(value, str) for value in (case_id, expected, predicted)):
                raise ValueError(f"Invalid evaluation record on line {line_number}")
            records.append(
                {"case_id": case_id, "expected": expected, "predicted": predicted}
            )
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("predictions", type=Path, help="UTF-8 JSONL with labels and predictions")
    arguments = parser.parse_args()
    print(json.dumps(calculate_metrics(read_predictions(arguments.predictions)), indent=2))


if __name__ == "__main__":
    main()
