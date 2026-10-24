"""Reproducible sample and synthetic evaluation for the deletion audit agent."""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
import main  # noqa: E402


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def canonical(step: dict) -> str:
    return json.dumps(step, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def evaluate_sample() -> dict:
    expected = read_rows(ROOT / "dataset" / "sample_output.csv")
    predicted = read_rows(ROOT / "code" / "evaluation" / "predicted_sample.csv")
    if [r["case_id"] for r in expected] != [r["case_id"] for r in predicted]:
        raise AssertionError("sample rows or case ordering differ")
    n = len(expected)
    status_correct = sum(a["deletion_status"] == b["deletion_status"] for a, b in zip(expected, predicted))
    sequence_exact = 0
    expected_steps: Counter[str] = Counter()
    predicted_steps: Counter[str] = Counter()
    expected_fields: Counter[tuple[str, str, str]] = Counter()
    predicted_fields: Counter[tuple[str, str, str]] = Counter()
    expected_n = predicted_n = 0
    for a, b in zip(expected, predicted):
        ea, pa = json.loads(a["steps_json"]), json.loads(b["steps_json"])
        if [canonical(s) for s in ea] == [canonical(s) for s in pa]:
            sequence_exact += 1
        for case_id, steps, step_counter, field_counter in (
            (a["case_id"], ea, expected_steps, expected_fields),
            (b["case_id"], pa, predicted_steps, predicted_fields),
        ):
            for step in steps:
                step_counter[case_id + "|" + canonical(step)] += 1
                for key, value in step.items():
                    field_counter[(case_id, key, str(value))] += 1
        expected_n += len(ea)
        predicted_n += len(pa)
    exact_steps = sum((expected_steps & predicted_steps).values())
    exact_fields = sum((expected_fields & predicted_fields).values())
    expected_field_n = sum(expected_fields.values())
    predicted_field_n = sum(predicted_fields.values())
    return {
        "cases": n,
        "status_correct": status_correct,
        "status_accuracy": status_correct / n if n else 1,
        "sequence_exact_cases": sequence_exact,
        "sequence_accuracy": sequence_exact / n if n else 1,
        "expected_steps": expected_n,
        "predicted_steps": predicted_n,
        "exact_step_matches": exact_steps,
        "step_precision": exact_steps / predicted_n if predicted_n else 0,
        "step_recall": exact_steps / expected_n if expected_n else 1,
        "expected_fields": expected_field_n,
        "predicted_fields": predicted_field_n,
        "exact_field_matches": exact_fields,
        "field_precision": exact_fields / predicted_field_n if predicted_field_n else 0,
        "field_recall": exact_fields / expected_field_n if expected_field_n else 1,
    }


def evaluate_custom() -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []
    # 1. A non-deletion privacy request is not authorized for destructive work.
    request = {"case_id": "synthetic_optout", "email": "case@example.invalid", "audit_at": "2026-10-01T00:00:00Z", "request_text": "Please opt out of marketing; do not delete my account."}
    status, steps = main.audit_case(request, [], {}, {})
    results.append(("non-deletion opt-out", status == "NOT_APPLICABLE" and steps == [], f"status={status}, steps={len(steps)}"))

    # 2. Historical email aliases remain attributable after an address change.
    subject = main.Subject("synthetic-user", {"old@example.invalid", "New Name"})
    fields = {"email": "old@example.invalid", "row_id": "r-1"}
    alias_ok = main._alias_match(fields, subject, "new@example.invalid")
    results.append(("historical identifier resolution", alias_ok, f"matched={alias_ok}"))

    # 3. A live connector produces a finding, stop action, then future check.
    subject = main.Subject("synthetic-user", {"case@example.invalid"})
    artifact = main.Artifact("synthetic-evidence", "synthetic", None, "integration_service", "DATA_FLOW", "flow_9001", {"user_id": "synthetic-user", "enabled": True}, None)
    request = {"case_id": "synthetic_flow", "email": "case@example.invalid", "audit_at": "2026-10-01T00:00:00Z", "request_text": "Delete my account and personal data."}
    status, steps = main.audit_case(request, [artifact], {"synthetic-user": subject}, {"case@example.invalid": "synthetic-user"})
    operations = [step["operation"] for step in steps]
    flow_ok = status == "INCOMPLETE" and operations == ["REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"]
    results.append(("active sync remediation order", flow_ok, f"status={status}, operations={operations}"))
    return results


def main_cli() -> None:
    print(json.dumps({"sample": evaluate_sample(), "custom_cases": evaluate_custom()}, indent=2))
    failures = [name for name, ok, _ in evaluate_custom() if not ok]
    if failures:
        raise SystemExit("custom evaluation failed: " + ", ".join(failures))


if __name__ == "__main__":
    main_cli()
