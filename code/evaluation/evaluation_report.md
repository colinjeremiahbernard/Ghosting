# Evaluation report

## Public sample

The agent was run against `dataset/sample_deletion_requests.csv` and compared with the participant-facing `dataset/sample_output.csv`. Evaluation ignores JSON object-key order and whitespace. It matches full step objects as a multiset for step precision/recall; field precision/recall match `(case, field, value)` tuples as multisets. Sequence accuracy requires the entire ordered step array for a case to match.

| Metric | Result |
|---|---:|
| Cases | 32 |
| Case-level deletion-status accuracy | 32/32 (100.0%) |
| Expected / predicted steps | 193 / 155 |
| Exact step matches | 90 |
| Step precision / recall | 58.1% / 46.6% |
| Expected / predicted fields | 1,351 / 1,085 |
| Exact field-value matches | 1,058 |
| Field precision / recall | 97.5% / 78.3% |
| Exact ordered sequence cases | 0/32 (0.0%) |

The sample proves status classification on this small public set, but step coverage is materially lower. In particular, several expected point-in-time read-back checks refer to resources without an identity-bearing value in the record. The pipeline conservatively avoids assigning such ambiguous anonymous records to a person. Some future verification steps also lack a directly observed absence result, and should remain uncited in an incomplete plan. These gaps explain why perfect status accuracy does not imply complete step accuracy.

## Additional synthetic evaluation cases

`python3 code/evaluation/evaluate.py` executes these three independent cases. They use synthetic identifiers and do not hardcode challenge case labels.

1. **Opt-out with explicit non-deletion** — marketing opt-out plus “do not delete” must return `NOT_APPLICABLE` and no steps. **Passed.**
2. **Historical email resolution** — a record containing an old address must match a subject whose identity history includes that alias. **Passed.**
3. **Active sync remediation order** — an enabled connector must yield `REPORT_ACTIVE_DATA_FLOW`, `DISABLE_DATA_FLOW`, then `VERIFY_DATA_FLOW_DISABLED`, with status `INCOMPLETE`. **Passed.**

## Failures found and improvements made

- Initial parsing did not correlate split log start/completion rows. Trace/request identifiers are now grouped so the completed lookup carries its resource and result.
- Support replica contact queries and hashed analytics contact lookups were not recognized as deletion-relevant secondary identifiers. Category mapping now classifies them and applies deletion policy.
- Backup restore candidates can be risks even when a log does not label the state as “restore”; eligibility and deletion-block fields are evaluated explicitly.
- Explicit “do not delete” language could be misclassified because it contained a delete verb. Negative deletion language now overrides destructive intent.
- Policy treatment is loaded from `deletion_rules.csv` and governs the proposed delete, redact, or anonymize action.
- The remaining sample errors are mostly missing or ambiguous record associations and incomplete evidence citations. A later improvement should use a calibrated OCR path for screenshots and stronger, evidence-backed links between point-in-time read-backs and identity history. OCR is optional and unavailable if its external engine is not installed.

## Reproduce

```bash
python3 code/main.py --input dataset/sample_deletion_requests.csv --output code/evaluation/predicted_sample.csv
python3 code/evaluation/evaluate.py
```
