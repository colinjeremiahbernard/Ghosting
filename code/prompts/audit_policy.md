# Deletion audit decision protocol

This protocol documents the deterministic agent's decision sequence. The runtime implementation is `code/main.py`; this file is an auditable specification, not a prompt sent to a hosted model.

1. Resolve the request email against the identity snapshot and audit history, using only identity changes at or before `audit_at`. Derive normalized email hashes for legacy hashed fields.
2. Classify the request text. Access, correction, portability, opt-out, and explicit non-deletion requests do not authorize destructive processing.
3. Read the deletion rules and evidence manifest. Parse each supported evidence file and associate observations by exact identifiers or trace-correlated lookups. Exclude observations captured or recorded after the audit cutoff.
4. For each attributable system/resource pair, use the latest grounded observation and apply the category treatment from the supplied rules. Distinguish retained security/legal records, redacted shared support context, tombstones, analytics attribution, and active data/restore paths.
5. Treat reported workflow status and successful operation events as claims, not proof. A remaining record or active recreation path creates a finding, policy-ordered remediation, and future verification step. Evidence-backed treated/retained records generate verification only.
6. Emit `NOT_APPLICABLE` with `[]` when deletion was not requested; otherwise choose `INCOMPLETE` if a prohibited record or recreation risk remains and `COMPLETE` only when observed evidence supports the required state.
7. Serialize findings, remediation, and verification in that phase order. Within each phase, sort by the operation order in `problem_statement.md`, then system and resource.

Optional screenshot OCR requires Pillow, `pytesseract`, and a Tesseract executable. Without them, OCR-only screenshot observations are unavailable and the report must not claim OCR coverage.
