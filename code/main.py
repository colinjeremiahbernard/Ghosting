"""Evidence-grounded privacy deletion audit pipeline.

The pipeline is deterministic and local-only. It builds identity histories and an
evidence index from the participant-facing files, reconstructs each case at its
audit cutoff, then serializes policy-ordered findings, actions, and checks.
"""
from __future__ import annotations

import argparse
import csv
from functools import lru_cache
import hashlib
import importlib
import json
import re
import sqlite3
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
RULE_PRIORITY = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
SYSTEM_BY_COLLECTION = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "product_telemetry": ("telemetry_service", "PRODUCT_TELEMETRY"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
    "email_delivery_logs": ("notification_service", "EMAIL_DELIVERY_LOG"),
}
SUPPORTED_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
    "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
    "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "DATA_FLOW",
}


def parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def iso_time(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def normalize_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def normalize_phone(value: str) -> str:
    return re.sub(r"\D", "", value)


@lru_cache(maxsize=32)
def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def load_policy_actions() -> dict[str, str]:
    """Read the policy's required action for each data category."""
    return {
        row["data_category"].strip().upper(): row["required_action"].strip().upper()
        for row in read_csv(DATASET / "deletion_rules.csv")
    }


def flatten_values(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out.append(str(k))
            out.extend(flatten_values(v))
    elif isinstance(value, (list, tuple)):
        for item in value:
            out.extend(flatten_values(item))
    elif value is not None:
        out.append(str(value))
    return out


@dataclass
class Artifact:
    evidence_id: str
    path: str
    captured_at: datetime | None
    system_id: str
    category: str
    resource_id: str
    fields: dict[str, Any]
    observed_at: datetime | None
    raw_text: str = ""

    @property
    def when(self) -> datetime | None:
        return self.observed_at or self.captured_at


@dataclass
class Subject:
    user_id: str
    aliases: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)


def _time_in_record(record: dict[str, Any], fallback: datetime | None) -> datetime | None:
    for key in ("observed_at", "event_time", "timestamp", "recorded_at", "updated_at", "indexed_at", "captured_at", "created_at", "generated_at"):
        t = parse_time(record.get(key))
        if t:
            return t
    return fallback


def _system_category(system: str, collection: str) -> tuple[str, str]:
    mapped = SYSTEM_BY_COLLECTION.get(collection.casefold())
    if mapped:
        return mapped
    table = collection.casefold()
    if table.startswith("customer_profiles") or table.startswith("account_profiles"):
        return "account_service", "USER_PROFILE"
    if table.startswith("search_documents") or table.startswith("customer_search"):
        return "search_service", "SEARCH_INDEX_ENTRY"
    if table.startswith("analytics") or table.startswith("customer_analytics"):
        return "analytics_platform", "ANALYTICS_PROFILE"
    if table.startswith("support") or table.startswith("ticket_attachments"):
        return "support_platform", "SUPPORT_ATTACHMENT" if "attachment" in table else "SUPPORT_MESSAGE"
    if system:
        sysname = system.casefold()
        if "account" in sysname or "identity" in sysname or "profile_service" in sysname:
            return ("identity_service", "ACCOUNT_TOMBSTONE") if "identity" in sysname else ("account_service", "USER_PROFILE")
        if "search" in sysname or "index" in sysname:
            return "search_service", "SEARCH_INDEX_ENTRY"
        if "analytics" in sysname:
            return "analytics_platform", "ANALYTICS_PROFILE"
        if "support" in sysname:
            return "support_platform", "SUPPORT_MESSAGE"
        if "export" in sysname:
            return "export_service", "USER_EXPORT"
        if "backup" in sysname or "restore" in sysname:
            return "backup_service", "BACKUP_ARCHIVE"
        if "security" in sysname:
            return "security_service", "SECURITY_AUDIT_LOG"
        if "integration" in sysname or "connector" in sysname:
            return "integration_service", "DATA_FLOW"
        if "marketing" in sysname:
            return "marketing_platform", "MARKETING_PROFILE"
        if "notification" in sysname:
            return "notification_service", "EMAIL_DELIVERY_LOG"
    return system or "unknown_system", "UNKNOWN"


def _records_from_json(obj: Any, evidence_id: str, path: str, captured: datetime | None) -> list[Artifact]:
    out: list[Artifact] = []

    def walk(node: Any, system: str = "", collection: str = "") -> None:
        if isinstance(node, dict):
            local_system = str(node.get("data_store") or node.get("system_id") or node.get("system") or node.get("source_system") or system)
            local_collection = str(node.get("collection") or node.get("collection_name") or collection)
            origin = str(node.get("origin") or node.get("source") or "")
            if not local_system and origin:
                local_system, _ = _system_category(origin, local_collection)
            if "service_exports" in node and isinstance(node["service_exports"], dict):
                for svc, data in node["service_exports"].items():
                    walk(data, svc, collection)
            if "snapshots" in node and isinstance(node["snapshots"], list):
                for snap in node["snapshots"]:
                    if isinstance(snap, dict):
                        walk(snap, str(snap.get("data_store", system)), str(snap.get("collection", collection)))
            if "records" in node and isinstance(node["records"], list):
                for rec in node["records"]:
                    if isinstance(rec, dict):
                        walk(rec, local_system, local_collection)
            rid = node.get("resource_id") or node.get("record_id") or node.get("_id")
            if rid:
                sys_id, category = _system_category(local_system, local_collection)
                fields = dict(node)
                # Expanded JSON payloads in relational exports are part of the record.
                for k, v in list(fields.items()):
                    if isinstance(v, str) and v[:1] in "{[":
                        try:
                            fields[k] = json.loads(v)
                        except json.JSONDecodeError:
                            pass
                out.append(Artifact(evidence_id, path, captured, sys_id, category, str(rid), fields, _time_in_record(node, captured), json.dumps(node, ensure_ascii=False)))
            for key, value in node.items():
                if key in {"service_exports", "snapshots", "records"}:
                    continue
                if isinstance(value, (dict, list)):
                    child_system, child_collection = system, collection
                    if key in SYSTEM_BY_COLLECTION:
                        child_system, child_collection = SYSTEM_BY_COLLECTION[key][0], key
                    elif key.endswith("_profiles") or key.endswith("_documents") or key.endswith("_events") or key.endswith("_jobs") or key.endswith("_logs"):
                        child_collection = key
                    walk(value, child_system, child_collection)
        elif isinstance(node, list):
            for item in node:
                walk(item, system, collection)

    walk(obj)
    return out


def _records_from_sql(path: Path, evidence_id: str, captured: datetime | None) -> list[Artifact]:
    out: list[Artifact] = []
    db = sqlite3.connect(":memory:")
    try:
        db.executescript(path.read_text(encoding="utf-8", errors="replace"))
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            if table == "snapshot_scope":
                continue
            cols = [r[1] for r in db.execute(f'PRAGMA table_info("{table}")')]
            for row in db.execute(f'SELECT * FROM "{table}"'):
                rec = dict(zip(cols, row))
                rid = rec.get("resource_id") or rec.get("record_id") or rec.get("_id")
                if not rid:
                    continue
                collection = str(rec.get("collection_name") or table)
                system = str(rec.get("origin_system") or rec.get("system_id") or "")
                sys_id, category = _system_category(system, collection)
                if category == "UNKNOWN":
                    sys_id, category = _system_category(system, table)
                if isinstance(rec.get("record_json"), str):
                    try:
                        nested = json.loads(rec["record_json"])
                        rec["record_json"] = nested
                    except json.JSONDecodeError:
                        pass
                out.append(
                    Artifact(
                        evidence_id, path.as_posix(), captured, sys_id, category,
                        str(rid), rec, _time_in_record(rec, captured),
                        json.dumps(rec, ensure_ascii=False, default=str),
                    )
                )
    except sqlite3.Error as e:
        print(f"Warning: could not read SQLite evidence {path.name}: {e}", file=sys.stderr)
    finally:
        db.close()
    return out


def _read_pdf(path: Path) -> str:
    """Extract PDF text, falling back when the preferred parser is unavailable."""
    try:
        pdfplumber = importlib.import_module("pdfplumber")
        with pdfplumber.open(path) as pdf:
            return "\n".join(page.extract_text() or "" for page in pdf.pages)
    except ImportError:
        try:
            pdf_reader = importlib.import_module("pypdf").PdfReader
            return "\n".join(page.extract_text() or "" for page in pdf_reader(str(path)).pages)
        except (ImportError, OSError, ValueError, RuntimeError):
            return ""
    except (OSError, ValueError, RuntimeError):
        try:
            pdf_reader = importlib.import_module("pypdf").PdfReader
            return "\n".join(page.extract_text() or "" for page in pdf_reader(str(path)).pages)
        except (ImportError, OSError, ValueError, RuntimeError):
            return ""


def _read_image(path: Path) -> str:
    """Use OCR when a supported engine is installed; screenshots remain optional evidence."""
    try:
        pytesseract = importlib.import_module("pytesseract")
        image = importlib.import_module("PIL.Image")
        return pytesseract.image_to_string(image.open(path))
    except (ImportError, OSError, RuntimeError, ValueError):
        return ""


RESOURCE_RE = re.compile(
    r"\b(?:account|search|analytics|support|export|data_flow|backup|"
    r"audit_record|tombstone|marketing|cache|telemetry|profile|flow|archive|"
    r"event|record)_\d+\b",
    re.I,
)
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*)=([^\s]+)")


def _text_records(raw: str, evidence_id: str, relpath: str, captured: datetime | None, origin: str) -> list[Artifact]:
    """Turn logs and document lines into resource-scoped evidence observations."""
    if not raw.strip():
        return []
    lines = raw.splitlines()
    resources = sorted(set(RESOURCE_RE.findall(raw)), key=str.casefold)
    if not resources:
        return []
    out: list[Artifact] = []
    stem = Path(relpath).stem.casefold()
    for resource in resources:
        related = [line for line in lines if resource.casefold() in line.casefold()]
        trace_ids = set(re.findall(r"(?:trace_id|requestId)=\"?([A-Za-z0-9_-]+)", "\n".join(related), re.I))
        if trace_ids:
            related = sorted(set(related + [line for line in lines if any(t in line for t in trace_ids)]))
        if not related:
            related = [raw]
        if Path(relpath).suffix.casefold() in {".pdf", ".png", ".jpg", ".jpeg", ".webp"}:
            # A resource label in a business document or screenshot is usually on
            # a different line/region from the person's identifiers. Keep the
            # complete artifact as context once its resource has been recognized.
            related = lines
        # Keep one resource observation per evidence item; all matching lines are
        # joined so a split start/completion lookup remains understandable.
        text = "\n".join(related)
        fields: dict[str, Any] = {"text": text}
        # The customer-account handover and similar exports use pipe-delimited
        # read-back records rather than JSON or key=value log entries.
        for line in related:
            parts = [p.strip() for p in line.split("|")]
            record_time = parts[0].lstrip("- ") if parts else ""
            if len(parts) >= 5 and parse_time(record_time):
                fields.update({
                    "observed_at": record_time,
                    "service": parts[1],
                    "system_id": parts[1],
                    "data_category": parts[3],
                    "evidence_state": parts[4],
                    "lookup_value": parts[5] if len(parts) > 5 else "",
                })
        for line in related:
            for key, value in KV_RE.findall(line):
                fields[key.casefold()] = value.strip('"\'')
            if line[:4].isdigit() and parse_time(line[:20] + "Z"):
                fields.setdefault("observed_at", line[:20] + "Z")
        service = str(fields.get("service", fields.get("function", fields.get("system_id", ""))))
        explicit_category = str(fields.get("data_category", fields.get("record_type", ""))).upper()
        if explicit_category in SUPPORTED_CATEGORIES:
            category = explicit_category
            system = service or origin
        elif "contact_lookup" in text.casefold() and "analytics" in (service + origin).casefold():
            category, system = "SECONDARY_IDENTIFIER", "analytics_platform"
        elif "contact_query" in text.casefold() or "legacy_contact_index" in text.casefold():
            category, system = "SECONDARY_IDENTIFIER", "support_platform"
        elif "attachment" in stem or resource.casefold().startswith("support_") and "attachment" in text.casefold():
            category = "SUPPORT_ATTACHMENT"
            system = "support_platform"
        elif "legal_retention" in stem:
            category, system = "LEGAL_HOLD_RECORD", "legal_service"
        elif "security_retention" in stem or resource.casefold().startswith("audit_record_"):
            category, system = "SECURITY_AUDIT_LOG", "security_service"
        else:
            origin_lower = origin.casefold()
            known_systems = (
                "account_service", "search_service", "analytics_platform", "support_platform",
                "export_service", "integration_service", "backup_service", "security_service",
                "marketing_platform", "notification_service",
            )
            system = service or next(
                (s for s in known_systems if s.split("_", maxsplit=1)[0] in origin_lower), origin
            )
            system, category = _system_category(system, stem)
        if resource.casefold().startswith("support_") and "attachment" in stem:
            category = "SUPPORT_ATTACHMENT"
        observed = _time_in_record(fields, captured)
        out.append(Artifact(evidence_id, relpath, captured, system or "unknown_system", category, resource, fields, observed, text))
    return out


def load_artifacts() -> tuple[list[Artifact], dict[str, dict[str, Any]], dict[str, datetime | None]]:
    manifest_rows = read_csv(DATASET / "evidence_files.csv")
    manifest = {r["file_id"]: r for r in manifest_rows}
    captures = {fid: parse_time(row.get("captured_at")) for fid, row in manifest.items()}
    artifacts: list[Artifact] = []
    text_artifacts: list[Artifact] = []
    for fid, row in manifest.items():
        path = DATASET / row["file_path"]
        captured = captures[fid]
        if not path.exists():
            continue
        suffix = path.suffix.casefold()
        if suffix == ".json":
            try:
                obj = json.loads(path.read_text(encoding="utf-8-sig"))
                artifacts.extend(_records_from_json(obj, fid, row["file_path"], captured))
            except (OSError, json.JSONDecodeError):
                continue
        elif suffix == ".sql":
            artifacts.extend(_records_from_sql(path, fid, captured))
        elif suffix == ".pdf":
            raw = _read_pdf(path)
            if raw.strip():
                text_artifacts.extend(_text_records(raw, fid, row["file_path"], captured, row.get("origin", "")))
        elif suffix in {".log", ".txt"}:
            raw = path.read_text(encoding="utf-8", errors="replace")
            text_artifacts.extend(_text_records(raw, fid, row["file_path"], captured, row.get("origin", "")))
        elif suffix in {".png", ".jpg", ".jpeg", ".webp"}:
            raw = _read_image(path)
            if raw.strip():
                text_artifacts.extend(_text_records(raw, fid, row["file_path"], captured, row.get("origin", "")))
    return artifacts + text_artifacts, manifest, captures


def _identity_subjects(audit_at: datetime) -> tuple[dict[str, Subject], dict[str, str]]:
    identities = read_csv(DATASET / "user_identities.csv")
    history = read_csv(DATASET / "user_audit_log.csv")
    by_id: dict[str, Subject] = {}
    email_to_user: dict[str, str] = {}
    for row in identities:
        uid = row["user_id"]
        subject = by_id.setdefault(uid, Subject(uid))
        updated = parse_time(row.get("updated_at"))
        if updated and updated <= audit_at:
            for key in ("name", "email", "phone", "email_hash"):
                value = row.get(key, "").strip()
                if value:
                    subject.aliases.add(value)
                    if key == "email":
                        email_to_user[normalize_email(value)] = uid
        # The current snapshot is also a resolution index when an older email maps
        # through audit history; values after audit_at are not included as aliases.
        current_email = row.get("email", "").strip()
        if current_email:
            email_to_user.setdefault(normalize_email(current_email), uid)
    for row in history:
        t = parse_time(row.get("event_time"))
        if t and t > audit_at:
            continue
        uid = row.get("user_id", "")
        subject = by_id.setdefault(uid, Subject(uid))
        field_name = row.get("field_name", "").casefold()
        for value in (row.get("old_value", ""), row.get("new_value", "")):
            val = value.strip()
            if val:
                subject.aliases.add(val)
                if field_name == "email":
                    email_to_user[normalize_email(val)] = uid
    for subject in by_id.values():
        for alias in list(subject.aliases):
            if "@" in alias:
                subject.hashes.add(hashlib.sha256(normalize_email(alias).encode("utf-8")).hexdigest())
    return by_id, email_to_user


def _request_subject(request: dict[str, str], subjects: dict[str, Subject], email_to_user: dict[str, str], audit_at: datetime) -> Subject:
    email = normalize_email(request.get("email", ""))
    uid = email_to_user.get(email, "")
    if not uid:
        for row in read_csv(DATASET / "user_audit_log.csv"):
            t = parse_time(row.get("event_time"))
            historical_emails = {
                normalize_email(row.get("old_value", "")),
                normalize_email(row.get("new_value", "")),
            }
            if (
                row.get("field_name", "").casefold() == "email"
                and t and t <= audit_at and email in historical_emails
            ):
                uid = row.get("user_id", "")
                break
    return subjects.get(uid, Subject(uid or ""))


DELETE_PATTERNS = [
    r"\bdelet(?:e|ed|ing|ion)\b", r"\beras(?:e|ed|ing|ure)\b", r"\bremov(?:e|ed|ing|al)\b",
    r"\bclose\b.{0,35}\baccount\b", r"\baccount\b.{0,35}\bclosed\b", r"\bwould like it closed\b",
    r"\bexclu[si][oó]n\b", r"\beliminar\b", r"\bborra(?:r|do)\b", r"\bapagar\b", r"\bexclus[aã]o\b",
    r"\bsuppression\b", r"\bsupprimer\b", r"\beffacer\b", r"\bforget me\b", r"\bprofile is gone\b",
    r"계정.{0,12}(?:삭제|탈퇴)|삭제.{0,12}계정", r"削除|消去|退会",
]
NON_DELETE_PATTERNS = [
    r"\baccess\s+request\b", r"\bcorrect\s+my\s+(?:email|address|phone|profile)\b", r"\bupdate\s+my\s+(?:email|address|phone|profile)\b",
    r"\bexport\s+my\s+data\b", r"\bdownload\s+my\s+data\b", r"\bopt\s*out\b", r"\bunsubscribe\b",
    r"\bdo\s+not\s+sell\b", r"\brectif(?:y|ication)\b", r"\bportability\b",
]


def authorizes_deletion(text: str) -> bool:
    s = normalize_text(text)
    if re.search(r"\b(?:not|don't|do not|never|would not|wouldn't)\b.{0,40}\b(?:delete|erase|remove|close)\b", s):
        return False
    if any(re.search(p, s, re.I) for p in NON_DELETE_PATTERNS):
        return False
    return any(re.search(p, s, re.I) for p in DELETE_PATTERNS)


def _alias_match(fields: dict[str, Any], subject: Subject, request_email: str) -> bool:
    vals = flatten_values(fields)
    norm_vals = {normalize_text(x) for x in vals if x}
    # Exact equality for names, emails, phone numbers, hashes, and user IDs avoids
    # false attribution from substrings or unrelated search results.
    for alias in subject.aliases:
        if normalize_text(alias) in norm_vals:
            return True
        if "@" in alias and normalize_email(alias) in {normalize_email(x) for x in vals}:
            return True
        if alias.startswith("+") and normalize_phone(alias) in {normalize_phone(x) for x in vals if normalize_phone(x)}:
            return True
    if request_email and normalize_email(request_email) in {normalize_email(x) for x in vals}:
        return True
    norm_hashes = {x.casefold() for x in vals}
    if subject.hashes & norm_hashes:
        return True
    if subject.user_id and subject.user_id.casefold() in {x.casefold() for x in vals}:
        return True
    blob = normalize_text(" ".join(vals))
    candidates = set(subject.aliases)
    if request_email:
        candidates.add(request_email)
    for candidate in candidates:
        token = normalize_text(candidate)
        if not token:
            continue
        if "@" in candidate or candidate.startswith("+") or re.fullmatch(r"[a-f0-9]{64}", candidate, re.I) or candidate == subject.user_id:
            if re.search(r"(?<![\w@.+-])" + re.escape(token) + r"(?![\w@.+-])", blob):
                return True
        elif len(token) > 5 and re.search(r"(?<!\w)" + re.escape(token) + r"(?!\w)", blob):
            return True
    return False


def _evidence_matches(
    artifacts: list[Artifact],
    subject: Subject,
    email: str,
    audit_at: datetime,
    linked_resource_ids: set[str] | None = None,
) -> list[Artifact]:
    matches: list[Artifact] = []
    for a in artifacts:
        if a.captured_at and a.captured_at > audit_at:
            continue
        if a.when and a.when > audit_at:
            continue
        if _alias_match(a.fields, subject, email) or (
            linked_resource_ids and a.resource_id in linked_resource_ids
        ):
            matches.append(a)
    return matches


def _activity_for_subject(subject: Subject, email: str, audit_at: datetime) -> list[dict[str, str]]:
    out = []
    for row in read_csv(DATASET / "system_activity.csv"):
        t = parse_time(row.get("event_time"))
        if t and t > audit_at:
            continue
        combined = normalize_text(" ".join(row.values()))
        has_user_id = bool(subject.user_id and normalize_text(subject.user_id) in combined)
        has_email = bool(normalize_email(email) and normalize_email(email) in combined)
        has_alias = any(normalize_text(a) in combined for a in subject.aliases if len(a) > 5)
        if has_user_id or has_email or has_alias:
            out.append(row)
    return out


def _direct_identifier_fields(a: Artifact, subject: Subject) -> list[str]:
    out = []
    aliases = {normalize_text(x) for x in subject.aliases if x and x != subject.user_id and "@" not in x and not x.startswith("+") and not re.fullmatch(r"[a-f0-9]{64}", x, re.I)}
    emails = {normalize_email(x) for x in subject.aliases if "@" in x}
    phones = {normalize_phone(x) for x in subject.aliases if x.startswith("+")}
    hashes = {x.casefold() for x in subject.hashes}
    direct_field_words = ("name", "email", "phone", "hash")
    for k, v in a.fields.items():
        if not any(word in str(k).casefold() for word in direct_field_words):
            continue
        vals = flatten_values(v)
        if any(normalize_text(x) in aliases or normalize_email(x) in emails or normalize_phone(x) in phones or x.casefold() in hashes for x in vals if x):
            out.append(k.casefold())
    # Direct fields in a free-text message/document are visible PII even if they are
    # not stored in a structured column.
    raw = normalize_text(a.raw_text)
    if raw and any(normalize_text(x) in raw for x in (aliases | emails | phones | hashes)):
        out.append("unstructured_pii")
    return out


def _record_state(a: Artifact, subject: Subject, audit_at: datetime) -> tuple[str, str] | None:
    category = a.category
    f = {str(k).casefold(): v for k, v in a.fields.items()}
    direct = _direct_identifier_fields(a, subject)
    hint = str(f.get("evidence_state", f.get("state", f.get("result", "")))).upper()
    if category == "USER_PROFILE" and (
        hint in {"NOT_FOUND", "ABSENT", "404"}
        or
        f.get("profile", object()) is None
        or str(f.get("status_code", f.get("http_status", ""))) == "404"
        or str(f.get("rows", "")) == "0"
    ):
        return "ABSENT", "VERIFY_RECORD_ABSENT"
    empty_rows_categories = {
        "SEARCH_INDEX_ENTRY", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE",
        "PRODUCT_TELEMETRY", "USER_EXPORT", "MARKETING_PROFILE",
    }
    if str(f.get("rows", "")) == "0" and category in empty_rows_categories:
        return "ABSENT", "VERIFY_RECORD_ABSENT"
    if category == "DATA_FLOW":
        enabled = str(f.get("enabled", f.get("active", hint))).casefold()
        if enabled in {"1", "true", "yes", "enabled", "active"}:
            return "ACTIVE", "REPORT_ACTIVE_DATA_FLOW"
        if hint in {"ACTIVE", "ENABLED"}:
            return "ACTIVE", "REPORT_ACTIVE_DATA_FLOW"
        return "DISABLED", "VERIFY_DATA_FLOW_DISABLED"
    if category == "BACKUP_ARCHIVE":
        allowed = str(f.get("restore_allowed", f.get("restore_permitted", hint))).casefold()
        eligible = str(f.get("eligible", "")).casefold()
        deletion_block = str(f.get("deletion_block", "")).casefold()
        if eligible in {"1", "true", "yes"} and deletion_block in {"0", "false", "no"}:
            return "ACTIVE", "REPORT_RESTORE_RISK"
        if allowed in {"1", "true", "yes", "allowed", "active"}:
            return "ACTIVE", "REPORT_RESTORE_RISK"
        if allowed in {"0", "false", "no", "blocked", "denied"}:
            return "BLOCKED", "VERIFY_RESTORE_BLOCKED"
        return None
    if category == "SECURITY_AUDIT_LOG":
        if hint in {"FOUND", "PRESENT", "RETAINED"} or str(f.get("rows", "")) == "1":
            return "PRESENT", "VERIFY_RECORD_PRESENT"
        retain_until = parse_time(f.get("retention_until"))
        if not retain_until or retain_until < audit_at:
            return None
        return "PRESENT", "VERIFY_RECORD_PRESENT"
    if category == "LEGAL_HOLD_RECORD":
        hold = str(f.get("legal_hold_active", f.get("hold_active", f.get("retention_reason", "")))).casefold()
        until = parse_time(f.get("retained_until")) or parse_time(f.get("hold_until"))
        if hold in {"1", "true", "yes", "active"} or (until and until >= audit_at):
            return "PRESENT", "VERIFY_RECORD_PRESENT"
        return None
    if category == "ACCOUNT_TOMBSTONE":
        direct_identifiers = [k for k in ("name", "full_name", "email", "phone", "email_hash") if f.get(k) not in (None, "", "null")]
        if direct_identifiers or direct:
            return "PRESENT", "REPORT_EXPOSED_PII"
        return "REDACTED", "VERIFY_RECORD_REDACTED"
    if category == "SUPPORT_ATTACHMENT":
        if hint in {"NOT_FOUND", "ABSENT", "DELETED"}:
            return "ABSENT", "VERIFY_RECORD_ABSENT"
        return "PRESENT", "REPORT_REMAINING_RECORD"
    if category == "SUPPORT_MESSAGE":
        # Keep shared support/order context; remove only the direct identifiers.
        if hint in {"REDACTED", "ANONYMIZED"}:
            return "REDACTED", "VERIFY_RECORD_REDACTED"
        if hint in {"IDENTIFIABLE", "EXPOSED_PII"}:
            return "PRESENT", "REPORT_EXPOSED_PII"
        if hint in {"NOT_FOUND", "ABSENT", "DELETED"}:
            return "ABSENT", "VERIFY_RECORD_ABSENT"
        return ("PRESENT", "REPORT_EXPOSED_PII") if direct else ("REDACTED", "VERIFY_RECORD_REDACTED")
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if hint in {"ANONYMIZED", "ANONYMOUS"}:
            return "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"
        if hint in {"IDENTIFIABLE", "EXPOSED_PII"}:
            return "PRESENT", "REPORT_EXPOSED_PII"
        if hint in {"NOT_FOUND", "ABSENT", "DELETED"}:
            return "ABSENT", "VERIFY_RECORD_ABSENT"
        ref = str(f.get("customer_reference", f.get("user_id", "")) or "")
        attributed = bool(direct or (subject.user_id and ref == subject.user_id))
        if not attributed:
            return "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED"
        # Policy requires irreversible anonymization whenever an analytics or
        # telemetry record remains attributable, even if a direct field is present.
        return "PRESENT", "REPORT_REMAINING_RECORD"
    if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG"}:
        if hint in {"NOT_FOUND", "ABSENT", "404", "DELETED"}:
            return "ABSENT", "VERIFY_RECORD_ABSENT"
        if category in {"USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE"}:
            return "PRESENT", "REPORT_REMAINING_RECORD"
        return ("PRESENT", "REPORT_EXPOSED_PII") if direct else ("REDACTED", "VERIFY_RECORD_REDACTED")
    # Infer category conservatively from field names when a manifest or table used
    # a new collection name.
    lower = (a.system_id + " " + a.path + " " + " ".join(f.keys())).casefold()
    if "marketing" in lower:
        return "PRESENT", "REPORT_REMAINING_RECORD"
    if "email_delivery" in lower or "notification" in lower:
        return ("PRESENT", "REPORT_EXPOSED_PII") if direct else None
    if direct and a.resource_id and a.resource_id != Path(a.path).stem:
        return "PRESENT", "REPORT_EXPOSED_PII"
    return None


def _new_step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str) -> dict[str, Any]:
    return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource, "operation": operation, "state": state, "evidence_id": evidence}


def audit_case(
    request: dict[str, str],
    artifacts: list[Artifact],
    subjects: dict[str, Subject],
    email_to_user: dict[str, str],
    policy_actions: dict[str, str] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    audit_at = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    if not authorizes_deletion(request.get("request_text", "")):
        return "NOT_APPLICABLE", []
    email = request.get("email", "")
    subject = _request_subject(request, subjects, email_to_user, audit_at)
    activity = _activity_for_subject(subject, email, audit_at)
    linked_resource_ids = {
        row["resource_id"]
        for row in activity
        if row.get("event_type") == "LINK_RESOURCE_IDENTITY"
        and row.get("reported_result", "").casefold() == "success"
        and row.get("resource_id")
    }
    matches = _evidence_matches(artifacts, subject, email, audit_at, linked_resource_ids)
    required_actions = policy_actions if policy_actions is not None else load_policy_actions()

    # Keep the latest grounded state for each system/resource/category. Different
    # evidence sources for the same record are combined by recency, not reported status.
    candidates: dict[tuple[str, str], Artifact] = {}
    for a in matches:
        if a.category == "UNKNOWN":
            continue
        key = (a.system_id, a.resource_id)
        prior = candidates.get(key)
        if prior is None or (a.when or datetime.min.replace(tzinfo=timezone.utc)) > (prior.when or datetime.min.replace(tzinfo=timezone.utc)):
            candidates[key] = a

    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verification: list[dict[str, Any]] = []
    violation = False

    # A retained record and a prohibited record can share one subject reference;
    # the policy category decides the treatment.
    for key, a in candidates.items():
        state = _record_state(a, subject, audit_at)
        if not state:
            continue
        current_state, operation = state
        if operation.startswith("REPORT_"):
            violation = True
            findings.append(_new_step("FINDING", a.system_id, a.resource_id, operation, current_state, a.evidence_id))
            action = {
                "REPORT_REMAINING_RECORD": ("DELETE_RECORD", "ABSENT"),
                "REPORT_EXPOSED_PII": ("REDACT_RECORD", "REDACTED"),
                "REPORT_ACTIVE_DATA_FLOW": ("DISABLE_DATA_FLOW", "DISABLED"),
                "REPORT_RESTORE_RISK": ("BLOCK_RESTORE", "BLOCKED"),
            }[operation]
            policy_action = required_actions.get(a.category, "")
            if policy_action == "ANONYMIZE":
                action = ("ANONYMIZE_RECORD", "ANONYMIZED")
            elif policy_action == "REDACT":
                action = ("REDACT_RECORD", "REDACTED")
            elif policy_action == "DELETE":
                action = ("DELETE_RECORD", "ABSENT")
            remediations.append(_new_step("REMEDIATION", a.system_id, a.resource_id, action[0], action[1], ""))
            verify = {
                "DELETE_RECORD": ("VERIFY_RECORD_ABSENT", "ABSENT"),
                "REDACT_RECORD": ("VERIFY_RECORD_REDACTED", "REDACTED"),
                "ANONYMIZE_RECORD": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
                "DISABLE_DATA_FLOW": ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
                "BLOCK_RESTORE": ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
            }[action[0]]
            verification.append(_new_step("VERIFICATION", a.system_id, a.resource_id, verify[0], verify[1], ""))
        else:
            verification.append(_new_step("VERIFICATION", a.system_id, a.resource_id, operation, current_state, a.evidence_id))

    # Use supported read-back and snapshot facts to prove absence for deleted
    # profiles, but never infer absence from a successful delete activity alone.
    for a in matches:
        if a.category not in {"USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:
            continue
        # structured null/404 read-back record references a resource but carries no
        # matching direct identifier in its profile; match is by exact request email.
        fields = {str(k).casefold(): v for k, v in a.fields.items()}
        vals = {normalize_email(x) for x in flatten_values(a.fields)}
        queried_email = normalize_email(email) in vals
        status = str(fields.get("status_code", fields.get("http_status", "")))
        found_zero = status == "404" or str(fields.get("rows", "")) == "0" or fields.get("profile") is None
        if queried_email and found_zero and a.category == "USER_PROFILE":
            verification.append(_new_step("VERIFICATION", a.system_id, a.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", a.evidence_id))

    # Coalesce duplicate observations of the same required check, retaining the
    # latest evidence citation. Incomplete plans use empty citations for future work.
    def unique_steps(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        keep: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for item in items:
            k = (item["system_id"], item["resource_id"], item["operation"], item["state"])
            old = keep.get(k)
            if old is None or (item.get("evidence_id", "") and not old.get("evidence_id", "")):
                keep[k] = item
        return sorted(keep.values(), key=lambda s: (RULE_PRIORITY.get(s["operation"], 99), s["system_id"], s["resource_id"]))

    findings = unique_steps(findings)
    remediations = unique_steps(remediations)
    verification = unique_steps(verification)
    status = "INCOMPLETE" if violation else "COMPLETE"
    steps = findings + remediations + verification
    for i, step in enumerate(steps, 1):
        step["step_no"] = i
    return status, steps


def generate(input_path: Path, output_path: Path) -> list[dict[str, Any]]:
    read_csv.cache_clear()
    requests = read_csv(input_path)
    artifacts, _, _ = load_artifacts()
    policy_actions = load_policy_actions()
    output: list[dict[str, Any]] = []
    for request in sorted(requests, key=lambda r: r["case_id"]):
        audit_at = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
        subjects, email_to_user = _identity_subjects(audit_at)
        status, steps = audit_case(request, artifacts, subjects, email_to_user, policy_actions)
        output.append({"case_id": request["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        writer.writeheader()
        writer.writerows(output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit deletion requests using local evidence")
    parser.add_argument("--input", type=Path, default=DATASET / "deletion_requests.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv")
    args = parser.parse_args()
    rows = generate(args.input, args.output)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["deletion_status"]] = counts.get(row["deletion_status"], 0) + 1
    print(f"Wrote {len(rows)} rows to {args.output}")
    print("Statuses: " + json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
