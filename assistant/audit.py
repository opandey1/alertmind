"""
audit.py — shared audit-record contract for AlertMind.

Extracts the small set of helpers that batch (`runner.py`) and ad-hoc
(`paste_core.py`) records both need, so their records are structurally
comparable without importing private underscored helpers across modules.

Records never contain raw pasted input or raw values matching the tested secret
classes — only fingerprints, lengths and already-redacted derived fields.
"""
import hashlib
import json
import os

ADHOC_LOG = os.path.join("outputs", "adhoc", "adhoc-audit.jsonl")
_ADHOC_LOG = ADHOC_LOG  # backward-compatible alias; new code uses the public name


def short_sha(value: str) -> str:
    """16-char correlation fingerprint; not encryption or a secrecy control."""
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def windows_long_path(path: str) -> str:
    """Windows MAX_PATH(260) workaround via the \\\\?\\ prefix. No-op elsewhere."""
    if os.name == "nt":
        p = os.path.abspath(path)
        return p if p.startswith("\\\\?\\") else "\\\\?\\" + p
    return path


def build_adhoc_audit_record(result: dict, source: str = "paste") -> dict:
    """
    Build one sanitized audit record from a paste_core result. Raw input and
    tested raw secret values are structurally absent (the result never carried them).
    Failure-path provider metadata is preserved.
    """
    cfg = result.get("config", {})
    meta = result.get("call_meta", {}) or {}
    return {
        "record_id": result.get("result_id"),
        "source": source,
        "created_at": result.get("created_at"),
        "input_hash": result.get("input_hash"),
        "parse_mode": result.get("parse_mode"),
        "provider": cfg.get("provider"),
        "model_requested": cfg.get("model_requested"),
        "model_actual": meta.get("model_actual") or meta.get("model"),
        "view": cfg.get("view"),
        "prompt_name": cfg.get("prompt_name"),
        "system_prompt_hash": cfg.get("system_prompt_hash"),
        "endpoint": cfg.get("endpoint"),
        "egress_consent_required": cfg.get("egress_consent_required"),
        "call_status": result.get("call_status"),
        "boundary_status": result.get("boundary_status"),
        "injection_hit_count": len(result.get("injection_hits", [])),
        "redaction_trace_count": len(result.get("redaction_trace", [])),
        "redacted_user_message_hash": short_sha(result.get("redacted_user_message", "")),
        "schema_valid": result.get("schema_valid"),
        "schema_errors": result.get("schema_errors", []),
        "disposition": (result.get("parsed_output") or {}).get("disposition_suggestion"),
        "response_id": meta.get("response_id"),
        "system_fingerprint": meta.get("system_fingerprint"),
        "finish_reason": meta.get("finish_reason"),
        "usage": meta.get("usage"),
        "analyst_review_required": True,
    }


def _existing_ids(path: str) -> set:
    ids = set()
    if not os.path.exists(windows_long_path(path)):
        return ids
    with open(windows_long_path(path), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ids.add(json.loads(line).get("record_id"))
            except Exception:
                continue
    return ids


def append_jsonl_once(path: str, record: dict, record_id: str) -> bool:
    """
    Append one JSON line, idempotently keyed on record_id. Returns True if the
    record was written, False if a record with that id already existed.
    Single-writer, local use: dedupe by scanning, then O_APPEND write.
    """
    if record_id in _existing_ids(path):
        return False
    os.makedirs(windows_long_path(os.path.dirname(path)) or ".", exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    # O_APPEND makes each single write atomic on POSIX and adequate for local Windows use.
    fd = os.open(windows_long_path(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(windows_long_path(path), 0o600)  # best-effort; not a full ACL on Windows
    except Exception:
        pass
    return True
