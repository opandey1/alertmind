"""
injection.py — visibility-only injection-marker scan + hard boundary gate.

This is NOT the injection defence. The real controls are the system-prompt
trust boundary, local redaction, the absence of tools/action interface, schema
validation, and mandatory analyst review. This module gives the analyst
*visibility* into instruction-shaped text inside untrusted telemetry, and one
hard, blocking check: a literal <ALERT_DATA> delimiter in model-bound data.

Detection is incomplete by design. Rules require instruction-shaped continuation
so ordinary telemetry (an `authorized_keys` path, a `SYSTEM:` log prefix) does
not match.
"""
import json
import re

_SNIPPET_MAX = 120
DELIM_OPEN, DELIM_CLOSE = "<ALERT_DATA>", "</ALERT_DATA>"

# (name, compiled pattern). Patterns use bounded quantifiers to avoid
# catastrophic backtracking.
_RULES = [
    ("ignore_previous",
     re.compile(r"(?i)\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|prompts|context)")),
    ("role_override",
     re.compile(r"(?i)\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+(?:a|an)\s+\w+|new\s+system\s+prompt)\b")),
    ("forced_disposition",
     re.compile(r"(?i)\b(?:classify|mark|treat|report|label|set)\b.{0,25}?\b(?:as\s+)?(?:benign|safe|false[\s-]?positive|clean|not\s+malicious)\b")),
    ("forced_output",
     re.compile(r"(?i)\b(?:you\s+must|always|only)\s+(?:respond|reply|answer|output|return)\b.{0,25}?(?:with|format|json|exactly)")),
    ("no_action",
     re.compile(r"(?i)\b(?:take\s+no\s+action|do\s+not\s+(?:alert|report|escalate|flag|investigate|block))\b")),
    ("prompt_exfil",
     re.compile(r"(?i)\b(?:reveal|repeat|print|show|disclose|output)\b.{0,25}?\b(?:system\s+prompt|your\s+(?:prompt|instructions)|previous\s+instructions)\b")),
    ("system_impersonation",
     re.compile(r"(?i)(?:<\|(?:im_start|system|assistant)\|>|\[/?INST\]|^\s*system\s*:\s*(?:you|ignore|always|respond|disregard))")),
    ("authorization_claim",
     re.compile(r"(?i)\bthis\s+(?:activity|action|alert|behaviou?r|command)\s+(?:is|was)\s+(?:approved|authorized|authorised|sanctioned|expected)\b")),
    ("delimiter_break",
     re.compile(r"</?ALERT_DATA>")),
]


def _scan_text(value, path, hits):
    """Scan one attacker-controlled string and append bounded evidence rows."""
    for name, pat in _RULES:
        m = pat.search(value)
        if m:
            snip = value[max(0, m.start() - 10): m.start() + _SNIPPET_MAX]
            hits.append({"field_path": path, "rule": name,
                         "snippet": snip[:_SNIPPET_MAX]})


def _walk(obj, path, hits):
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path else str(k)
            # JSON object keys are attacker-controlled data too, and are included
            # verbatim by json.dumps() in the model-bound prompt.
            if isinstance(k, str):
                _scan_text(k, f"{child}<key>", hits)
            _walk(v, child, hits)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk(v, f"{path}[{i}]", hits)
    elif isinstance(obj, str):
        _scan_text(obj, path, hits)


def scan_alert(obj) -> list:
    """Return bounded field-path/rule/snippet markers from model-bound data.
    Recursive, non-mutating, snippets rendered as text (never HTML)."""
    hits = []
    _walk(obj, "", hits)
    return hits


def has_boundary_break(hits: list) -> bool:
    """True when a static ALERT_DATA delimiter is present in model-bound data."""
    return any(h["rule"] == "delimiter_break" for h in hits)


def contains_boundary(obj) -> bool:
    """Independent fail-safe gate over the exact serialized model-bound object.

    This intentionally duplicates the marker rule at the enforcement boundary:
    marker scanning is visibility, while this function decides whether a call is
    allowed. Dictionary keys and values are both present in the serialization.
    """
    serialized = json.dumps(obj, ensure_ascii=False, default=str)
    return DELIM_OPEN in serialized or DELIM_CLOSE in serialized
