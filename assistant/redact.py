"""
redact.py — AlertMind LLM assistant redaction layer.

Guardrail: the assistant must NEVER receive secrets. Every alert is passed
through redact_alert() BEFORE any prompt is built, so credential material is
stripped locally and never leaves the environment in the LLM prompt.

Design notes:
  * Redaction is deterministic (regex) so it is unit-testable and reproducible —
    this is what produces the before/after "redaction proof" the rubric requires.
  * We redact the VALUE but keep the KEY / marker, so the analyst still sees that
    a secret was present (e.g. `password=[REDACTED:password]`) without leaking it.
  * File hashes in a Sysmon `Hashes=` field are IOCs, not secrets, and are kept.
    Credential material (passwords, tokens, API keys, private keys) is removed.
"""
import hashlib as _hashlib
import hmac as _hmac
import json as _json
import os as _os
import re

# (name, compiled pattern, replacement).  Order matters: PEM blocks first.
_RULES = [
    ("private_key",
     re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.S),
     "[REDACTED:private_key]"),

    ("ssh_private_key",
     re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----", re.S),
     "[REDACTED:ssh_private_key]"),

    ("bearer_token",
     re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{10,}"),
     "Bearer [REDACTED:bearer_token]"),

    ("aws_access_key",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "[REDACTED:aws_access_key]"),

    ("aws_secret_key",
     re.compile(r"(?i)\b(aws_secret_access_key)\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{30,}[\"']?"),
     r"\1=[REDACTED:aws_secret_key]"),

    ("openai_key",
     re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
     "[REDACTED:api_key]"),

    # key=value style secrets: password/passwd/pwd/secret/token/api_key/access_key/client_secret
    ("kv_secret",
     re.compile(r"(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*[\"']?([^\s\"';,&]+)"),
     r"\1=[REDACTED:secret]"),

    # connection-string password:  Pwd=...;  or  Password=...;
    ("connstr_pwd",
     re.compile(r"(?i)\b(pwd|password)\s*=\s*[^;\"'\s]+"),
     r"\1=[REDACTED:secret]"),
]

# Fields whose entire value is sensitive if present (defence in depth).
_SENSITIVE_KEYS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)")


def redact_text(text: str) -> str:
    """Apply every redaction rule to a string."""
    if not isinstance(text, str):
        return text
    for _name, pat, repl in _RULES:
        text = pat.sub(repl, text)
    return text


_TRACE_HMAC_KEY = _os.environ.get("ALERTMIND_TRACE_HMAC_KEY", "").encode("utf-8")


def _correlation_hash(s: str):
    """Optional keyed fingerprint; never store an unsalted secret digest.

    Set ALERTMIND_TRACE_HMAC_KEY to correlate the same redacted value across
    trace rows. Without a key the field is None, which is safer for real data.
    """
    if not _TRACE_HMAC_KEY:
        return None
    return _hmac.new(_TRACE_HMAC_KEY, s.encode("utf-8", "replace"),
                     _hashlib.sha256).hexdigest()[:12]


def _mask(value: str) -> str:
    """Length-only mask — never the original value."""
    return "\u2022" * min(len(value), 6) + f" ({len(value)} chars)"


def _canonical_sensitive(value) -> str:
    """Stable local representation used only for mask length/optional HMAC."""
    if isinstance(value, str):
        return value
    return _json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _matched_values(text: str):
    """Rule-name -> list of matched substrings (used ONLY for masking/hashing;
    never stored in results)."""
    out = []
    for name, pat, _repl in _RULES:
        for m in pat.finditer(text):
            out.append((name, m.group(0)))
    return out


def _redact_node(obj, path, trace):
    """Shared recursion. If `trace` is a list, append sanitized evidence rows.
    Both redact_alert() and redact_alert_with_trace() delegate here, so the
    proof path and the production path cannot diverge."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            child = f"{path}.{k}" if path else str(k)
            if _SENSITIVE_KEYS.search(str(k)):
                raw = _canonical_sensitive(v)
                if trace is not None:
                    trace.append({
                        "field_path": child, "rule": "sensitive_field",
                        "source": "sensitive_key", "masked_value": _mask(raw),
                        "value_length": len(raw),
                        "value_hash": _correlation_hash(raw),
                        "value_type": type(v).__name__,
                        "removed": True,
                    })
                out[k] = "[REDACTED:sensitive_field]"
            else:
                out[k] = _redact_node(v, child, trace)
        return out
    if isinstance(obj, list):
        return [_redact_node(v, f"{path}[{i}]", trace) for i, v in enumerate(obj)]
    if isinstance(obj, str):
        redacted = redact_text(obj)
        if trace is not None:
            for name, raw in _matched_values(obj):
                trace.append({
                    "field_path": path, "rule": name, "source": "regex",
                    "masked_value": _mask(raw), "value_length": len(raw),
                    "value_hash": _correlation_hash(raw),
                    "value_type": "str", "removed": raw not in redacted,
                })
        return redacted
    return obj


def redact_alert(obj):
    """
    Recursively redact an alert (dict / list / str). Returns a NEW object;
    the original is never mutated. Values under obviously-sensitive keys are
    fully redacted as a second layer of defence.
    """
    return _redact_node(obj, "", None)


def redact_alert_with_trace(obj):
    """Return (redacted_object, sanitized_trace). The trace never contains a
    complete matched value — only a mask, length and correlation hash."""
    trace = []
    red = _redact_node(obj, "", trace)
    return red, trace


def find_secrets(text: str):
    """Return the list of rule names that matched — used by the proof test to
    assert that planted secrets were detected."""
    if not isinstance(text, str):
        return []
    hits = []
    for name, pat, _repl in _RULES:
        if pat.search(text):
            hits.append(name)
    return hits


if __name__ == "__main__":
    demo = ('CommandLine: net use \\\\srv /user:admin Password=Sup3rSecret! ; '
            'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEYAB ; '
            'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload ; '
            'api_key=sk-abcdEFGH1234567890ijklmnop')
    print("BEFORE:\n", demo, "\n\nAFTER:\n", redact_text(demo))
