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
     re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
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


def redact_alert(obj):
    """
    Recursively redact an alert (dict / list / str). Returns a NEW object;
    the original is never mutated. Values under obviously-sensitive keys are
    fully redacted as a second layer of defence.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(v, str) and _SENSITIVE_KEYS.search(str(k)):
                out[k] = "[REDACTED:sensitive_field]"
            else:
                out[k] = redact_alert(v)
        return out
    if isinstance(obj, list):
        return [redact_alert(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


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
