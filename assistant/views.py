"""
views.py — alert "views" that control how much ATT&CK metadata the model sees.

The corpus alert carries the rule's own ATT&CK label in several places: `mitre.id`,
the T-code inside `rule_description`, AND detection-authored key fields such as
`audit.key = "t1053_003_cron"`. If the model sees any of these, then "did it return
the right technique" only tests whether it can COPY the rule's label, not classify.

Two views:
  operational  - full (redacted) alert, including the rule's ATT&CK metadata.
                 Realistic for a Wazuh-integrated assistant. The matching metric
                 here is "ATT&CK metadata CONSISTENCY", not classification.
  evaluation   - a strict, label-reduced view: removes the detection-authored
                 labels that encode the answer (`mitre`, `rule_id`,
                 `rule_description`, and `*.key` fields like `audit.key`), then
                 strips any surviving technique codes from remaining strings.
                 Raw host evidence (exe, command, path, user, registry object,
                 access mask, syscall) is retained, so the model must classify
                 from evidence. `evaluation_view_leaks()` proves nothing slipped
                 through.

Apply the view AFTER redaction (redact for secrets first, then choose the view).
"""
import copy
import json
import re

# Technique codes for STRIPPING from prose: T1053, T1053.003, slash/comma-joined.
_TCODE = re.compile(
    r"\(?\b[tT]\d{4}(?:[._]\d{3})?(?:\s*[/,]\s*[tT]\d{4}(?:[._]\d{3})?)*\b\)?",
    re.I,
)
# Looser pattern for leak DETECTION: catches t1053_003 even inside t1053_003_cron
# (a trailing "_cron" defeats a \b-anchored match, so detection must not anchor).
_TCODE_ANY = re.compile(r"(?i)[tT]\d{4}(?:[._]\d{3})?")

# Detection-authored fields that encode the answer (vs. raw host evidence).
_LABEL_KEYS = ("mitre", "rule_id", "rule_description", "evidence_file")


def _strip_tcodes(obj):
    if isinstance(obj, dict):
        return {k: _strip_tcodes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_tcodes(v) for v in obj]
    if isinstance(obj, str):
        s = _TCODE.sub("", obj)
        # Also remove codes embedded inside tokens named after the technique
        # (e.g. a test file "amtest_t1037_AM" or a DNS label "am-t1071dns").
        # Real-world evidence would not be self-labeled; this is a corpus artifact.
        s = _TCODE_ANY.sub("", s)
        return s.replace("  ", " ").strip()
    return obj


def _drop_label_subkeys(obj):
    """Recursively drop detection-authored label fields such as `audit.key`."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = k.lower()
            if kl == "key" or kl.endswith(".key") or kl.endswith("_key"):
                continue  # e.g. audit.key = "t1053_003_cron"
            out[k] = _drop_label_subkeys(v)
        return out
    if isinstance(obj, list):
        return [_drop_label_subkeys(v) for v in obj]
    return obj


def to_evaluation_view(alert: dict) -> dict:
    """Strict label-reduced view: strip detection labels, keep raw evidence."""
    a = copy.deepcopy(alert)
    for k in _LABEL_KEYS:
        a.pop(k, None)
    a = _drop_label_subkeys(a)
    return _strip_tcodes(a)


def evaluation_view_leaks(alert_view: dict) -> list:
    """Return any ATT&CK-technique-like tokens surviving in an evaluation view."""
    blob = json.dumps(alert_view)
    return sorted(set(m.group(0) for m in _TCODE_ANY.finditer(blob)))


def apply_view(alert: dict, view: str) -> dict:
    if view == "evaluation":
        return to_evaluation_view(alert)
    return alert  # operational: unchanged
