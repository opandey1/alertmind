"""
views.py — alert "views" that control how much ATT&CK metadata the model sees.

The corpus alert carries the rule's own ATT&CK label (`mitre.id`) and the T-code
inside `rule_description`. If the model sees those, then "did it return the right
technique" only tests whether it can COPY the rule's label — not classify.

Two views:
  operational  - full (redacted) alert, including the rule's ATT&CK metadata.
                 Realistic for a Wazuh-integrated assistant. The matching metric
                 here is "ATT&CK metadata CONSISTENCY", not classification.
  evaluation   - strips `mitre`, `rule_id`, and every T-code from string values,
                 leaving the raw process / file / registry / audit fields and the
                 prose description. This is a true ATT&CK CLASSIFICATION test.

Apply the view AFTER redaction (redact for secrets first, then choose the view).
"""
import copy
import re

_TCODE = re.compile(r"\(?\bT\d{4}(?:\.\d{3})?(?:\s*/\s*T\d{4}(?:\.\d{3})?)*\b\)?", re.I)


def _strip_tcodes(obj):
    if isinstance(obj, dict):
        return {k: _strip_tcodes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_tcodes(v) for v in obj]
    if isinstance(obj, str):
        return _TCODE.sub("", obj).replace("  ", " ").strip()
    return obj


def to_evaluation_view(alert: dict) -> dict:
    """Remove the rule's ATT&CK metadata so the model must infer the technique."""
    a = copy.deepcopy(alert)
    a.pop("mitre", None)
    a.pop("rule_id", None)
    return _strip_tcodes(a)


def apply_view(alert: dict, view: str) -> dict:
    if view == "evaluation":
        return to_evaluation_view(alert)
    return alert  # operational: unchanged
