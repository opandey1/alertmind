"""
schema.py — validate the assistant's JSON output (feedback #11).

parse_response() only confirms the model returned *some* JSON. This validates the
SHAPE: required keys, field types, allowed dispositions/confidence, ATT&CK-ID
syntax, and the <=5-summary-line / 1-4-query validator bounds. The prompt asks
for 2-3 queries, while the validator deliberately tolerates 1-4. Invalid output
is caught and recorded (parse_status='schema_invalid') rather than silently
scored.

Kept dependency-free so the offline/mock path needs no `pip install`. The
equivalent formal JSON Schema is included below and can be plugged into the
`jsonschema` package instead if preferred.
"""
import copy
import re

DISPOSITIONS = {"likely_true_positive", "likely_benign", "needs_investigation"}
CONFIDENCES = {"high", "medium", "low"}
_TID = re.compile(r"^T\d{4}(?:\.\d{3})?(?:\s*[/,]\s*T\d{4}(?:\.\d{3})?)*$")  # single or slash/comma-joined

# Formal schema (documentation / optional jsonschema use).
JSON_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "attack_technique_id", "disposition_suggestion",
                 "confidence", "investigation_queries", "draft_user_message", "caveats"],
    "properties": {
        "summary": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
        "attack_technique_id": {
            "type": ["string", "null"],
            "pattern": r"^T\d{4}(?:\.\d{3})?(?:\s*[/,]\s*T\d{4}(?:\.\d{3})?)*$",
        },
        "attack_technique_name": {"type": ["string", "null"]},
        "disposition_suggestion": {"enum": sorted(DISPOSITIONS)},
        "confidence": {"enum": sorted(CONFIDENCES)},
        "investigation_queries": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "maxItems": 4,
        },
        "draft_user_message": {"type": "string"},
        "caveats": {"type": "string"},
    },
}

REQUIRED = JSON_SCHEMA["required"]


def ollama_json_schema():
    """Return the provider-side schema accepted by Ollama's grammar parser.

    Ollama 0.33.0 rejects the full schema at realistic prediction budgets when
    the ATT&CK-ID ``pattern`` is present (``failed to parse grammar``).  Keep
    every structural constraint but omit that provider-side regex; the same
    expression remains enforced by :func:`validate_output` after generation.
    A deep copy prevents provider compatibility from weakening the canonical
    documented/runtime contract.
    """
    schema = copy.deepcopy(JSON_SCHEMA)
    schema["properties"]["attack_technique_id"].pop("pattern", None)
    return schema


def validate_output(parsed: dict):
    """
    Returns (ok, errors, normalized). Coerces a few safe cases (a string summary
    becomes a one-item list; summary is truncated to 5). Anything else that
    violates the schema is reported in `errors` and ok is False.
    """
    errors = []
    if not isinstance(parsed, dict) or parsed.get("_parse_error"):
        return False, ["not a JSON object"], parsed
    p = dict(parsed)

    # Keep the dependency-free runtime validator aligned with the formal
    # provider-side schema.  Extra fields are often a sign that a model added
    # prose or invented a second output contract, so record them as invalid
    # instead of silently accepting a shape the prompt did not request.
    allowed = set(JSON_SCHEMA["properties"])
    for key in sorted(set(p) - allowed):
        errors.append(f"additional_property:{key}")

    for k in REQUIRED:
        if k not in p:
            errors.append(f"missing:{k}")

    # summary
    if isinstance(p.get("summary"), str):
        p["summary"] = [p["summary"]]
    if "summary" in p and not isinstance(p["summary"], list):
        errors.append("summary:not_list")
    elif isinstance(p.get("summary"), list):
        if len(p["summary"]) > 5:
            errors.append("summary:>5_lines")
            p["summary"] = p["summary"][:5]
        if not all(isinstance(x, str) for x in p["summary"]):
            errors.append("summary:non_string_items")

    # attack_technique_id
    tid = p.get("attack_technique_id")
    if tid not in (None, "") and not (isinstance(tid, str) and _TID.match(tid)):
        errors.append(f"attack_technique_id:bad_syntax({tid})")

    # disposition / confidence
    if p.get("disposition_suggestion") not in DISPOSITIONS:
        errors.append(f"disposition:invalid({p.get('disposition_suggestion')})")
    if p.get("confidence") not in CONFIDENCES:
        errors.append(f"confidence:invalid({p.get('confidence')})")

    # queries
    q = p.get("investigation_queries")
    if q is not None:
        if not isinstance(q, list) or not all(isinstance(x, str) for x in q):
            errors.append("investigation_queries:not_string_list")
        elif not (1 <= len(q) <= 4):
            errors.append(f"investigation_queries:count({len(q)})")

    # free-text fields
    for k in ("draft_user_message", "caveats"):
        if k in p and not isinstance(p[k], str):
            errors.append(f"{k}:not_string")

    return (len(errors) == 0), errors, p
