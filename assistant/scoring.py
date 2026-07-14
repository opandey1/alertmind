"""
scoring.py — multi-metric scoring for the AlertMind assistant.

Replaces the old single boolean `score()` which could mark contradictory answers
correct (e.g. an attack tagged with the right technique but disposition
'likely_benign' scored as correct). Each dimension is now separate so the report
can be honest about what the assistant got right.

Metrics per alert:
  technique_exact_correct    - benign: assistant asserted NO technique;
                               attack:  exact ATT&CK id (sub-technique level) in ground truth
  technique_relaxed_correct  - as above but parent<->sub-technique also counts
  disposition_correct        - benign: 'likely_benign';
                               attack:  'likely_true_positive' or 'needs_investigation'
  response_consistent        - disposition and technique do not contradict each other
  overall_correct            - disposition_correct AND technique_relaxed_correct AND consistent
"""
import re

_ATTACK_OK_DISP = {"likely_true_positive", "needs_investigation"}


def codes(s: str):
    """All ATT&CK technique codes in a string, e.g. 'T1566/T1059' -> {T1566, T1059}."""
    return {c.upper() for c in re.findall(r"T\d{4}(?:\.\d{3})?", s or "", re.I)}


def _base(code: str):
    return code.split(".")[0].upper()


def score_alert(ground_truth: str, parsed: dict) -> dict:
    # An errored or unparseable response is correct on nothing.
    if not isinstance(parsed, dict) or parsed.get("_error") or parsed.get("_parse_error"):
        return {"technique_exact_correct": False, "technique_relaxed_correct": False,
                "disposition_correct": False, "response_consistent": False,
                "overall_correct": False, "assistant_tag": None, "assistant_disposition": None}
    gt = (ground_truth or "").strip()
    is_benign = gt.lower() == "benign"
    gt_codes = codes(gt)
    a_codes = codes(parsed.get("attack_technique_id"))   # handles single OR multi (e.g. T1136/T1098)
    disp = (parsed.get("disposition_suggestion") or "").strip().lower()

    if is_benign:
        technique_exact = not a_codes            # benign: should assert no technique
        technique_relaxed = technique_exact
        disposition_correct = (disp == "likely_benign")
    else:
        technique_exact = bool(a_codes & gt_codes)                        # sub-technique overlap
        technique_relaxed = technique_exact or bool(
            {_base(c) for c in a_codes} & {_base(c) for c in gt_codes})   # parent-technique overlap
        disposition_correct = disp in _ATTACK_OK_DISP

    # consistency: benign disposition must not carry an attack technique; a
    # confident true-positive must carry one.
    consistent = True
    if disp == "likely_benign" and a_codes:
        consistent = False
    if disp == "likely_true_positive" and not a_codes:
        consistent = False

    overall = disposition_correct and technique_relaxed and consistent

    return {
        "technique_exact_correct": technique_exact,
        "technique_relaxed_correct": technique_relaxed,
        "disposition_correct": disposition_correct,
        "response_consistent": consistent,
        "overall_correct": overall,
        "assistant_tag": "/".join(sorted(a_codes)) or None,
        "assistant_disposition": disp or None,
    }


def aggregate(rows):
    """rows: list of score_alert() dicts. Returns counts per metric."""
    keys = ["technique_exact_correct", "technique_relaxed_correct",
            "disposition_correct", "response_consistent", "overall_correct"]
    n = len(rows) or 1
    return {k: sum(1 for r in rows if r[k]) for k in keys} | {"n": len(rows)}
