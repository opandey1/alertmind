#!/usr/bin/env python3
"""Verify frozen AlertMind artifacts and reconstruct canonical scoring.

SIEM- and model-provider-independent: no Wazuh, Ollama, OpenAI or Anthropic
connection and no credentials. Every figure below is re-derived from committed
artifacts, so changes affecting the protected results fail the build instead of
silently moving a number in the report.

Scope: this covers the CI-protected assistant-evaluation figures only. MTTD,
the assisted-timing study, manual grounding verdicts, dashboards and
detection-rule counts are evidenced elsewhere and are NOT asserted here.

Three groups of assertions:

1. Frozen-file integrity   — SHA-256 of the corpus and the timing log, plus
                             newline-normalized content hashes for all six
                             retained audit logs.
2. Canonical scoring       — every reported run re-scored from its audit log.
3. Strict-view efficiency  — the §9.8 usage, latency, version and paired-hash
                             findings, asserted against raw stored values.

Exit code 0 means the CI-protected figures listed above still reproduce.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSISTANT = ROOT / "assistant"
sys.path.insert(0, str(ASSISTANT))

from rebuild_from_audit import rebuild  # noqa: E402
from scoring import aggregate  # noqa: E402

RUN_ROOT = ASSISTANT / "outputs" / "runs"
TIMING_LOG = ROOT / "measurement" / "timing-log.csv"


# ---------------------------------------------------------------- 1. integrity

EXPECTED_HASHES = {
    "measurement/alert-corpus.json":
        "4e842637f3cbcbb6e0704320824b64bdeb63c7d7ee7e22db0278e4d96c58b929",
    "measurement/timing-log.csv":
        "9ceba8e2468f44e879fa7929e528cfeaaef034ae363ffb66e98f57a21761cb9a",
}


# ------------------------------------------------------- 1b. audit-log content
#
# Newline-normalized content hashes for all six retained run logs, including
# the superseded 20260717_074112 evaluation run.
#
# These are NOT raw-file hashes. Every committed log is stored CRLF, so a raw
# hash would pass in CI and fail on any checkout that rewrites line endings.
# Normalization maps CRLF -> LF and lone CR -> LF and preserves every other
# byte, including whitespace and the trailing newline. The hash therefore
# survives Git EOL settings while still detecting a single changed character.
#
# This covers what the scoring assertions cannot see: grounding worksheet
# source text, raw model responses, and unscored response metadata such as
# response_id, system_fingerprint and finish_reason.

EXPECTED_LOG_CONTENT_HASHES = {
    "20260713T115729Z_ollama_operational":
        "6d1650e6e96557cae1b580456915d1ff7b3e7be0a068e02a078d21a69876dffc",
    "20260715_060542_ollama_oper_baseline":
        "f8b7701c7de7d557d5f9f0bbc19c0f2a442bf40fef5bb2eda4629ad80511966d",
    "20260717_073045_openai_oper_baseline":
        "a3ff0dd86bb69316fd551b572d7f6a7f7d72895bae8546c8f6ff4653a13d02fe",
    "20260717_074112_openai_eval_baseline":
        "3590dc7d0e038d5759f05bd6bb605ff499895a03b42cd478b9fb0c02bcd077e5",
    "20260718_180713_ollama_eval_baseline":
        "05f2fa9793b61ad11e6c6f054f67c9a1706c943255bda740c4508e5a2670b999",
    "20260718_183704_openai_eval_baseline":
        "0d246c2670b5c23962fbc4730ace5ae3f9db90a27c4cbc09c70009d9172eedd0",
}


# ------------------------------------------------------------------ 2. scoring
#
# Metric order is METRICS below. "all" covers the 20 corpus alerts; "attacks"
# covers the 14 attack-labelled alerts only.
#
# Every entry is a re-score of the committed audit log with the CURRENT
# validator and scorer. For 20260713T115729Z these are *retrospective* figures,
# not the numbers in that run's committed scoring CSV: that CSV is preserved
# as an as-run artifact of the then-current single-ID ATT&CK validator, which
# rejected the slash-joined IDs on A13 and A19 as bad_syntax. See
# measurement/grounding/README.md. The as-run CSV is deliberately not
# regenerated, and this expectation must never be described as its original
# output.

EXPECTED_RUNS = {
    "20260715_060542_ollama_oper_baseline": {
        "all": (14, 14, 14, 20, 14),
        "attacks": (14, 14, 14, 14, 14),
        "note": "matched llama3.1 operational baseline (as-run)",
    },
    "20260718_180713_ollama_eval_baseline": {
        "all": (3, 3, 14, 20, 1),
        "attacks": (1, 1, 14, 14, 1),
        "note": "llama3.1 strict label-reduced (as-run)",
    },
    "20260717_073045_openai_oper_baseline": {
        "all": (11, 14, 18, 14, 13),
        "attacks": (11, 14, 13, 13, 13),
        "note": "gpt-5.5 operational (as-run)",
    },
    "20260718_183704_openai_eval_baseline": {
        "all": (10, 14, 16, 16, 11),
        "attacks": (8, 12, 13, 13, 11),
        "note": "gpt-5.5 strict label-reduced (as-run)",
    },
    "20260713T115729Z_ollama_operational": {
        "all": (13, 14, 14, 20, 14),
        "attacks": (13, 14, 14, 14, 14),
        "note": "grounding-source sample — RETROSPECTIVE current-validator "
                "re-score, not the committed as-run CSV",
    },
}

METRICS = (
    "technique_exact_correct",
    "technique_relaxed_correct",
    "disposition_correct",
    "response_consistent",
    "overall_correct",
)


# ---------------------------------------------------------------- 3. §9.8 data
#
# Latency is asserted on the raw stored milliseconds rather than the rounded
# seconds printed in the report, so a rounding change cannot mask a data change.
# The report's 60.37 s / 21.18 min and 10.66 s / 3.81 min derive from these.

STRICT_RUNS = {
    "llama3.1:8b": {
        "run_id": "20260718_180713_ollama_eval_baseline",
        "prompt_tokens_median": 963.5,
        "completion_tokens_median": 218.5,
        "reasoning_tokens_median": None,        # provider reports null
        "visible_completion_median": 218.5,
        "total_tokens_median": 1182.5,
        "latency_ms_median": 60368.5,
        "latency_ms_sum": 1270831,
    },
    "gpt-5.5-2026-04-23": {
        "run_id": "20260718_183704_openai_eval_baseline",
        "prompt_tokens_median": 970.0,
        "completion_tokens_median": 786.5,
        "reasoning_tokens_median": 337.5,
        "visible_completion_median": 419.5,
        "total_tokens_median": 1708.5,
        "latency_ms_median": 10661.0,
        "latency_ms_sum": 228645,
    },
}

EXPECTED_PROMPT_VERSION = "23185744b88f77b7"
EXPECTED_REDACTION_VERSION = "3a527e33fa159616"
EXPECTED_RECORDS = 20


def fail(message: str) -> None:
    raise AssertionError(message)


def load_audit(run_id: str) -> list[dict]:
    """Read a run's audit log, tolerating either JSONL or a JSON array."""
    path = RUN_ROOT / run_id / "audit-log.jsonl"
    raw = path.read_text(encoding="utf-8-sig").strip()
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        return [json.loads(line) for line in raw.splitlines() if line.strip()]


def metric_tuple(result: dict) -> tuple[int, ...]:
    return tuple(result[name] for name in METRICS)


def verify_hashes() -> None:
    print("frozen-file integrity")
    for relative_path, expected in EXPECTED_HASHES.items():
        actual = hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{relative_path}: expected SHA-256 {expected}, got {actual}")
        print(f"  PASS  {relative_path} = {actual}")


def normalize_newlines(data: bytes) -> bytes:
    """CRLF -> LF and lone CR -> LF. All other bytes are preserved."""
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def verify_log_content_hashes() -> None:
    """Pin the byte content of every retained audit log, EOL-independently."""
    print("\naudit-log content integrity (newline-normalized)")
    for run_id, expected in EXPECTED_LOG_CONTENT_HASHES.items():
        path = RUN_ROOT / run_id / "audit-log.jsonl"
        if not path.exists():
            fail(f"{run_id}: audit-log.jsonl is missing")
        actual = hashlib.sha256(normalize_newlines(path.read_bytes())).hexdigest()
        if actual != expected:
            fail(f"{run_id}: normalized content hash changed; "
                 f"expected {expected}, got {actual}")
        print(f"  PASS  {run_id} = {actual}")


def verify_runs() -> None:
    print("\ncanonical scoring, re-derived from audit logs")
    for run_id, expected in EXPECTED_RUNS.items():
        audit_log = RUN_ROOT / run_id / "audit-log.jsonl"
        outputs, rows, all_metrics = rebuild(str(audit_log), str(TIMING_LOG))

        if len(outputs) != EXPECTED_RECORDS or len(rows) != EXPECTED_RECORDS:
            fail(f"{run_id}: expected {EXPECTED_RECORDS} reconstructed alerts, "
                 f"got {len(outputs)} outputs and {len(rows)} score rows")

        attack_rows = [r for r in rows
                       if r["ground_truth"].strip().lower() != "benign"]
        actual_all = metric_tuple(all_metrics)
        actual_attacks = metric_tuple(aggregate(attack_rows))

        if actual_all != expected["all"]:
            fail(f"{run_id}: all-alert metrics changed; "
                 f"expected {expected['all']}, got {actual_all}")
        if actual_attacks != expected["attacks"]:
            fail(f"{run_id}: attack-only metrics changed; "
                 f"expected {expected['attacks']}, got {actual_attacks}")

        print(f"  PASS  {run_id}")
        print(f"        all={actual_all} attacks={actual_attacks}")
        print(f"        {expected['note']}")


def verify_strict_efficiency() -> None:
    """Assert the §9.8 usage, latency, version and paired-hash findings."""
    print("\nstrict-view efficiency and pairing (report §9.8)")
    paired: dict[str, dict[str, dict]] = {}

    for model, expected in STRICT_RUNS.items():
        run_id = expected["run_id"]
        records = load_audit(run_id)
        if len(records) != EXPECTED_RECORDS:
            fail(f"{run_id}: expected {EXPECTED_RECORDS} records, "
                 f"got {len(records)}")

        versions = {r.get("prompt_version") for r in records}
        if versions != {EXPECTED_PROMPT_VERSION}:
            fail(f"{run_id}: prompt_version {versions} != "
                 f"{{{EXPECTED_PROMPT_VERSION}}}")
        versions = {r.get("redaction_version") for r in records}
        if versions != {EXPECTED_REDACTION_VERSION}:
            fail(f"{run_id}: redaction_version {versions} != "
                 f"{{{EXPECTED_REDACTION_VERSION}}}")

        prompt, completion, reasoning, visible, total, latency = ([] for _ in range(6))
        for record in records:
            usage = record.get("usage") or {}
            p = usage.get("prompt_tokens")
            c = usage.get("completion_tokens")
            r = usage.get("reasoning_tokens")
            t = usage.get("total_tokens")
            if p is None or c is None or t is None:
                fail(f"{run_id}/{record.get('alert_id')}: incomplete usage block")
            prompt.append(p)
            completion.append(c)
            total.append(t)
            visible.append(c - (r or 0))
            if r is not None:
                reasoning.append(r)
            latency.append(record["latency_ms"])

        actual = {
            "prompt_tokens_median": statistics.median(prompt),
            "completion_tokens_median": statistics.median(completion),
            "reasoning_tokens_median": (statistics.median(reasoning)
                                        if reasoning else None),
            "visible_completion_median": statistics.median(visible),
            "total_tokens_median": statistics.median(total),
            "latency_ms_median": statistics.median(latency),
            "latency_ms_sum": sum(latency),
        }
        for key, want in expected.items():
            if key == "run_id":
                continue
            got = actual[key]
            if want is None:
                if got is not None:
                    fail(f"{run_id}: {key} expected None "
                         f"(provider reports no separate count), got {got}")
            elif float(got) != float(want):
                fail(f"{run_id}: {key} expected {want}, got {got}")

        paired[model] = {r["alert_id"]: r for r in records}
        print(f"  PASS  {model} ({run_id})")
        print(f"        prompt={actual['prompt_tokens_median']} "
              f"completion={actual['completion_tokens_median']} "
              f"reasoning={actual['reasoning_tokens_median']} "
              f"visible={actual['visible_completion_median']} "
              f"total={actual['total_tokens_median']}")
        print(f"        latency median={actual['latency_ms_median']} ms "
              f"sum={actual['latency_ms_sum']} ms")

    left, right = paired.values()
    shared = sorted(set(left) & set(right))
    if len(shared) != EXPECTED_RECORDS:
        fail(f"paired strict runs: expected {EXPECTED_RECORDS} shared alert ids, "
             f"got {len(shared)}")

    for field in ("input_hash", "redacted_prompt_hash"):
        mismatched = [a for a in shared if left[a][field] != right[a][field]]
        if mismatched:
            fail(f"{field}: {len(mismatched)}/{EXPECTED_RECORDS} pairs differ "
                 f"({', '.join(mismatched[:5])})")
        print(f"  PASS  {field} matches {EXPECTED_RECORDS}/{EXPECTED_RECORDS} "
              f"across the paired strict runs")

    print(f"  PASS  prompt version {EXPECTED_PROMPT_VERSION}, "
          f"redaction version {EXPECTED_REDACTION_VERSION} on both runs")


def main() -> int:
    verify_hashes()
    verify_log_content_hashes()
    verify_runs()
    verify_strict_efficiency()
    print("\nPASS: frozen evidence, canonical scoring and §9.8 efficiency "
          "findings verified offline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
