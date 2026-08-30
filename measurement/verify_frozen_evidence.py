#!/usr/bin/env python3
"""Verify frozen AlertMind artifacts and reconstruct canonical scoring.

SIEM- and model-provider-independent: no Wazuh, Ollama, OpenAI or Anthropic
connection and no credentials. Every figure below is re-derived from committed
artifacts, so changes affecting the protected results fail the build instead of
silently moving a number in the report.

Scope: this covers the CI-protected assistant-evaluation figures only. MTTD,
the assisted-timing study, manual grounding verdicts, dashboards and
detection-rule counts are evidenced elsewhere and are NOT asserted here.

Four groups of assertions:

1. Frozen-file integrity   — SHA-256 of the corpus and the timing log, plus
                             newline-normalized hashes for protected audit
                             logs.
2. Canonical scoring       — every reported run re-scored from its audit log.
3. Strict-view efficiency  — the §9.8 usage, latency, version and paired-hash
                             findings, asserted against raw stored values.
4. Accepted Qwen evidence  — final-run provenance, manifests, request config,
                             scoring, performance and stochastic-sample facts.

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
# Newline-normalized content hashes for the six legacy protected run logs plus
# the accepted final Qwen pair. Historical Qwen pilots and pre-commit
# candidates remain immutable evidence but are not published benchmark inputs.
#
# These are NOT raw-file hashes. Stored line endings vary, and a raw hash can
# pass in CI but fail on a checkout that rewrites line endings.
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
    "20260830_054251_ollama_oper_baseline":
        "39ecf388af73e1639b2bad206509d093c30b8d233ae5f54a5c60cecc012aba8a",
    "20260830_070142_ollama_eval_baseline":
        "3731f0ac7f822b5069a53cfbff4c958c65c15eb1596c898c444710faec4b9e6d",
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
    "20260830_054251_ollama_oper_baseline": {
        "all": (14, 14, 14, 20, 14),
        "attacks": (14, 14, 14, 14, 14),
        "note": "accepted qwen3:8b operational sample (as-run)",
    },
    "20260830_070142_ollama_eval_baseline": {
        "all": (3, 6, 14, 18, 4),
        "attacks": (2, 5, 13, 13, 4),
        "note": "accepted qwen3:8b strict label-reduced sample (as-run)",
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

QWEN_FINAL_COMMIT_SHORT = "7ca2543"
QWEN_FINAL_COMMIT_FULL = "7ca2543e620151b77d2d032e728090ae587aeaf8"
QWEN_MODEL_MANIFEST_DIGEST = (
    "sha256:500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41"
)
QWEN_MODEL_BLOB_DIGEST = (
    "sha256:a3de86cd1c132c822487ededd47a324c50491393e6565cd14bafa40d0b8e686f"
)
QWEN_MODEL_CAPTURE = "measurement/run-manifests/qwen3-8b-ollama-show-final-20260830.txt"
QWEN_MODEL_CAPTURE_NORMALIZED_SHA256 = (
    "4f64b8ffadf260ca5de887ab01eee473e789542712d275c77f4724a85833ad4c"
)
QWEN_REQUEST_CONFIG = {
    "provider": "ollama",
    "model_requested": "qwen3:8b",
    "endpoint": "http://localhost:11434/v1/chat/completions",
    "token_parameter": "max_tokens",
    "token_budget": 4096,
    "temperature": 0.6,
    "top_p": 0.95,
    "seed": 42,
    "top_k": "not sent (model default)",
    "repeat_penalty": "not sent (model default)",
    "reasoning_control": "omitted (model default)",
    "structured_outputs": True,
    "response_format": "json_schema_ollama_compatible",
    "provider_schema_omissions": ["attack_technique_id.pattern"],
    "runtime_attack_id_validation": True,
}
QWEN_FINAL_RUNS = {
    "20260830_054251_ollama_oper_baseline": {
        "view": "operational",
        "candidate": "20260827_180830_ollama_oper_baseline",
        "audit_hash":
            "39ecf388af73e1639b2bad206509d093c30b8d233ae5f54a5c60cecc012aba8a",
        "all": (14, 14, 14, 20, 14),
        "attacks": (14, 14, 14, 14, 14),
        "schema_valid": 20,
        "valid_overall": 14,
        "benign_disposition": 0,
        "performance": {
            "prompt_tokens_median": 1587.5,
            "completion_tokens_median": 314,
            "reasoning_tokens_median": None,
            "visible_completion_median": 314,
            "total_tokens_median": 1930.5,
            "latency_ms_median": 163600,
            "latency_ms_sum": 3233286,
        },
    },
    "20260830_070142_ollama_eval_baseline": {
        "view": "evaluation",
        "candidate": "20260827_192445_ollama_eval_baseline",
        "audit_hash":
            "3731f0ac7f822b5069a53cfbff4c958c65c15eb1596c898c444710faec4b9e6d",
        "all": (3, 6, 14, 18, 4),
        "attacks": (2, 5, 13, 13, 4),
        "schema_valid": 20,
        "valid_overall": 4,
        "benign_disposition": 1,
        "performance": {
            "prompt_tokens_median": 1522,
            "completion_tokens_median": 306,
            "reasoning_tokens_median": None,
            "visible_completion_median": 306,
            "total_tokens_median": 1811,
            "latency_ms_median": 168209.5,
            "latency_ms_sum": 3589865,
        },
    },
}

EXPECTED_PROMPT_VERSION = "23185744b88f77b7"
EXPECTED_REDACTION_VERSION = "3a527e33fa159616"
EXPECTED_QWEN_REDACTION_VERSION = "cf0549f832d13b7f"
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


def performance_summary(records: list[dict], run_id: str) -> dict:
    """Return the raw-token and latency figures protected for Qwen runs."""
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

    return {
        "prompt_tokens_median": statistics.median(prompt),
        "completion_tokens_median": statistics.median(completion),
        "reasoning_tokens_median": (statistics.median(reasoning)
                                    if reasoning else None),
        "visible_completion_median": statistics.median(visible),
        "total_tokens_median": statistics.median(total),
        "latency_ms_median": statistics.median(latency),
        "latency_ms_sum": sum(latency),
    }


def verify_qwen_final_evidence() -> None:
    """Protect the accepted Qwen pair, manifests and measured configuration."""
    print("\naccepted qwen3:8b final evidence")
    expected_ids = [f"A{i:02d}" for i in range(1, EXPECTED_RECORDS + 1)]
    final_records: dict[str, dict[str, dict]] = {}

    for run_id, expected in QWEN_FINAL_RUNS.items():
        records = load_audit(run_id)
        if len(records) != EXPECTED_RECORDS:
            fail(f"{run_id}: expected {EXPECTED_RECORDS} audit rows, "
                 f"got {len(records)}")
        ids = [record.get("alert_id") for record in records]
        if ids != expected_ids:
            fail(f"{run_id}: expected ordered IDs A01..A20, got {ids}")
        final_records[run_id] = {record["alert_id"]: record for record in records}

        expected_sets = {
            "run_id": {run_id},
            "provider": {"ollama"},
            "model": {"qwen3:8b"},
            "view": {expected["view"]},
            "git_commit": {QWEN_FINAL_COMMIT_SHORT},
            "prompt_version": {EXPECTED_PROMPT_VERSION},
            "redaction_version": {EXPECTED_QWEN_REDACTION_VERSION},
            "model_actual": {"qwen3:8b"},
            "finish_reason": {"stop"},
            "parse_status": {"valid"},
        }
        for field, wanted in expected_sets.items():
            got = {record.get(field) for record in records}
            if got != wanted:
                fail(f"{run_id}: {field} expected {wanted}, got {got}")
        bad_schema = [record["alert_id"] for record in records
                      if record.get("schema_errors")]
        if bad_schema:
            fail(f"{run_id}: schema errors present for {', '.join(bad_schema)}")
        bad_config = [record["alert_id"] for record in records
                      if record.get("request_config") != QWEN_REQUEST_CONFIG]
        if bad_config:
            fail(f"{run_id}: request configuration changed for "
                 f"{', '.join(bad_config)}")

        audit_path = RUN_ROOT / run_id / "audit-log.jsonl"
        actual_hash = hashlib.sha256(
            normalize_newlines(audit_path.read_bytes())
        ).hexdigest()
        if actual_hash != expected["audit_hash"]:
            fail(f"{run_id}: normalized audit hash expected "
                 f"{expected['audit_hash']}, got {actual_hash}")

        outputs, rows, all_metrics = rebuild(str(audit_path), str(TIMING_LOG))
        if len(outputs) != EXPECTED_RECORDS or len(rows) != EXPECTED_RECORDS:
            fail(f"{run_id}: reconstruction returned {len(outputs)} outputs "
                 f"and {len(rows)} score rows")
        attack_rows = [row for row in rows
                       if row["ground_truth"].strip().lower() != "benign"]
        benign_rows = [row for row in rows
                       if row["ground_truth"].strip().lower() == "benign"]
        actual_all = metric_tuple(all_metrics)
        actual_attacks = metric_tuple(aggregate(attack_rows))
        if actual_all != expected["all"] or actual_attacks != expected["attacks"]:
            fail(f"{run_id}: Qwen metrics changed; expected "
                 f"all={expected['all']} attacks={expected['attacks']}, got "
                 f"all={actual_all} attacks={actual_attacks}")
        schema_valid = sum(bool(row["schema_valid"]) for row in rows)
        valid_overall = sum(bool(row["valid_overall_correct"]) for row in rows)
        if schema_valid != expected["schema_valid"]:
            fail(f"{run_id}: schema_valid expected {expected['schema_valid']}, "
                 f"got {schema_valid}")
        if valid_overall != expected["valid_overall"]:
            fail(f"{run_id}: valid_overall_correct expected "
                 f"{expected['valid_overall']}, "
                 f"got {valid_overall}")
        benign_correct = sum(bool(row["disposition_correct"])
                             for row in benign_rows)
        if benign_correct != expected["benign_disposition"]:
            fail(f"{run_id}: benign disposition expected "
                 f"{expected['benign_disposition']}/6, got {benign_correct}/6")

        actual_performance = performance_summary(records, run_id)
        if actual_performance != expected["performance"]:
            fail(f"{run_id}: performance changed; expected "
                 f"{expected['performance']}, got {actual_performance}")

        manifest_path = ROOT / "measurement" / "run-manifests" / f"{run_id}.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        if manifest.get("status") != "final" or not manifest.get("accepted_as_final"):
            fail(f"{run_id}: manifest is not accepted final evidence")
        if manifest.get("run_id") != run_id or manifest.get("view") != expected["view"]:
            fail(f"{run_id}: manifest identity/view does not match the run")
        provenance = manifest.get("provenance") or {}
        if (not provenance.get("execution_on_committed_code") or
                provenance.get("embedded_git_commit_short") != QWEN_FINAL_COMMIT_SHORT or
                provenance.get("embedded_git_commit_full") != QWEN_FINAL_COMMIT_FULL):
            fail(f"{run_id}: manifest provenance does not pin the execution commit")
        if (manifest.get("integrity") or {}).get(
                "audit_log_normalized_sha256") != expected["audit_hash"]:
            fail(f"{run_id}: manifest audit hash does not match the protected hash")
        if manifest.get("effective_request_config") != QWEN_REQUEST_CONFIG:
            fail(f"{run_id}: manifest request configuration changed")
        model = manifest.get("model") or {}
        if (model.get("tag") != "qwen3:8b" or
                model.get("manifest_digest") != QWEN_MODEL_MANIFEST_DIGEST or
                model.get("model_blob_digest") != QWEN_MODEL_BLOB_DIGEST or
                model.get("ollama_show_capture") != QWEN_MODEL_CAPTURE):
            fail(f"{run_id}: manifest model identity/config capture changed")
        if manifest.get("performance") != expected["performance"]:
            fail(f"{run_id}: manifest performance does not match raw evidence")

        names = ("technique_exact", "technique_relaxed", "disposition",
                 "response_consistent", "overall")
        expected_checks = {
            "audit_rows": EXPECTED_RECORDS,
            "consistent_request_config_rows": EXPECTED_RECORDS,
            "finish_reason_stop": EXPECTED_RECORDS,
            "schema_valid": expected["schema_valid"],
            "all_alert_metrics": {
                **dict(zip(names, expected["all"])),
                "valid_overall": expected["valid_overall"],
            },
            "attack_only_metrics": {
                "n": len(attack_rows),
                **dict(zip(names, expected["attacks"])),
            },
            "benign_disposition_correct":
                f"{expected['benign_disposition']}/{len(benign_rows)}",
        }
        if manifest.get("run_checks") != expected_checks:
            fail(f"{run_id}: manifest run checks do not match re-derived results")

        candidate = {record["alert_id"]: record
                     for record in load_audit(expected["candidate"])}
        mismatched_inputs = [alert_id for alert_id in expected_ids
                             if (candidate[alert_id]["input_hash"] !=
                                 final_records[run_id][alert_id]["input_hash"] or
                                 candidate[alert_id]["redacted_prompt_hash"] !=
                                 final_records[run_id][alert_id]["redacted_prompt_hash"])]
        if mismatched_inputs:
            fail(f"{run_id}: candidate input/prompt mismatch for "
                 f"{', '.join(mismatched_inputs)}")
        response_matches = sum(
            candidate[alert_id]["response_hash"] ==
            final_records[run_id][alert_id]["response_hash"]
            for alert_id in expected_ids
        )
        if response_matches != 0:
            fail(f"{run_id}: expected 0/20 byte-identical candidate responses, "
                 f"got {response_matches}/20")

        print(f"  PASS  {run_id}")
        print(f"        all={actual_all} attacks={actual_attacks} "
              f"schema={schema_valid}/20")
        print(f"        latency median={actual_performance['latency_ms_median']} ms "
              f"sum={actual_performance['latency_ms_sum']} ms")
        print("        candidate prompts match 20/20; responses match 0/20")

    run_ids = list(QWEN_FINAL_RUNS)
    left, right = (final_records[run_id] for run_id in run_ids)
    mismatched = [alert_id for alert_id in expected_ids
                  if left[alert_id]["input_hash"] != right[alert_id]["input_hash"]]
    if mismatched:
        fail(f"accepted Qwen pair: input_hash differs for {', '.join(mismatched)}")
    print("  PASS  input_hash matches 20/20 across accepted Qwen views")

    capture = ROOT / QWEN_MODEL_CAPTURE
    actual_capture_hash = hashlib.sha256(
        normalize_newlines(capture.read_bytes())
    ).hexdigest()
    if actual_capture_hash != QWEN_MODEL_CAPTURE_NORMALIZED_SHA256:
        fail(f"Qwen model capture hash expected "
             f"{QWEN_MODEL_CAPTURE_NORMALIZED_SHA256}, got {actual_capture_hash}")
    print(f"  PASS  post-run model capture = {actual_capture_hash}")


def main() -> int:
    verify_hashes()
    verify_log_content_hashes()
    verify_runs()
    verify_strict_efficiency()
    verify_qwen_final_evidence()
    print("\nPASS: frozen evidence, canonical scoring, §9.8 efficiency and "
          "accepted Qwen evidence verified offline")
    return 0


if __name__ == "__main__":
    sys.exit(main())
