#!/usr/bin/env python3
"""
runner.py — process the frozen alert corpus through the AlertMind assistant.

Pipeline per alert:  redact -> apply view -> build prompt -> call LLM -> parse ->
                     validate -> log -> score

Views (--view):
  operational  (default) full redacted alert incl. the rule's ATT&CK metadata.
               Realistic; technique match here is METADATA CONSISTENCY.
  evaluation   strips mitre / rule_id / T-codes so the model must CLASSIFY from
               raw fields. This is the defensible ATT&CK-accuracy measurement.

Outputs go to a fresh, non-overwriting run directory: outputs/runs/<run_id>/
  assistant_outputs.json  - the four deliverables per alert (analyst reads these)
  assistant_scoring.csv   - per-alert multi-metric scores vs ground truth
  audit-log.jsonl         - per-call record incl. the REDACTED prompt sent,
                            hashes, latency, parse status, parsed output

Usage:
  python runner.py --provider mock
  python runner.py --provider ollama --model llama3.1:8b --view evaluation
  python runner.py --provider ollama --model qwen3:8b --view evaluation \
      --alert-ids A04,A06,A10,A12,A16,A18
"""
import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

from redact import redact_alert
from views import apply_view
from prompts import get_system_prompt, build_user_prompt
from llm import call_llm_meta, parse_response
from scoring import score_alert, aggregate
from schema import validate_output


def _win_long(path):
    """Windows MAX_PATH(260) workaround: use the \\\\?\\ extended-length prefix.
    No-op off Windows."""
    if os.name == "nt":
        p = os.path.abspath(path)
        return p if p.startswith("\\\\?\\") else "\\\\?\\" + p
    return path


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


def _git_commit() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def load_ground_truth(path):
    gt = {}
    if path and os.path.exists(path):
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                gt[row["alert_id"].strip()] = row.get("ground_truth", "").strip()
    return gt


def select_alerts(alerts, alert_ids="", limit=0):
    """Select a diagnostic subset without modifying the frozen corpus.

    Explicit IDs retain corpus order. `--alert-ids` and `--limit` are mutually
    exclusive so a run cannot silently select a different set than intended.
    """
    if limit < 0:
        raise ValueError("--limit must be zero or a positive integer")
    if alert_ids and limit:
        raise ValueError("--alert-ids cannot be combined with --limit")
    if not alert_ids:
        return list(alerts[:limit]) if limit else list(alerts)

    requested = {item.strip() for item in alert_ids.split(",") if item.strip()}
    if not requested:
        raise ValueError("--alert-ids must contain at least one alert ID")
    available = {a.get("alert_id") for a in alerts}
    unknown = sorted(requested - available)
    if unknown:
        raise ValueError(f"unknown alert ID(s): {', '.join(unknown)}")
    return [a for a in alerts if a.get("alert_id") in requested]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="mock", choices=["mock", "anthropic", "openai", "ollama"])
    ap.add_argument("--model", default="mock")
    ap.add_argument("--view", default="operational", choices=["operational", "evaluation"])
    ap.add_argument("--prompt", default="baseline", choices=["baseline", "benign_aware"])
    ap.add_argument("--corpus", default="../measurement/alert-corpus.json")
    ap.add_argument("--timing-log", default="../measurement/timing-log.csv")
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument(
        "--alert-ids",
        default="",
        metavar="A04,A06",
        help="diagnostic subset of comma-separated corpus alert IDs; cannot be combined with --limit",
    )
    args = ap.parse_args()

    corpus = json.load(open(args.corpus, encoding="utf-8"))
    alerts = corpus["alerts"] if isinstance(corpus, dict) else corpus
    try:
        alerts = select_alerts(alerts, args.alert_ids, args.limit)
    except ValueError as exc:
        ap.error(str(exc))
    ground = load_ground_truth(args.timing_log)

    system = get_system_prompt(args.prompt)
    prompt_version = _sha(system)
    redaction_version = _sha(open(os.path.join(os.path.dirname(__file__), "redact.py")).read())
    git_commit = _git_commit()
    scope_suffix = f"_subset{len(alerts)}" if args.alert_ids else ""
    run_id = (f"{datetime.now(timezone.utc):%Y%m%d_%H%M%S}_"
              f"{args.provider}_{args.view[:4]}_{args.prompt}{scope_suffix}")
    run_dir = os.path.join(args.outdir, "runs", run_id)
    os.makedirs(_win_long(run_dir), exist_ok=True)

    outputs, score_rows = {}, []
    with open(_win_long(os.path.join(run_dir, "audit-log.jsonl")), "w", encoding="utf-8") as audit:
        for a in alerts:
            aid = a["alert_id"]
            redacted = redact_alert(a)                       # GUARDRAIL: secrets stripped first
            viewed = apply_view(redacted, args.view)          # then choose how much metadata to show
            user = build_user_prompt(viewed)

            t0 = time.time()
            call_meta = {}
            try:
                raw, call_meta = call_llm_meta(args.provider, system, user, args.model)
                err = None
            except Exception as e:
                raw, err = json.dumps({"_error": str(e)}), str(e)
                # ProviderError carries the request config, and the response
                # metadata (usage / reasoning_tokens / finish_reason) when a
                # response was received — keep it: this is the failure the
                # diagnostics exist for.
                call_meta = getattr(e, "meta", {}) or {}
            latency_ms = int((time.time() - t0) * 1000)

            parsed = parse_response(raw)
            ok, errors, parsed = validate_output(parsed)
            parse_status = "error" if err else ("parse_error" if parsed.get("_parse_error")
                                                else ("valid" if ok else "schema_invalid"))
            parsed["_alert_id"] = aid
            parsed["analyst_review_required"] = True          # GUARDRAIL: draft only

            gt = ground.get(aid, "")
            sc = score_alert(gt, parsed)
            # Preserve every pre-registered metric, but add a validity-gated
            # result so schema-invalid output cannot receive apparent overall
            # credit (for example a recognizable but malformed ATT&CK ID).
            sc["schema_valid"] = parse_status == "valid"
            sc["valid_overall_correct"] = (
                sc["schema_valid"] and sc["overall_correct"]
            )
            outputs[aid] = parsed
            score_rows.append({"alert_id": aid, "ground_truth": gt,
                               "confidence": parsed.get("confidence"), **sc})

            audit.write(json.dumps({
                "run_id": run_id, "ts": datetime.now(timezone.utc).isoformat(),
                "alert_id": aid, "provider": args.provider, "model": args.model,
                "view": args.view, "prompt_name": args.prompt, "prompt_version": prompt_version,
                "redaction_version": redaction_version, "git_commit": git_commit,
                "input_hash": _sha(json.dumps(a, sort_keys=True)),
                "redacted_prompt": user,                      # proof: exactly what was sent
                "redacted_prompt_hash": _sha(user),
                "response_hash": _sha(raw), "latency_ms": latency_ms,
                "parse_status": parse_status, "schema_errors": errors,
                # Effective request config + provider response metadata: the run's
                # interpretation depends on reasoning effort and token allocation,
                # and on WHICH model snapshot actually served the request.
                "request_config": call_meta.get("request_config"),
                "model_actual": call_meta.get("model_actual"),
                "response_id": call_meta.get("response_id"),
                "system_fingerprint": call_meta.get("system_fingerprint"),
                "finish_reason": call_meta.get("finish_reason"),
                "usage": call_meta.get("usage"),
                "parsed_output": parsed, "raw_response": raw,
            }) + "\n")
            print(f"  {aid}: tag={sc['assistant_tag']} disp={sc['assistant_disposition']} "
                  f"overall={sc['overall_correct']} ({parse_status})")

    json.dump(outputs, open(_win_long(os.path.join(run_dir, "assistant_outputs.json")), "w", encoding="utf-8"), indent=2)
    with open(_win_long(os.path.join(run_dir, "assistant_scoring.csv")), "w", newline="", encoding="utf-8") as f:
        cols = ["alert_id", "ground_truth", "assistant_tag", "assistant_disposition", "confidence",
                "technique_exact_correct", "technique_relaxed_correct", "disposition_correct",
                "response_consistent", "overall_correct", "schema_valid",
                "valid_overall_correct"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(score_rows)
    try:
        os.chmod(_win_long(os.path.join(run_dir, "audit-log.jsonl")), 0o600)  # even redacted logs are sensitive
    except OSError:
        pass

    agg = aggregate(score_rows)
    n = agg["n"] or 1
    print(f"\n[{args.provider}/{args.model} · {args.view} view · {args.prompt} prompt] {agg['n']} alerts")
    print(f"  technique exact:   {agg['technique_exact_correct']}/{n}")
    print(f"  technique relaxed: {agg['technique_relaxed_correct']}/{n}")
    print(f"  disposition:       {agg['disposition_correct']}/{n}")
    print(f"  consistent:        {agg['response_consistent']}/{n}")
    print(f"  OVERALL correct:   {agg['overall_correct']}/{n}")
    schema_valid = sum(1 for row in score_rows if row["schema_valid"])
    valid_overall = sum(1 for row in score_rows if row["valid_overall_correct"])
    print(f"  schema valid:      {schema_valid}/{n}")
    print(f"  VALID overall:     {valid_overall}/{n} (schema-valid responses only)")
    print(f"outputs: {run_dir}/")


if __name__ == "__main__":
    sys.exit(main())
