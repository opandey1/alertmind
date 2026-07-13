#!/usr/bin/env python3
"""
runner.py — process the frozen alert corpus through the AlertMind assistant.

Pipeline per alert:  redact -> build prompt -> call LLM -> parse -> log -> score

Outputs (into --outdir, default assistant/outputs/):
  assistant_outputs.json  - the four deliverables per alert (summary, ATT&CK tag,
                            investigation queries, draft user message) — what the
                            analyst reads during the ASSISTED triage pass.
  assistant_scoring.csv   - alert_id, ground_truth, assistant_tag,
                            disposition_suggestion, assistant_tag_correct — the
                            hallucination / tag-accuracy measure, computed vs the
                            ground truth in timing-log.csv.
  audit-log.jsonl         - one line per call: timestamp, model, the REDACTED
                            prompt actually sent, and the raw response (evidence
                            that no secrets left the environment + full traceability).

Usage:
  python runner.py --provider mock                       # offline, no setup
  python runner.py --provider ollama --model llama3.1    # local model
  python runner.py --provider anthropic --model claude-... (ANTHROPIC_API_KEY set)
  python runner.py --provider openai --model gpt-...      (OPENAI_API_KEY set)
"""
import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone

from redact import redact_alert
from prompts import SYSTEM_PROMPT, build_user_prompt
from llm import call_llm, parse_response


def _codes(s: str):
    """Extract ATT&CK technique codes from a ground-truth / tag string."""
    return set(re.findall(r"T\d{4}(?:\.\d{3})?", s or "", re.I))


def _base(code: str):
    return code.split(".")[0].upper()


def score(ground_truth: str, parsed: dict) -> bool:
    """
    True if the assistant's call agrees with ground truth.
      benign GT  -> correct iff the assistant suggested 'likely_benign'
      attack GT  -> correct iff the assistant's technique (sub or parent) is in GT
    """
    disp = (parsed.get("disposition_suggestion") or "").lower()
    if (ground_truth or "").strip().lower() == "benign":
        return disp == "likely_benign"
    gt = _codes(ground_truth)
    tid = (parsed.get("attack_technique_id") or "").upper()
    if not tid or not gt:
        return False
    if tid in gt:
        return True
    # allow parent<->sub-technique match
    return _base(tid) in {_base(c) for c in gt}


def load_ground_truth(path):
    gt = {}
    if path and os.path.exists(path):
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                gt[row["alert_id"].strip()] = row.get("ground_truth", "").strip()
    return gt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="mock", choices=["mock", "anthropic", "openai", "ollama"])
    ap.add_argument("--model", default="mock")
    ap.add_argument("--corpus", default="../measurement/alert-corpus.json")
    ap.add_argument("--timing-log", default="../measurement/timing-log.csv")
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--limit", type=int, default=0, help="process only N alerts (0=all)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    corpus = json.load(open(args.corpus, encoding="utf-8"))
    alerts = corpus["alerts"] if isinstance(corpus, dict) else corpus
    if args.limit:
        alerts = alerts[: args.limit]
    ground = load_ground_truth(args.timing_log)

    audit_path = os.path.join(args.outdir, "audit-log.jsonl")
    outputs, scoring = {}, []
    with open(audit_path, "w", encoding="utf-8") as audit:
        for a in alerts:
            aid = a["alert_id"]
            redacted = redact_alert(a)                      # GUARDRAIL: strip secrets first
            user = build_user_prompt(redacted)
            try:
                raw = call_llm(args.provider, SYSTEM_PROMPT, user, args.model)
            except Exception as e:                          # never crash the batch
                raw = json.dumps({"_error": str(e)})
            parsed = parse_response(raw)
            gt = ground.get(aid, "")
            correct = score(gt, parsed)

            parsed["_alert_id"] = aid
            parsed["analyst_review_required"] = True         # GUARDRAIL: draft only
            outputs[aid] = parsed
            scoring.append({
                "alert_id": aid,
                "ground_truth": gt,
                "assistant_tag": parsed.get("attack_technique_id"),
                "disposition_suggestion": parsed.get("disposition_suggestion"),
                "confidence": parsed.get("confidence"),
                "assistant_tag_correct": "TRUE" if correct else "FALSE",
            })
            audit.write(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "alert_id": aid, "provider": args.provider, "model": args.model,
                "redacted_prompt": user,           # exactly what was sent — proof of no-secrets
                "raw_response": raw,
            }) + "\n")
            print(f"  {aid}: tag={parsed.get('attack_technique_id')} "
                  f"disp={parsed.get('disposition_suggestion')} correct={correct}")

    json.dump(outputs, open(os.path.join(args.outdir, "assistant_outputs.json"), "w", encoding="utf-8"), indent=2)
    with open(os.path.join(args.outdir, "assistant_scoring.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["alert_id", "ground_truth", "assistant_tag",
                                          "disposition_suggestion", "confidence", "assistant_tag_correct"])
        w.writeheader()
        w.writerows(scoring)

    n = len(scoring)
    ok = sum(1 for s in scoring if s["assistant_tag_correct"] == "TRUE")
    benign = [s for s in scoring if s["ground_truth"].lower() == "benign"]
    benign_ok = sum(1 for s in benign if s["assistant_tag_correct"] == "TRUE")
    print(f"\n[{args.provider}/{args.model}] {n} alerts | tag/disposition correct: {ok}/{n} "
          f"({100*ok//max(n,1)}%) | benign correctly identified: {benign_ok}/{len(benign)}")
    print(f"outputs: {args.outdir}/assistant_outputs.json, assistant_scoring.csv, audit-log.jsonl")


if __name__ == "__main__":
    sys.exit(main())
