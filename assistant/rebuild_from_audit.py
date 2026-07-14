#!/usr/bin/env python3
"""
rebuild_from_audit.py — rebuild assistant_outputs.json + assistant_scoring.csv
from a run's audit-log.jsonl.

Use when a run completed (audit-log.jsonl written) but the summary files did not
(e.g. a Windows MAX_PATH crash). The audit log holds every raw model response, so
scoring is reproduced offline with no model re-run.

Usage:
  python rebuild_from_audit.py <path-to-audit-log.jsonl> [--timing-log ../measurement/timing-log.csv]
Outputs are written next to the audit log.
"""
import argparse
import csv
import json
import os

from llm import parse_response
from schema import validate_output
from scoring import score_alert, aggregate


def _win_long(path):
    if os.name == "nt":
        p = os.path.abspath(path)
        return p if p.startswith("\\\\?\\") else "\\\\?\\" + p
    return path


def load_ground_truth(path):
    gt = {}
    if path and os.path.exists(path):
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                gt[row["alert_id"].strip()] = row.get("ground_truth", "").strip()
    return gt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("audit_log")
    ap.add_argument("--timing-log", default="../measurement/timing-log.csv")
    args = ap.parse_args()

    run_dir = os.path.dirname(os.path.abspath(args.audit_log))
    ground = load_ground_truth(args.timing_log)

    outputs, score_rows = {}, []
    with open(_win_long(args.audit_log), encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            aid = rec["alert_id"]
            parsed = parse_response(rec["raw_response"])
            ok, errors, parsed = validate_output(parsed)
            parsed["_alert_id"] = aid
            parsed["analyst_review_required"] = True
            gt = ground.get(aid, "")
            sc = score_alert(gt, parsed)
            outputs[aid] = parsed
            score_rows.append({"alert_id": aid, "ground_truth": gt,
                               "confidence": parsed.get("confidence"), **sc})

    json.dump(outputs, open(_win_long(os.path.join(run_dir, "assistant_outputs.json")), "w",
                            encoding="utf-8"), indent=2)
    with open(_win_long(os.path.join(run_dir, "assistant_scoring.csv")), "w", newline="",
              encoding="utf-8") as f:
        cols = ["alert_id", "ground_truth", "assistant_tag", "assistant_disposition", "confidence",
                "technique_exact_correct", "technique_relaxed_correct", "disposition_correct",
                "response_consistent", "overall_correct"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(score_rows)

    agg = aggregate(score_rows); n = agg["n"] or 1
    print(f"rebuilt {agg['n']} alerts from {os.path.basename(args.audit_log)}")
    print(f"  technique exact {agg['technique_exact_correct']}/{n} · relaxed "
          f"{agg['technique_relaxed_correct']}/{n} · disposition {agg['disposition_correct']}/{n} "
          f"· consistent {agg['response_consistent']}/{n} · OVERALL {agg['overall_correct']}/{n}")
    print(f"  wrote assistant_outputs.json + assistant_scoring.csv to {run_dir}")


if __name__ == "__main__":
    main()
