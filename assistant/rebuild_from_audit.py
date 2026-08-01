#!/usr/bin/env python3
"""
rebuild_from_audit.py — rebuild assistant_outputs.json + assistant_scoring.csv
from a run's audit-log.jsonl.

Use when a run completed (audit-log.jsonl written) but the summary files did not
(e.g. a Windows MAX_PATH crash), or to re-score saved responses with the current
validator/scorer. No model call is made. By default, regenerated files go to
outputs/rebuilt/<run_id>/ and never replace the committed run evidence.

Usage:
  python rebuild_from_audit.py <path-to-audit-log.jsonl>
  python rebuild_from_audit.py <path-to-audit-log.jsonl> --score-only
  python rebuild_from_audit.py <path-to-audit-log.jsonl> --output-dir <directory>

Existing regenerated files are replaced only when --overwrite is explicit.
Ground truth defaults to the repository's measurement/timing-log.csv, resolved
relative to this script rather than the caller's working directory.
"""
import argparse
import csv
import json
import os

from llm import parse_response
from schema import validate_output
from scoring import score_alert, aggregate


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_SCRIPT_DIR)


def _win_long(path):
    if os.name == "nt":
        p = os.path.abspath(path)
        return p if p.startswith("\\\\?\\") else "\\\\?\\" + p
    return path


def load_ground_truth(path):
    if not path:
        raise ValueError("A timing log is required to reconstruct scoring.")
    path = os.path.abspath(path)
    if not os.path.exists(_win_long(path)):
        raise FileNotFoundError(
            f"Timing log not found: {path}. Pass --timing-log with the ground-truth CSV."
        )
    gt = {}
    with open(_win_long(path), newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            gt[row["alert_id"].strip()] = row.get("ground_truth", "").strip()
    if not gt:
        raise ValueError(f"Timing log contains no ground-truth rows: {path}")
    return gt


def default_timing_log():
    """Return the repository timing log independently of the caller's cwd."""
    return os.path.join(_REPO_ROOT, "measurement", "timing-log.csv")


def default_output_dir(audit_log):
    """Keep derived files outside the immutable source-run directory."""
    run_id = os.path.basename(os.path.dirname(os.path.abspath(audit_log)))
    return os.path.join(_SCRIPT_DIR, "outputs", "rebuilt", run_id)


def rebuild(audit_log, timing_log):
    """Return regenerated outputs, score rows and aggregate metrics in memory."""
    audit_log = os.path.abspath(audit_log)
    if not os.path.exists(_win_long(audit_log)):
        raise FileNotFoundError(f"Audit log not found: {audit_log}")

    ground = load_ground_truth(timing_log)

    outputs, score_rows = {}, []
    with open(_win_long(audit_log), encoding="utf-8") as f:
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

    return outputs, score_rows, aggregate(score_rows)


def write_outputs(output_dir, outputs, score_rows, overwrite=False):
    """Write derived files, refusing to replace either target by default."""
    output_dir = os.path.abspath(output_dir)
    json_path = os.path.join(output_dir, "assistant_outputs.json")
    csv_path = os.path.join(output_dir, "assistant_scoring.csv")
    existing = [p for p in (json_path, csv_path) if os.path.exists(_win_long(p))]
    if existing and not overwrite:
        names = ", ".join(os.path.basename(p) for p in existing)
        raise FileExistsError(
            f"Refusing to replace existing rebuilt file(s): {names}. "
            "Choose another --output-dir or pass --overwrite explicitly."
        )

    os.makedirs(_win_long(output_dir), exist_ok=True)

    with open(_win_long(json_path), "w", encoding="utf-8") as f:
        json.dump(outputs, f, indent=2)
    with open(_win_long(csv_path), "w", newline="", encoding="utf-8") as f:
        cols = ["alert_id", "ground_truth", "assistant_tag", "assistant_disposition", "confidence",
                "technique_exact_correct", "technique_relaxed_correct", "disposition_correct",
                "response_consistent", "overall_correct"]
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(score_rows)

    return json_path, csv_path


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("audit_log")
    ap.add_argument("--timing-log", default=default_timing_log())
    ap.add_argument(
        "--output-dir",
        help="Destination for regenerated files (default: assistant/outputs/rebuilt/<run_id>).",
    )
    ap.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacement of existing files in the selected output directory.",
    )
    ap.add_argument(
        "--score-only",
        action="store_true",
        help="Print reconstructed metrics without writing any files.",
    )
    args = ap.parse_args(argv)
    if args.score_only and (args.output_dir or args.overwrite):
        ap.error("--score-only cannot be combined with --output-dir or --overwrite")

    outputs, score_rows, agg = rebuild(args.audit_log, args.timing_log)

    n = agg["n"] or 1
    print(f"reconstructed {agg['n']} alerts from {os.path.basename(args.audit_log)}")
    print(f"  technique exact {agg['technique_exact_correct']}/{n} · relaxed "
          f"{agg['technique_relaxed_correct']}/{n} · disposition {agg['disposition_correct']}/{n} "
          f"· consistent {agg['response_consistent']}/{n} · OVERALL {agg['overall_correct']}/{n}")
    print(f"  timing ground truth: {os.path.abspath(args.timing_log)}")

    if args.score_only:
        print("  score-only: no files written")
        return

    output_dir = args.output_dir or default_output_dir(args.audit_log)
    write_outputs(output_dir, outputs, score_rows, overwrite=args.overwrite)
    print(f"  wrote assistant_outputs.json + assistant_scoring.csv to {os.path.abspath(output_dir)}")


if __name__ == "__main__":
    main()
