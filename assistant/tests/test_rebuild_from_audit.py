#!/usr/bin/env python3
"""Regression tests for non-destructive audit-log reconstruction."""

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import rebuild_from_audit as rebuild  # noqa: E402


def model_output():
    return {
        "summary": ["A scheduled task was created."],
        "attack_technique_id": "T1053.003",
        "attack_technique_name": "Scheduled Task/Job: Cron",
        "disposition_suggestion": "needs_investigation",
        "confidence": "medium",
        "investigation_queries": ["rule.id:100200", "agent.name:win-victim"],
        "draft_user_message": "Please confirm whether this task was expected.",
        "caveats": "Administrative activity can create scheduled tasks.",
    }


class RebuildSafetyTests(unittest.TestCase):
    def make_inputs(self, root):
        run_dir = root / "source-run"
        run_dir.mkdir()
        audit = run_dir / "audit-log.jsonl"
        audit.write_text(
            json.dumps({"alert_id": "A01", "raw_response": json.dumps(model_output())}) + "\n",
            encoding="utf-8",
        )
        timing = root / "timing-log.csv"
        with timing.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["alert_id", "ground_truth"])
            writer.writeheader()
            writer.writerow({"alert_id": "A01", "ground_truth": "T1053.003"})
        return run_dir, audit, timing

    def test_default_paths_are_cwd_independent_and_non_destructive(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir, audit, _ = self.make_inputs(Path(td))
            output = Path(rebuild.default_output_dir(audit))
            self.assertNotEqual(output, run_dir)
            self.assertEqual(output.name, run_dir.name)
            self.assertEqual(output.parent.name, "rebuilt")
        self.assertEqual(Path(rebuild.default_timing_log()).name, "timing-log.csv")
        self.assertEqual(Path(rebuild.default_timing_log()).parent.name, "measurement")

    def test_score_only_does_not_write_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir, audit, timing = self.make_inputs(Path(td))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                rebuild.main([str(audit), "--timing-log", str(timing), "--score-only"])
            self.assertFalse((run_dir / "assistant_outputs.json").exists())
            self.assertFalse((run_dir / "assistant_scoring.csv").exists())
            self.assertIn("score-only: no files written", stream.getvalue())
            self.assertIn("schema valid 1/1", stream.getvalue())
            self.assertIn("VALID overall 1/1", stream.getvalue())

    def test_default_main_destination_is_separate_from_source_run(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run_dir, audit, timing = self.make_inputs(root)
            destination = root / "derived" / run_dir.name
            stream = io.StringIO()
            with patch.object(rebuild, "default_output_dir", return_value=str(destination)):
                with contextlib.redirect_stdout(stream):
                    rebuild.main([str(audit), "--timing-log", str(timing)])
            self.assertTrue((destination / "assistant_outputs.json").exists())
            self.assertTrue((destination / "assistant_scoring.csv").exists())
            self.assertFalse((run_dir / "assistant_outputs.json").exists())
            self.assertFalse((run_dir / "assistant_scoring.csv").exists())
            with (destination / "assistant_scoring.csv").open(
                newline="", encoding="utf-8"
            ) as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["schema_valid"], "True")
            self.assertEqual(row["valid_overall_correct"], "True")

    def test_existing_rebuilt_files_require_explicit_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            run_dir, audit, timing = self.make_inputs(root)
            outputs, rows, _ = rebuild.rebuild(str(audit), str(timing))
            destination = root / "rebuilt"
            rebuild.write_outputs(str(destination), outputs, rows)
            with self.assertRaisesRegex(FileExistsError, "--overwrite"):
                rebuild.write_outputs(str(destination), outputs, rows)
            rebuild.write_outputs(str(destination), outputs, rows, overwrite=True)
            self.assertFalse((run_dir / "assistant_outputs.json").exists())

    def test_missing_timing_log_fails_clearly(self):
        with tempfile.TemporaryDirectory() as td:
            _, audit, _ = self.make_inputs(Path(td))
            with self.assertRaisesRegex(FileNotFoundError, "--timing-log"):
                rebuild.rebuild(str(audit), str(Path(td) / "missing.csv"))


if __name__ == "__main__":
    unittest.main()
