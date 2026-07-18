#!/usr/bin/env python3
"""
Proof that the evaluation view is label-reduced: no ATT&CK technique code
(any case, '.' or '_' separators) and no detection-authored label field
(mitre, rule_id, rule_description, evidence_file, *.key) survives, while raw
host evidence is retained. Addresses report-review item #12.
"""
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from redact import redact_alert
import views

CORPUS = os.environ.get(
    "ALERTMIND_CORPUS",
    str(ROOT.parent / "measurement" / "alert-corpus.json"),
)


def _load():
    data = json.load(open(CORPUS, encoding="utf-8"))
    return data["alerts"] if isinstance(data, dict) else data


class EvaluationViewLeakageTests(unittest.TestCase):
    def setUp(self):
        self.alerts = _load()

    def test_no_technique_code_survives_any_alert(self):
        for a in self.alerts:
            view = views.to_evaluation_view(redact_alert(a))
            leaks = views.evaluation_view_leaks(view)
            self.assertEqual(leaks, [], f"{a['alert_id']} leaked {leaks}")

    def test_label_fields_removed(self):
        for a in self.alerts:
            view = views.to_evaluation_view(redact_alert(a))
            blob = json.dumps(view).lower()
            for field in ("mitre", "rule_id", "rule_description", "evidence_file"):
                self.assertNotIn(f'"{field}"', blob, f"{a['alert_id']} kept {field}")
            self.assertNotIn('.key"', blob, f"{a['alert_id']} kept a .key field")

    def test_raw_evidence_retained(self):
        # the evaluation view must still carry triage-relevant raw fields
        present = 0
        for a in self.alerts:
            view = views.to_evaluation_view(redact_alert(a))
            blob = json.dumps(view).lower()
            if any(tok in blob for tok in
                   ("audit.exe", "audit.command", "image", "commandline",
                    "targetfilename", "grantedaccess", "registry", "path")):
                present += 1
        self.assertEqual(present, len(self.alerts),
                         "some alerts lost all raw evidence")

    def test_operational_view_is_unchanged(self):
        a = self.alerts[0]
        self.assertEqual(views.apply_view(a, "operational"), a)


if __name__ == "__main__":
    unittest.main(verbosity=2)
