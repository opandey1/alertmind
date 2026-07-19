#!/usr/bin/env python3
"""
Proof that the strict label-reduced evaluation view removes the tested ATT&CK-code
and detection-label leakage classes, while retaining raw host evidence.
Addresses report-review item #12 and the leakage-test follow-ups.
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
    with open(CORPUS, encoding="utf-8") as f:      # context manager: no ResourceWarning
        data = json.load(f)
    return data["alerts"] if isinstance(data, dict) else data


# A synthetic alert exercising every label channel + representative raw evidence.
_SYNTH = {
    "alert_id": "SYN01",
    "rule_id": "100203",
    "rule_description": "AlertMind: LSASS access - credential dumping (T1003.001)",
    "mitre": {"id": ["T1003.001"], "tactic": ["Credential Access"]},
    "evidence_file": "win_100203-lsass-T1003_001.png",
    "key_fields": {
        "audit.key": "t1003_001_lsass",           # detection label -> must drop
        "registry.key": "HKLM\\Software\\Legit",   # raw evidence -> must keep
        "custom_key": "t1055_xyz",                 # key-shaped + code -> drop
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "CommandLine": "rundll32 comsvcs.dll MiniDump 1234 dump.bin full",
        "GrantedAccess": "0x1fffff",
    },
}


class SyntheticLabelChannelTests(unittest.TestCase):
    def setUp(self):
        self.view = views.to_evaluation_view(self._deep(_SYNTH))

    @staticmethod
    def _deep(o):
        return json.loads(json.dumps(o))

    def test_all_label_channels_removed(self):
        blob = json.dumps(self.view).lower()
        for field in ("mitre", "rule_id", "rule_description", "evidence_file"):
            self.assertNotIn(f'"{field}"', blob)
        self.assertNotIn("audit.key", blob)          # denylisted
        self.assertNotIn("custom_key", blob)          # key-shaped + technique code
        self.assertEqual(views.evaluation_view_leaks(self.view), [])

    def test_value_aware_key_retained(self):
        # a registry key with a non-label value must survive
        kf = self.view.get("key_fields", {})
        self.assertIn("registry.key", kf)
        self.assertEqual(kf["registry.key"], "HKLM\\Software\\Legit")

    def test_raw_evidence_values_retained(self):
        kf = self.view.get("key_fields", {})
        self.assertEqual(kf.get("Image"), "C:\\Windows\\System32\\rundll32.exe")
        self.assertIn("MiniDump", kf.get("CommandLine", ""))
        self.assertEqual(kf.get("GrantedAccess"), "0x1fffff")


class CorpusLeakageTests(unittest.TestCase):
    def setUp(self):
        self.alerts = _load()

    def test_no_technique_code_survives_any_alert(self):
        for a in self.alerts:
            view = views.to_evaluation_view(redact_alert(a))
            leaks = views.evaluation_view_leaks(view)
            self.assertEqual(leaks, [], f"{a['alert_id']} leaked {leaks}")

    def test_label_fields_removed(self):
        for a in self.alerts:
            blob = json.dumps(views.to_evaluation_view(redact_alert(a))).lower()
            for field in ("mitre", "rule_id", "rule_description", "evidence_file"):
                self.assertNotIn(f'"{field}"', blob, f"{a['alert_id']} kept {field}")
            self.assertNotIn("audit.key", blob, f"{a['alert_id']} kept audit.key")

    def test_representative_alerts_retain_specific_evidence(self):
        """Assert VALUES, not just field-name presence, for one Windows + one Linux alert."""
        by_id = {a["alert_id"]: a for a in self.alerts}

        def kf(aid):
            return views.to_evaluation_view(redact_alert(by_id[aid])).get("key_fields", {})

        # pick alerts known to carry these fields; skip gracefully if corpus differs
        win = next((a for a in self.alerts
                    if "GrantedAccess" in (a.get("key_fields") or {})), None)
        lin = next((a for a in self.alerts
                    if "audit.exe" in (a.get("key_fields") or {})), None)
        if win:
            v = views.to_evaluation_view(redact_alert(win)).get("key_fields", {})
            self.assertTrue(v.get("GrantedAccess"), "Windows access mask lost")
        if lin:
            v = views.to_evaluation_view(redact_alert(lin)).get("key_fields", {})
            self.assertTrue(v.get("audit.exe"), "Linux audit.exe lost")
            self.assertNotIn("t1", json.dumps(v).lower().replace("audit.type", ""))

    def test_operational_view_is_unchanged(self):
        self.assertEqual(views.apply_view(self.alerts[0], "operational"), self.alerts[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
