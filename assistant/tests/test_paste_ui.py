#!/usr/bin/env python3
"""Streamlit rerun-state regressions for the Paste & inspect tab."""
import os
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE if (HERE / "app.py").exists() else HERE.parent
PROJECT_ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault(
    "ALERTMIND_CORPUS", str(PROJECT_ROOT / "measurement" / "alert-corpus.json")
)
os.environ.setdefault(
    "ALERTMIND_TIMING", str(PROJECT_ROOT / "measurement" / "timing-log.csv")
)

from streamlit.testing.v1 import AppTest  # noqa: E402


def _widget(sequence, label):
    return next(item for item in sequence if item.label == label)


def _has_state(app, key):
    try:
        app.session_state[key]
        return True
    except KeyError:
        return False


class PasteUiStateTests(unittest.TestCase):
    def setUp(self):
        self.app = AppTest.from_file(str(ROOT / "app.py")).run(timeout=15)
        self.assertEqual(len(self.app.exception), 0)

    def _click(self, label):
        _widget(self.app.button, label).click()
        self.app.run(timeout=15)

    def test_app_renders_paste_tab(self):
        self.assertIn("🧪 Paste & inspect", [tab.label for tab in self.app.tabs])

    def test_default_offline_ui_contract(self):
        self.assertEqual(_widget(self.app.radio, "Mode").value, "Analyst")
        self.assertEqual(_widget(self.app.selectbox, "Provider").value, "mock")
        self.assertEqual(_widget(self.app.text_input, "Model").value, "mock")
        self.assertEqual(_widget(self.app.selectbox, "View").value, "operational")
        self.assertEqual(_widget(self.app.selectbox, "Prompt").value, "baseline")
        self.assertEqual(
            [tab.label for tab in self.app.tabs],
            ["🔎 Triage one alert", "🧪 Paste & inspect"],
        )

    def test_evaluator_mode_adds_scoring_without_removing_paste(self):
        _widget(self.app.radio, "Mode").set_value("Evaluator")
        self.app.run(timeout=15)
        self.assertEqual(
            [tab.label for tab in self.app.tabs],
            [
                "🔎 Triage one alert",
                "🧪 Paste & inspect",
                "📊 Evaluator scoring",
            ],
        )

    def test_loading_new_sample_clears_result_and_draft(self):
        self._click("Load synthetic secrets example")
        self._click("Run paste & inspect")
        first_id = self.app.session_state["paste_result"]["result_id"]
        draft = _widget(self.app.text_area, "Draft user message (editable)")
        draft.set_value("CUSTOM-EDIT-FROM-FIRST-ALERT")
        self.app.run(timeout=15)

        self._click("Load synthetic injection example")
        self.assertFalse(_has_state(self.app, "paste_result"))
        self.assertFalse(_has_state(self.app, f"paste_draft_{first_id}"))

        self._click("Run paste & inspect")
        second = _widget(self.app.text_area, "Draft user message (editable)")
        self.assertNotEqual(second.value, "CUSTOM-EDIT-FROM-FIRST-ALERT")

    def test_invalid_input_does_not_leave_previous_result(self):
        self._click("Load synthetic secrets example")
        self._click("Run paste & inspect")
        self.assertTrue(_has_state(self.app, "paste_result"))

        _widget(self.app.text_area, "Alert JSON or plain text").set_value("")
        self.app.run(timeout=15)
        self._click("Run paste & inspect")
        self.assertFalse(_has_state(self.app, "paste_result"))
        self.assertTrue(any("Empty input" in str(err.value) for err in self.app.error))

    def test_consent_resets_when_input_changes(self):
        _widget(self.app.selectbox, "Provider").set_value("openai")
        self.app.run(timeout=15)
        _widget(self.app.text_area, "Alert JSON or plain text").set_value('{"a": 1}')
        self.app.run(timeout=15)
        consent_label = (
            "I confirm this alert is synthetic or approved for processing by the "
            "selected external provider."
        )
        _widget(self.app.checkbox, consent_label).check()
        self.app.run(timeout=15)
        self.assertTrue(_widget(self.app.checkbox, consent_label).value)

        _widget(self.app.text_area, "Alert JSON or plain text").set_value(
            '{"different": 2}'
        )
        self.app.run(timeout=15)
        self.assertFalse(_widget(self.app.checkbox, consent_label).value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
