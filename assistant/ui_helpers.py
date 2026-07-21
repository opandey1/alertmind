"""ui_helpers.py — side-effect-free presentation helpers shared by app.py and
paste_tab.py (importing app.py would run Streamlit code at import time)."""


def disposition_color(disp: str) -> str:
    return {"likely_true_positive": "red", "likely_benign": "green",
            "needs_investigation": "orange"}.get(disp, "gray")
