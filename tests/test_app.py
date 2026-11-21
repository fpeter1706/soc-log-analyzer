import os

from streamlit.testing.v1 import AppTest

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")


def test_app_loads_and_runs_analysis():
    at = AppTest.from_file(APP, default_timeout=90).run()
    assert not at.exception
    [b for b in at.sidebar.button if b.label == "Run analysis"][0].click().run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Events parsed"] == "4397" and int(metrics["Alerts"]) >= 8
