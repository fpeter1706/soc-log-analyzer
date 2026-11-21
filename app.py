"""SOC Log Analyzer dashboard (Streamlit)."""
import os

import pandas as pd
import plotly.express as px
import streamlit as st

from soc import ai_triage, anomaly, db, detector, parser
from soc import rules as rules_mod

SEVERITIES = ["Critical", "High", "Medium", "Low"]
COLORS = {"Critical": "#b71c1c", "High": "#ef6c00", "Medium": "#f9a825", "Low": "#2e7d32"}
BASE = os.path.dirname(os.path.abspath(__file__))

st.set_page_config(page_title="SOC Log Analyzer", layout="wide")
st.title("SOC Log Analyzer")
st.caption("Rule-based and ML detection with AI-assisted alert triage (local model, your logs stay on your PC)")

# ---------------- sidebar ----------------
sb = st.sidebar
sb.header("Log source")
source = sb.radio("Choose input", ["Sample logs", "Upload my own"])
year = sb.number_input("Year of SSH log (syslog has no year)", 2000, 2100, 2026)
ssh_text = web_text = ""
if source == "Sample logs":
    with open(os.path.join(BASE, "sample_data", "auth.log"), encoding="utf-8") as f:
        ssh_text = f.read()
    with open(os.path.join(BASE, "sample_data", "access.log"), encoding="utf-8") as f:
        web_text = f.read()
else:
    up_ssh, up_web = sb.file_uploader("SSH auth log", type=["log", "txt"]), sb.file_uploader("Web access log", type=["log", "txt"])
    ssh_text = up_ssh.getvalue().decode("utf-8", errors="replace") if up_ssh else ""
    web_text = up_web.getvalue().decode("utf-8", errors="replace") if up_web else ""

sb.header("Detection")
try:
    base_rules = rules_mod.load_rules()
except rules_mod.RuleError as exc:
    st.error(f"Rules file problem: {exc}")
    st.stop()
by_id = {r["id"]: r for r in base_rules}
r1 = sb.slider("Brute force: failed logins", 3, 20, by_id["R1"]["threshold"])
r4 = sb.slider("Web scan: 404 responses", 5, 50, by_id["R4"]["threshold"])
use_ml = sb.checkbox("Enable ML anomaly detection", value=True)
contamination = sb.slider("ML sensitivity (share flagged)", 0.005, 0.05, 0.01, 0.005, disabled=not use_ml)

sb.header("AI triage (LM Studio)")
cfg_default = ai_triage.LLMConfig.from_env()
llm_url = sb.text_input("LM Studio server URL", cfg_default.base_url)
llm_model = sb.text_input("Model name (empty = loaded model)", cfg_default.model)
client = ai_triage.LMStudioClient(ai_triage.LLMConfig(base_url=llm_url, model=llm_model, timeout=cfg_default.timeout))
if sb.button("Check connection"):
    st.session_state["llm_ok"] = client.is_available()
if "llm_ok" in st.session_state:
    (sb.success if st.session_state["llm_ok"] else sb.warning)(
        "LM Studio reachable" if st.session_state["llm_ok"] else "LM Studio not reachable: rule-based explanations will be used")

if sb.button("Run analysis", type="primary"):
    rules = rules_mod.with_overrides(base_rules, {"R1": {"threshold": r1}, "R4": {"threshold": r4}})
    logs, stats = parser.parse_logs(ssh_text, web_text, int(year))
    alerts = detector.analyze(logs, rules)
    if use_ml:
        ml = anomaly.detect_anomalies(logs, contamination=contamination)
        alerts = pd.concat([alerts, ml], ignore_index=True).sort_values("first_seen", kind="stable").reset_index(drop=True)
    conn = db.connect(os.path.join(BASE, "soc_alerts.db"))
    db.init_db(conn)
    db.save_results(conn, logs, alerts, rules)
    conn.close()
    st.session_state.update(result=(logs, alerts, stats, rules), triage={})

if "result" not in st.session_state:
    st.info("Choose a log source in the sidebar and click **Run analysis**.")
    st.stop()
logs, alerts, stats, rules = st.session_state["result"]
playbooks = {r["id"]: r.get("playbook", []) for r in rules}

# ---------------- summary ----------------
c = st.columns(6)
c[0].metric("Events parsed", len(logs))
c[1].metric("Alerts", len(alerts))
c[2].metric("Critical", int((alerts["severity"] == "Critical").sum()) if len(alerts) else 0)
c[3].metric("High", int((alerts["severity"] == "High").sum()) if len(alerts) else 0)
c[4].metric("ML alerts", int((alerts["engine"] == "ml").sum()) if len(alerts) else 0)
c[5].metric("Lines skipped", stats.skipped)
if len(alerts) == 0:
    st.success("No suspicious activity detected with the current rules.")
    st.stop()

tab_over, tab_alerts, tab_rules = st.tabs(["Overview", "Alerts and AI triage", "Rules"])

with tab_over:
    left, right = st.columns(2)
    sev = alerts["severity"].value_counts().reindex(SEVERITIES).dropna().reset_index()
    sev.columns = ["severity", "alerts"]
    left.plotly_chart(px.bar(sev, x="severity", y="alerts", color="severity", color_discrete_map=COLORS,
                             title="Alerts by severity"), width="stretch")
    top = alerts.groupby("ip")["event_count"].sum().sort_values(ascending=False).head(10).reset_index()
    right.plotly_chart(px.bar(top, x="event_count", y="ip", orientation="h", title="Top source IPs by suspicious events")
                       .update_yaxes(autorange="reversed"), width="stretch")
    tactics = alerts[alerts["tactic"] != ""]["tactic"].value_counts().reset_index()
    tactics.columns = ["tactic", "alerts"]
    if len(tactics):
        st.plotly_chart(px.bar(tactics, x="alerts", y="tactic", orientation="h", title="MITRE ATT&CK tactics seen"),
                        width="stretch")
    st.plotly_chart(px.scatter(alerts, x="first_seen", y="rule_name", color="severity", size="event_count",
                               color_discrete_map=COLORS, hover_data=["ip", "details"], title="Alert timeline"),
                    width="stretch")

with tab_alerts:
    f1, f2 = st.columns(2)
    sev_pick = f1.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    eng_pick = f2.multiselect("Detection engine", ["rules", "ml"], default=["rules", "ml"])
    view = alerts[alerts["severity"].isin(sev_pick) & alerts["engine"].isin(eng_pick)].reset_index(drop=True)
    show = view.assign(mitre=view["mitre_id"].map(rules_mod.technique_url))[
        ["severity", "rule_name", "ip", "first_seen", "event_count", "mitre", "tactic", "engine", "details"]]
    event = st.dataframe(show, width="stretch", hide_index=True, on_select="rerun", selection_mode="single-row",
                         column_config={"mitre": st.column_config.LinkColumn("MITRE ATT&CK", display_text=r"techniques/(.*)/")})
    st.download_button("Download alerts as CSV", view.to_csv(index=False).encode("utf-8"), "soc_alerts.csv", "text/csv")

    sel = event.selection.rows
    if sel:
        row = view.iloc[sel[0]].to_dict()
        key = f"{row['rule_id']}|{row['ip']}|{row['first_seen']}"
        st.subheader(f"{row['rule_name']} from {row['ip']}")
        ev, ai = st.columns(2)
        with ev:
            st.markdown("**Evidence**")
            st.write(f"Severity **{row['severity']}**, {row['event_count']} events, "
                     f"{row['first_seen']} to {row['last_seen']}")
            st.write(row["details"])
            if row["mitre_id"]:
                st.write(f"MITRE ATT&CK: [{row['mitre_id']} {row['mitre_name']}]({rules_mod.technique_url(row['mitre_id'])}) ({row['tactic']})")
        with ai:
            st.markdown("**AI triage** (advisory only)")
            if st.button("Explain with local AI", key="btn_" + key):
                with st.spinner("Asking the local model..."):
                    st.session_state["triage"][key] = client.triage(row, playbooks.get(row["rule_id"]))
            t = st.session_state["triage"].get(key)
            if t is None:
                t = ai_triage.fallback_triage(row, playbooks.get(row["rule_id"]), "click the button for an AI explanation")
            st.write(t.explanation)
            st.write(f"**Likely attack:** {t.likely_attack}")
            st.write(f"**False-positive likelihood:** {t.false_positive_likelihood} | **Confidence:** {t.confidence:.0%}")
            st.markdown("**Suggested next steps**")
            for s in t.next_steps:
                st.markdown(f"- {s}")
            if t.source == "llm":
                st.caption("AI-generated. Verify against the evidence before acting.")
            else:
                st.caption(f"Rule-based explanation ({t.note}).")
    else:
        st.info("Select an alert row to see its evidence and AI triage.")

with tab_rules:
    st.dataframe(pd.DataFrame([{"id": r["id"], "name": r["name"], "type": r["type"], "severity": r["severity"],
                                "threshold": str(r.get("threshold", "-")), "window_min": str(r.get("window_minutes", "-")),
                                "mitre": r["mitre"].get("id", "")} for r in rules]), width="stretch", hide_index=True)
    st.caption("Rules are defined in rules/default_rules.yaml and validated at startup.")
