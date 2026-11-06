
import streamlit as st
import pandas as pd
import plotly.express as px

from detection.threat_detector import analyze_logs
from database.db_manager import (
    initialize_db, save_alerts, get_alert_history
)
from reports.report_generator import generate_pdf_report

st.set_page_config(
    page_title="SOC Sentinel | Security Operations Center",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.stApp { background-color: #0b1220; color: #e5e7eb; }
[data-testid="stMetric"] {
    background: #172337;
    padding: 18px;
    border-radius: 10px;
    border: 1px solid #263b59;
}
</style>
""", unsafe_allow_html=True)

initialize_db()

st.title("🛡️ SOC SENTINEL")
st.caption("Network Threat Detection & Security Monitoring Platform")
st.divider()

st.sidebar.title("SOC CONTROL PANEL")
uploaded_file = st.sidebar.file_uploader(
    "Upload Network Logs (CSV)", type=["csv"]
)

if uploaded_file:
    logs = pd.read_csv(uploaded_file)
    st.sidebar.success("Uploaded log file selected")
else:
    logs = pd.read_csv("data/sample_network_logs.csv")
    st.sidebar.info("Using demo network logs")

if st.sidebar.button("🔍 Analyze Network Logs",width="stretch"):
    st.session_state["analyzed"] = True

if st.session_state.get("analyzed", False):
    try:
        alerts = analyze_logs(logs)
        saved_count = save_alerts(alerts)

        st.subheader("Security Overview")

        total = len(logs)
        total_alerts = len(alerts)
        critical = int((alerts["severity"] == "Critical").sum())
        high = int((alerts["severity"] == "High").sum())
        medium = int((alerts["severity"] == "Medium").sum())

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Network Events", total)
        c2.metric("Total Alerts", total_alerts)
        c3.metric("Critical Alerts", critical)
        c4.metric("High Alerts", high)

        st.caption(f"New alerts saved to incident database: {saved_count}")

        st.divider()
        left, right = st.columns(2)

        with left:
            st.subheader("Alert Severity Distribution")
            if not alerts.empty:
                severity_data = (
                    alerts["severity"].value_counts().reset_index()
                )
                severity_data.columns = ["Severity", "Count"]
                fig = px.pie(
                    severity_data,
                    names="Severity",
                    values="Count",
                    hole=0.55
                )
                st.plotly_chart(fig, width="stretch")
            else:
                st.info("No alerts detected.")

        with right:
            st.subheader("Network Protocol Distribution")
            protocol_data = logs["protocol"].value_counts().reset_index()
            protocol_data.columns = ["Protocol", "Count"]
            fig = px.bar(
                protocol_data,
                x="Protocol",
                y="Count",
                color="Protocol"
            )
            st.plotly_chart(fig, width="stretch")
        st.divider()
        st.subheader("🚨 Detected Security Alerts")

        if alerts.empty:
            st.success("No alerts detected in the selected logs.")
        else:
            st.dataframe(alerts, width="stretch")

        st.download_button(
            "📄 Download Security Report (PDF)",
            data=generate_pdf_report(alerts),
            file_name="SOC_Sentinel_Security_Report.pdf",
            mime="application/pdf"
        )

    except Exception as error:
        st.error(f"Analysis error: {error}")

else:
    st.info("Click 'Analyze Network Logs' in the sidebar to start monitoring.")

st.divider()
st.subheader("🗄️ Incident History")

history = get_alert_history()

if history.empty:
    st.info("No incidents stored yet. Analyze logs to create incident records.")
else:
    st.dataframe(history, width="stretch")

st.caption("SOC Sentinel | Educational Security Monitoring Prototype")