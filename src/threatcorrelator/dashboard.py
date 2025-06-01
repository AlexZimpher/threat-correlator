import streamlit as st
import pandas as pd
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.correlate import correlate_logs
from pathlib import Path
import tempfile

st.set_page_config(page_title="ThreatCorrelator", layout="wide")
st.title("🔐 ThreatCorrelator Dashboard")

# Load IOC data
session = get_session()
iocs = session.query(IOC).all()
df = pd.DataFrame([{
    "IP": ioc.ip,
    "Confidence": ioc.confidence,
    "Country": ioc.country,
    "Last Seen": ioc.last_seen,
    "Usage": ioc.usage,
    "Source": ioc.source
} for ioc in iocs])

st.metric("Total IOCs", len(df))

# Show severity distribution
if not df.empty:
    st.subheader("📊 IOC Confidence Levels")
    st.bar_chart(df["Confidence"].value_counts(bins=[0, 50, 80, 100]))

    st.subheader("🌍 IOC Countries")
    st.bar_chart(df["Country"].value_counts())

# Upload log file to scan
st.subheader("🪵 Upload a Log File to Correlate")
uploaded_file = st.file_uploader("Choose a JSON log file", type=["json"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = Path(tmp.name)

    results = correlate_logs(tmp_path)
    st.success(f"✅ Found {len(results)} threats in uploaded log.")

    if results:
        results_df = pd.DataFrame(results)
        st.dataframe(results_df)
        st.download_button("Download CSV", results_df.to_csv(index=False), "correlation_results.csv", "text/csv")
