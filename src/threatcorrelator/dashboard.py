import streamlit as st
import pandas as pd
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.correlate import correlate_logs
from pathlib import Path
import tempfile

st.set_page_config(page_title="ThreatCorrelator", layout="wide")
st.title("🔐 ThreatCorrelator Dashboard")

# ── Load IOC Data ────────────────────────────────────────────────
session = get_session()
iocs = session.query(IOC).all()

if iocs:
    df = pd.DataFrame(
        [
            {
                "IP": ioc.ip or (ioc.indicator if getattr(ioc, 'type', None) == 'ip' else None),
                "Domain": ioc.domain or (ioc.indicator if getattr(ioc, 'type', None) == 'domain' else None),
                "Confidence": ioc.confidence,
                "Country": ioc.country,
                "Last Seen": ioc.last_seen,
                "Usage": ioc.usage,
                "Source": ioc.source,
            }
            for ioc in iocs
        ]
    )

    st.metric("Total IOCs", len(df))

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("📊 Threat Confidence Levels")
        bins = pd.cut(
            df["Confidence"],
            bins=[0, 50, 80, 100],
            right=False,
            labels=["Low", "Medium", "High"],
        )
        st.bar_chart(bins.value_counts().sort_index())

    with col2:
        st.subheader("🌍 IOC Country Distribution")
        st.bar_chart(df["Country"].value_counts())

    with st.expander("🔍 View All IOCs"):
        st.dataframe(df, use_container_width=True)
else:
    st.warning("No IOCs found in database. Please run `threatcorrelator fetch` first.")

# ── Log File Upload & Correlation ────────────────────────────────
st.subheader("🪵 Upload a Log File to Correlate")
uploaded_file = st.file_uploader("Choose a Suricata-style JSON log", type=["json"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = Path(tmp.name)

    results = correlate_logs(tmp_path)

    if results:
        st.success(f"✅ Found {len(results)} threat IPs in the uploaded log.")
        results_df = pd.DataFrame(results)
        st.dataframe(results_df, use_container_width=True)
        st.download_button(
            "📥 Download Results as CSV",
            results_df.to_csv(index=False),
            "correlation_results.csv",
            "text/csv",
        )
    else:
        st.info("No threats detected in the uploaded log.")
