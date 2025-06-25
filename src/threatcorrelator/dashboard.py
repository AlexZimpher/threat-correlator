import streamlit as st
import pandas as pd
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.correlate import correlate_logs
from pathlib import Path
import tempfile
import plotly.express as px
import pdfkit
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

st.set_page_config(page_title="ThreatCorrelator", layout="wide")
st.title("🔐 ThreatCorrelator Dashboard")
st.markdown("""
Welcome! This dashboard helps you identify and visualize threats in your logs using the latest threat intelligence feeds. Use the tabs below to explore IOCs, correlate your own logs, and view rich visualizations.
""")

def main() -> None:
    """
    Main entry point for the Streamlit dashboard.
    Loads IOC data, displays metrics, charts, and handles file uploads.
    """
    tab1, tab2, tab3 = st.tabs(["IOC Overview", "Log Correlation", "Visualizations"])

    # ── Load IOC Data ────────────────────────────────────────────────
    session = get_session()
    iocs = session.query(IOC).all()

    if iocs:
        df = pd.DataFrame(
            [
                {
                    "Indicator": ioc.indicator,
                    "Domain": getattr(ioc, 'domain', None),
                    "Confidence": ioc.confidence,
                    "Country": ioc.country,
                    "Last Seen": ioc.last_seen,
                    "Usage": ioc.usage,
                    "Severity": getattr(ioc, 'severity', None),
                    "MITRE Tactic": getattr(ioc, 'mitre_tactic', None),
                    "Source": ioc.source,
                }
                for ioc in iocs
            ]
        )
        # IOC Overview Tab
        with tab1:
            st.header("IOC Overview")
            st.write("Browse and filter all known threat indicators.")
            st.sidebar.header("Filters")
            conf_min, conf_max = st.sidebar.slider("Confidence Range", 0, 100, (0, 100))
            country_filter = st.sidebar.multiselect("Country", options=sorted(df["Country"].dropna().unique()))
            filtered = df[(df["Confidence"] >= conf_min) & (df["Confidence"] <= conf_max)]
            if country_filter:
                filtered = filtered[filtered["Country"].isin(country_filter)]
            st.metric("Total IOCs", len(filtered))
            st.dataframe(filtered, use_container_width=True)
            st.download_button("Download CSV", filtered.to_csv(index=False), file_name="ioc_results.csv")
            if st.button("Download PDF"):
                pdf_bytes = generate_pdf(filtered)
                st.download_button("Download PDF", pdf_bytes, file_name="ioc_results.pdf")
        # Visualizations Tab
        with tab3:
            st.header("Visualizations")
            st.write("Explore threat data visually.")
            # Timeline chart
            if not filtered["Last Seen"].isnull().all():
                fig = px.histogram(filtered, x="Last Seen", nbins=30, title="IOC Timeline")
                st.plotly_chart(fig, use_container_width=True)
            # Choropleth map
            if "Country" in filtered:
                country_counts = filtered["Country"].value_counts().reset_index()
                country_counts.columns = ["Country", "Count"]
                fig = px.choropleth(country_counts, locations="Country", locationmode="country names", color="Count", title="IOC Country Map")
                st.plotly_chart(fig, use_container_width=True)
            # Severity breakdown
            if "Severity" in filtered:
                sev_counts = filtered["Severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig = px.pie(sev_counts, names="Severity", values="Count", title="Severity Distribution")
                st.plotly_chart(fig, use_container_width=True)
            # MITRE tactic breakdown
            if "MITRE Tactic" in filtered:
                tactic_counts = filtered["MITRE Tactic"].value_counts().reset_index()
                tactic_counts.columns = ["MITRE Tactic", "Count"]
                fig = px.bar(tactic_counts, x="MITRE Tactic", y="Count", title="MITRE ATT&CK Tactic Breakdown")
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No IOCs found in database. Please run `threatcorrelator fetch` first.")

    # Log Correlation Tab
    with tab2:
        st.header("Log Correlation")
        st.write("Upload your log file to scan for known threats. Supported: Suricata-style JSON, Apache, Windows XML.")
        uploaded_file = st.file_uploader("Choose a log file", type=["json", "log", "xml"])
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

def generate_pdf(df: pd.DataFrame) -> bytes:
    """Generate a simple PDF from a DataFrame."""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica", 10)
    y = height - 40
    for col in df.columns:
        c.drawString(40, y, f"{col}")
        y -= 15
    y -= 10
    for _, row in df.iterrows():
        y -= 15
        if y < 40:
            c.showPage()
            y = height - 40
        c.drawString(40, y, ", ".join(str(x) for x in row.values))
    c.save()
    buffer.seek(0)
    return buffer.read()

if __name__ == "__main__":
    main()
