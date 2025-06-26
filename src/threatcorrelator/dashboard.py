import streamlit as st
import pandas as pd
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.correlate import correlate_logs
from threatcorrelator.mitre_map import dynamic_mitre_mapping
from threatcorrelator.config_loader import load_config
from pathlib import Path
import tempfile
import plotly.express as px
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Set up the Streamlit dashboard UI and configuration
st.set_page_config(page_title="ThreatCorrelator", layout="wide")
st.title("\ud83d\udd10 ThreatCorrelator Dashboard")
st.markdown(
    """
**ThreatCorrelator**: Instantly spot known malicious actors in your logs using real-time threat intelligence feeds. Upload logs, filter, visualize, and export results—all in one place.
"""
)

st.sidebar.title("Filters & Actions")

config = load_config()


# Helper to enrich IOC row with severity and MITRE mapping
def enrich_ioc_row(ioc):
    if not getattr(ioc, "severity", None):
        if getattr(ioc, "confidence", 0) >= config["severity_thresholds"].get(
            "high", 80
        ):
            severity = "High"
        elif getattr(ioc, "confidence", 0) >= config["severity_thresholds"].get(
            "medium", 50
        ):
            severity = "Medium"
        else:
            severity = "Low"
    else:
        severity = getattr(ioc, "severity")
    usage = getattr(ioc, "usage", "")
    indicator = getattr(ioc, "indicator", "")
    tactic, technique = dynamic_mitre_mapping(indicator, usage)
    return severity, tactic, technique


def main():
    tab1, tab2, tab3 = st.tabs(["IOC Overview", "Log Correlation", "Visualizations"])
    session = get_session()
    iocs = session.query(IOC).all()

    if iocs:
        df = pd.DataFrame(
            [
                {
                    "Indicator": ioc.indicator,
                    "Domain": getattr(ioc, "domain", None),
                    "Confidence": ioc.confidence,
                    "Country": ioc.country,
                    "Last Seen": ioc.last_seen,
                    "Usage": ioc.usage,
                    "Severity": enrich_ioc_row(ioc)[0],
                    "MITRE Tactic": enrich_ioc_row(ioc)[1],
                    "MITRE Technique": enrich_ioc_row(ioc)[2],
                    "Source": ioc.source,
                }
                for ioc in iocs
            ]
        )
        with tab1:
            st.subheader("IOC Overview")
            st.caption("Browse, filter, and export all known threat indicators.")
            conf_min, conf_max = st.sidebar.slider(
                "Confidence Range", 0, 100, (0, 100), key="conf"
            )
            country_filter = st.sidebar.multiselect(
                "Country",
                options=sorted(df["Country"].dropna().unique()),
                key="country",
            )
            filtered = df[
                (df["Confidence"] >= conf_min) & (df["Confidence"] <= conf_max)
            ]
            if country_filter:
                filtered = filtered[filtered["Country"].isin(country_filter)]
            st.metric("Total IOCs", len(filtered))
            st.dataframe(filtered, use_container_width=True, height=400)
            st.download_button(
                "⬇️ Download CSV",
                filtered.to_csv(index=False),
                file_name="ioc_results.csv",
            )
            if st.button("Export as PDF"):
                pdf_bytes = generate_pdf(filtered)
                st.download_button(
                    "⬇️ Download PDF", pdf_bytes, file_name="ioc_results.pdf"
                )
        with tab3:
            st.subheader("Visualizations")
            st.caption("See threat trends and breakdowns at a glance.")
            if not filtered["Last Seen"].isnull().all():
                fig = px.histogram(
                    filtered, x="Last Seen", nbins=30, title="IOC Timeline"
                )
                st.plotly_chart(fig, use_container_width=True)
            if "Country" in filtered:
                country_counts = filtered["Country"].value_counts().reset_index()
                country_counts.columns = ["Country", "Count"]
                fig = px.choropleth(
                    country_counts,
                    locations="Country",
                    locationmode="country names",
                    color="Count",
                    title="IOC Country Map",
                )
                st.plotly_chart(fig, use_container_width=True)
            if "Severity" in filtered:
                sev_counts = filtered["Severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig = px.pie(
                    sev_counts,
                    names="Severity",
                    values="Count",
                    title="Severity Distribution",
                )
                st.plotly_chart(fig, use_container_width=True)
            if "MITRE Tactic" in filtered:
                tactic_counts = filtered["MITRE Tactic"].value_counts().reset_index()
                tactic_counts.columns = ["MITRE Tactic", "Count"]
                fig = px.bar(
                    tactic_counts,
                    x="MITRE Tactic",
                    y="Count",
                    title="MITRE ATT&CK Tactic Breakdown",
                )
                st.plotly_chart(fig, use_container_width=True)
            if "MITRE Technique" in filtered:
                tech_counts = filtered["MITRE Technique"].value_counts().reset_index()
                tech_counts.columns = ["MITRE Technique", "Count"]
                fig = px.bar(
                    tech_counts,
                    x="MITRE Technique",
                    y="Count",
                    title="MITRE ATT&CK Technique Breakdown",
                )
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning(
            "No IOCs found in database. Please run `threatcorrelator fetch` first."
        )

    with tab2:
        st.subheader("Log Correlation")
        st.caption(
            "Upload a log file to scan for known threats. Supported: Suricata-style JSON, Apache, Windows XML."
        )
        uploaded_file = st.file_uploader(
            "Choose a log file", type=["json", "log", "xml"]
        )
        if uploaded_file:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                tmp.write(uploaded_file.read())
                tmp_path = Path(tmp.name)
            results = correlate_logs(tmp_path)
            if results:
                st.success(f"✅ Found {len(results)} threat IPs in the uploaded log.")
                results_df = pd.DataFrame(results)
                st.dataframe(results_df, use_container_width=True, height=400)
                st.download_button(
                    "⬇️ Download Results as CSV",
                    results_df.to_csv(index=False),
                    "correlation_results.csv",
                    "text/csv",
                )
            else:
                st.info("No threats detected in the uploaded log.")


def generate_pdf(df: pd.DataFrame) -> bytes:
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
