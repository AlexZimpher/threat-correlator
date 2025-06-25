# ThreatCorrelator Architecture

```mermaid
graph TD
    A[Threat Feeds: AbuseIPDB, OTX, Static CSV] --> B[Fetcher]
    B --> C[Parser/Normalizer]
    C --> D[SQLite DB]
    D --> E[Correlator]
    E --> F[Dashboard (Streamlit)]
    E --> G[CLI]
    F --> H[Visualization/Export]
    G --> H
```

- **Feeds:** Multiple sources (API, CSV, etc.)
- **Fetcher:** Downloads and normalizes IOCs
- **DB:** Stores all indicators
- **Correlator:** Matches logs to IOCs, applies enrichment, anomaly detection
- **Dashboard/CLI:** User interfaces for analysis and export

## Architecture Diagram

```mermaid
graph TD
    A[Log Files: JSONL, CSV, Apache, XML] --> B[extract_indicators_from_log]
    B --> C[correlate_logs]
    C --> D[Enrichment: GeoIP, ASN, Reverse DNS, Passive DNS]
    C --> E[MITRE ATT&CK Mapping]
    C --> F[Anomaly Detection]
    C --> G[SQLite DB: IOC Blacklist]
    G --> C
    C --> H[Streamlit Dashboard]
    C --> I[CLI Export/Report]
    H --> J[CSV/PDF Export]
    style G fill:#f9f,stroke:#333,stroke-width:2px
    style H fill:#bbf,stroke:#333,stroke-width:2px
    style D fill:#bfb,stroke:#333,stroke-width:2px
```
