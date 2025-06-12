# 🔐 ThreatCorrelator

**ThreatCorrelator** is a modular threat intelligence tool that fetches high-confidence malicious IP addresses from AbuseIPDB, stores them in a local SQLite database, and scans your log files for known threats. It provides both a powerful CLI and an interactive Streamlit dashboard to visualize and export findings.

![CI](https://github.com/AlexZimpher/threatcorrelator/actions/workflows/ci.yml/badge.svg)

---

## Features

- 🎯 **Multi-Source IOC Fetch**: Pull malicious IPs/domains from AbuseIPDB (requires API key) and AlienVault OTX (no key needed).
- 🕵️ **IP & Domain Correlation**: Scan logs (newline-delimited JSON) to match both IP and domain indicators.
- 🛡️ **MITRE ATT&CK Mapping**: Each matched IOC is tagged with a tactic/technique (e.g., T1110 – Brute Force for SSH usage).
- ⚠️ **Critical Severity**: If an IOC appears more than _n_ times (configurable), it’s elevated to “Critical.”
- ⏳ **Stale IOC Filtering**: Ignore IOCs whose `last_seen` is older than _X_ days (configurable).
- 🌍 **Country Resolution**: Translates ISO code to full country name (e.g., US → United States).
- 💻 **Streamlit Dashboard**: Interactive UI to fetch, correlate, visualize, filter, and download results.
- ✅ **Comprehensive Test Suite & CI**: End-to-end and CLI tests, plus Black/Flake8/Bandit/pytest-cov in GitHub Actions.

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/threatcorrelator.git
cd threatcorrelator
poetry install
```

---

## ⚙️ Configuration

1. **Copy the example config file:**

   ```bash
   cp config/config.example.yaml config/config.yaml
   ```

2. **Set your API keys as environment variables (recommended):**

   ```bash
   export ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   export OTX_API_KEY=your_otx_api_key
   ```
   Or on Windows PowerShell:
   ```powershell
   $env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
   $env:OTX_API_KEY="your_otx_api_key"
   ```

   The application will use these environment variables if set, otherwise it will fall back to the values in `config.yaml`.

3. **Edit `config/config.yaml`** to adjust thresholds and endpoints as needed:

   ```yaml
   abuseipdb:
     api_key: "YOUR_ABUSEIPDB_API_KEY"  # Optional if using env var
     endpoint: "https://api.abuseipdb.com/api/v2/blacklist"
     confidence_threshold: 75
     max_age_in_days: 30
     limit: 10000

   otx:
     api_key: "YOUR_OTX_API_KEY"  # Optional if using env var
     pulse_days: 7

   severity_thresholds:
     high: 80
     medium: 50
   ```

> ⚠️ Your `config.yaml` and `data/iocs.db` are ignored via `.gitignore` for security.

---

## 🛠️ CLI Usage

```bash
poetry run threatcorrelator fetch                 # Fetch & store IOCs from AbuseIPDB
poetry run threatcorrelator correlate logs/example.json   # Scan logs against IOCs
poetry run threatcorrelator export output/results.csv     # Export results
poetry run threatcorrelator show-config           # Show active configuration
```

## Usage Examples

### Fetch IOCs
```bash
threatcorrelator fetch --source abuseipdb
```

### Correlate Logs
```bash
threatcorrelator correlate --log data/test_logs.jsonl
```

### Launch Dashboard
```bash
threatcorrelator dashboard
```

---

## 📊 Streamlit Dashboard

Launch the dashboard to interact visually:

```bash
poetry run streamlit run src/threatcorrelator/dashboard.py
```

- View IOC stats
- Upload log files
- Visualize threat severity & country breakdown
- Export results interactively

## Screenshots

![Dashboard Screenshot](docs/dashboard_screenshot.png)

---

## 📦 Export Example

```bash
poetry run threatcorrelator export logs/test.json -o output/threats.csv
```

Outputs:

```csv
ip,confidence,country,last_seen,usage,severity
1.2.3.4,85,US,2025-05-31T13:05:00,ISP,High
...
```

---

## 📂 Project Structure

```
threatcorrelator/
├── config/                 # YAML configuration
├── src/threatcorrelator/  # Main source code
│   ├── fetch.py           # AbuseIPDB fetch logic
│   ├── correlate.py       # Log correlation logic
│   ├── storage.py         # ORM & DB
│   ├── cli.py             # CLI entrypoint
│   └── dashboard.py       # Streamlit dashboard (optional)
├── tests/                 # Unit tests
├── pyproject.toml         # Poetry configuration
└── .github/workflows/     # GitHub Actions CI
```

---

## 🧪 Testing

```bash
poetry run pytest
```

- `tests/test_correlator.py`: severity classification logic
- `tests/test_correlate_logs.py`: log scan integration
- `tests/test_fetch.py`: AbuseIPDB mock API tests

---

## Badges

![CI](https://github.com/yourusername/threat-correlator/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/yourusername/threat-correlator/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/threat-correlator)

---

## Future Work
- Integrate live passive DNS and threat intelligence APIs
- Expand anomaly detection and multi-stage behavior logic
- Add more log format support and enrichment
- Improve dashboard visualizations and PDF export
- Add more tests and coverage

---

## 📝 License

[MIT License](LICENSE)

---

## 👤 Author

**Alexander Zimpher**  
Cybersecurity Student @ WWU  
[https://github.com/AlexZimpher](https://github.com/AlexZimpher)

