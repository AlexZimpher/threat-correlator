# 🔐 ThreatCorrelator

**ThreatCorrelator** is a modular threat intelligence tool that fetches high-confidence malicious IP addresses from AbuseIPDB, stores them in a local SQLite database, and scans your log files for known threats. It provides both a powerful CLI and an interactive Streamlit dashboard to visualize and export findings.

![CI](https://github.com/yourusername/threatcorrelator/actions/workflows/ci.yml/badge.svg)

---

## 📌 Features

- ✅ Fetch IOCs from [AbuseIPDB](https://www.abuseipdb.com/)
- ✅ Store threat intelligence locally via SQLAlchemy
- ✅ Scan JSON log files for matching IPs
- ✅ Classify threat severity (High / Medium / Low)
- ✅ Visualize and interact via a Streamlit dashboard
- ✅ Export threat matches to CSV or JSON
- ✅ Clean modular code with full test coverage and CI

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

2. **Edit `config/config.yaml`** to include your AbuseIPDB API key:

   ```yaml
   abuseipdb:
     api_key: "your_api_key_here"  # 🔐 Replace with your actual key
     endpoint: "https://api.abuseipdb.com/api/v2/blacklist"
     confidence_threshold: 75
     max_age_in_days: 30
     limit: 10000

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

---

## 📝 License

[MIT License](LICENSE)

---

## 👤 Author

**Alexander Zimpher**  
Cybersecurity Student @ WWU  
[https://github.com/AlexZimpher](https://github.com/AlexZimpher)

