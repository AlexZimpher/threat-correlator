Here is the complete, copiable `README.md`:

````markdown
# 🔐 ThreatCorrelator

**ThreatCorrelator** is a modular threat intelligence tool that fetches known malicious IP addresses from AbuseIPDB, stores them locally, and scans your log files for matches. It includes a powerful CLI and an interactive Streamlit dashboard to visualize findings.

---

## 📌 Features

- ✅ Fetch high-confidence IOCs from [AbuseIPDB](https://www.abuseipdb.com/)
- ✅ Store and manage threat data in a local SQLite database
- ✅ Scan log files and classify threat severity
- ✅ Visualize IOCs and scan results via Streamlit dashboard
- ✅ Export data to CSV for offline review

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/ThreatCorrelator.git
cd ThreatCorrelator
poetry install
````

Create a `config/config.yaml` file with your AbuseIPDB API key:

```yaml
abuseipdb:
  api_key: "your_api_key_here"
  endpoint: "https://api.abuseipdb.com/api/v2/blacklist"
  max_age_in_days: 30
  confidence_threshold: 75
```

---

## 🛠️ CLI Usage

```bash
poetry run threatcorrelator fetch         # Fetch and store IOCs
poetry run threatcorrelator correlate logs/example.log   # Scan log for threats
poetry run threatcorrelator export iocs.csv              # Export to CSV
```

---

## 📊 Dashboard

Launch the Streamlit dashboard:

```bash
poetry run streamlit run src/threatcorrelator/dashboard.py
```

* View IOC stats
* Upload logs to scan interactively
* Visualize severity and source distribution

---

## 📂 Project Structure

```
threatcorrelator/
├── config/                 # Configuration (YAML)
├── src/threatcorrelator/  # Core modules
├── tests/                 # Unit tests
├── threats.db             # SQLite database (auto-generated)
├── pyproject.toml         # Poetry config
```

---

## 📦 Export Example

```bash
poetry run threatcorrelator export output/iocs.csv
```

Produces:

```csv
ip,confidence,last_reported
203.0.113.45,98,2025-05-31T13:05:00Z
...
```

---

## 🧪 Testing

```bash
poetry run pytest
```

---

## 🐳 Optional Docker (Coming Soon)

---

## 📸 Screenshots

> *(Add screenshots of CLI and dashboard here.)*

---

## 📝 License

[MIT](LICENSE)

---

## 👤 Author

Alexander Zimpher
Cybersecurity Student @ WWU
[https://github.com/yourusername](https://github.com/yourusername)

```
```

