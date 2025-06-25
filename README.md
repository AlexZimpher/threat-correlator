# 🔐 ThreatCorrelator

ThreatCorrelator helps you quickly identify known malicious actors in your log files by correlating them with threat intelligence feeds. Whether you’re a security analyst, system administrator, or just curious, ThreatCorrelator makes it easy to spot threats and understand their context—all with a simple interface and clear visualizations.

**Why it matters:**
- Quickly find out if your systems have interacted with known bad actors.
- Get actionable insights with clear severity ratings and threat context.
- No security expertise required—just point it at your logs and see results.

---

## Features

- 🎯 **Multi-Source IOC Fetch**: Pulls malicious IPs/domains from multiple sources (e.g., AbuseIPDB, AlienVault OTX). *Lets you check your logs against the latest threat intelligence.*
- 🕵️ **IP & Domain Correlation**: Scans your logs to match both IP and domain indicators. *Finds threats hiding in plain sight.*
- 🛡️ **MITRE ATT&CK Mapping**: Tags each threat with a known tactic/technique (e.g., T1110 – Brute Force). *Gives context to each detection.*
- ⚠️ **Critical Severity**: Flags repeated or high-confidence threats as “Critical.” *Helps you prioritize what matters most.*
- ⏳ **Stale IOC Filtering**: Ignores outdated threat indicators. *Keeps results relevant and actionable.*
- 🌍 **Country Resolution**: Shows the country of origin for each threat. *Adds geographic context to your findings.*
- 💻 **Streamlit Dashboard**: Interactive UI to fetch, correlate, visualize, filter, and download results. *See everything at a glance.*
- ✅ **Comprehensive Test Suite & CI**: Automated tests and code checks ensure reliability and security.

---

## How It Works

ThreatCorrelator follows a simple, modular pipeline:

1. **Fetch Threat Feeds**: Downloads the latest malicious IPs/domains from multiple sources.
2. **Store in Local Database**: Saves threat data in a local SQLite database for fast lookups.
3. **Correlate with Your Logs**: Scans your log files for any matches with known threats.
4. **Enrich & Classify**: Adds context (country, severity, MITRE tactic) to each detection.
5. **Visualize & Export**: View results in the dashboard or export them for reporting.

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
threatcorrelator fetch --source static
```

### Correlate Logs
```bash
threatcorrelator correlate --log data/test_logs.jsonl
threatcorrelator correlate --log logs/example_windows.xml
```

### Export Results
```bash
threatcorrelator export logs/example_apache.log -o outputs/results.csv
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
![Dashboard Table](docs/dashboard_table.png)
![Dashboard Timeline](docs/dashboard_timeline.png)

---

## Screenshots & Diagrams

Below are some key views from the Streamlit dashboard and system architecture:

![Dashboard Overview](docs/dashboard_screenshot.png)
*Dashboard showing threat country breakdown and severity chart.*

![Dashboard Table](docs/dashboard_table.png)
*Interactive table of correlated threats.*

![Dashboard Timeline](docs/dashboard_timeline.png)
*Timeline chart of threat activity over time.*

![System Architecture](docs/architecture_diagram.png)
*High-level data flow: Threat Feeds → Fetcher → Database → Correlator → Dashboard/CLI → Outputs.*

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

## 🚦 Quick Start (Try It Instantly!)

You can try ThreatCorrelator with sample data in just one command—no setup required:

```bash
poetry run streamlit run src/threatcorrelator/dashboard.py
```

*Sample logs and a pre-filled config are included for instant demo—no API keys needed for basic testing!*

---

## 🗂️ Sample Data & Defaults

- Example logs: `logs/example_log.jsonl`, `logs/example_apache.log`, `logs/example_windows.xml`
- Pre-filled config: `config/config.example.yaml`
- Demo IOC database: `data/iocs.db` (contains a few entries for demo purposes)

If you don’t provide API keys, the dashboard will load the sample threat list so you can see how it works.

---

## 🖥️ Cross-Platform Setup

- **Windows PowerShell:**
  ```powershell
  $env:ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
  $env:OTX_API_KEY="your_otx_api_key"
  ```
- **Linux/macOS Bash:**
  ```bash
  export ABUSEIPDB_API_KEY=your_abuseipdb_api_key
  export OTX_API_KEY=your_otx_api_key
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

![CI](https://github.com/AlexZimpher/threat-correlator/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/AlexZimpher/threat-correlator/branch/main/graph/badge.svg)](https://codecov.io/gh/AlexZimpher/threat-correlator)

---

## 🚀 Future Work
- Integrate additional threat intelligence APIs (e.g., VirusTotal, GreyNoise, Spamhaus)
- Expand anomaly detection and multi-stage behavior logic
- Add more log format support and enrichment
- Improve dashboard visualizations and PDF export
- Add more tests and coverage
- Sigma/rule-based detection support
- ML-based anomaly detection
- SIEM/Splunk/ELK connectors

---

## 👤 Author

**Alexander Zimpher**  
[https://github.com/AlexZimpher](https://github.com/AlexZimpher)

---

## Demo & Example Logs

This project includes a script to generate demo log files that are guaranteed to trigger threat detections using your current IOC database. This makes it easy for reviewers and recruiters to see the system in action.

### Generate Demo Logs

After fetching IOCs, run:

```sh
poetry run python generate_demo_logs.py
```

This will create:
- `logs/example_log.jsonl`      (JSONL log with IP/domain hits)
- `logs/example_apache.log`     (Apache log with IP hit)
- `logs/example_windows.xml`    (Windows XML log with IP/domain hits)

### Try Correlation

```sh
poetry run python -m threatcorrelator.cli correlate logs/example_log.jsonl
poetry run python -m threatcorrelator.cli correlate logs/example_apache.log
poetry run python -m threatcorrelator.cli correlate logs/example_windows.xml
```

You will see flagged threats in the output, demonstrating the detection and enrichment pipeline.

---

## Use Cases

**Use Case 1: Securing a Web Server**
> An admin points ThreatCorrelator at Apache log files to quickly find if any visitors’ IPs are known malicious. For example, in the provided `example_apache.log`, the tool flags an IP as a brute-force attacker (mapped to MITRE technique T1110). The admin can then block that IP and investigate further.

**Use Case 2: Incident Response Triage**
> A SOC analyst receives an alert about suspicious outbound traffic. They use ThreatCorrelator to cross-reference destination IPs against threat intel feeds. The dashboard highlights one IP as High Confidence malicious (95/100 abuse score), prompting immediate containment.

**Use Case 3: Threat Hunting (Proactive)**
> A security researcher fetches the latest 10,000 malicious IPs and runs ThreatCorrelator on a week’s worth of firewall logs. The tool finds 5 matches and elevates 2 to ‘Critical’ severity due to repeated hits, suggesting those machines were targeted multiple times.

**Input/Output Example:**
- *Sample log entry:*
  ```json
  {"timestamp": "2025-06-01T12:00:00Z", "src_ip": "1.2.3.4", "event": "login_attempt"}
  ```
- *Correlation result:*
  ```csv
  ip,confidence,country,last_seen,usage,severity
  1.2.3.4,85,US,2025-05-31T13:05:00,ISP,High
  ```

**Quick Demo:**
1. Fetch threat data from AbuseIPDB and OTX.
2. Correlate against the provided sample log file.
3. Open the dashboard to review results.

*No setup needed for demo: sample logs and a pre-filled config are included for quick testing!*

---

## 🧩 Design & Code Quality

ThreatCorrelator is built with modularity and security in mind:
- **Modular Architecture:** Fetcher, Correlator, and Storage modules each handle a specific responsibility, making it easy to extend or swap components.
- **Extensible Feeds:** Adding a new threat intelligence source is as simple as implementing a new fetcher module—see `src/threatcorrelator/fetch.py` for examples.
- **Security Best Practices:**
  - API keys are never committed—use environment variables or config files (which are gitignored).
  - SQLite database is local-only and not exposed to the network.
  - Input logs are sanitized and validated before processing.
  - CI includes Bandit static analysis to catch common Python security issues.
- **Quality Assurance:**
  - 100% tests passing, 85%+ coverage, and code linted (Black/Flake8) and security-scanned (Bandit) in CI.

For more on the architecture, see [docs/architecture.md](docs/architecture.md).

---

## 🌐 Supported & Extensible Threat Intelligence Sources

ThreatCorrelator is designed to easily integrate new threat intelligence feeds. Currently supported:
- **AbuseIPDB** (API key required)
- **AlienVault OTX** (no key needed)
- **Static CSV/JSON feeds** (just drop a file in the right place)

**Pluggable Design:**
- You can add new sources (e.g., VirusTotal, Spamhaus, GreyNoise) by implementing a new fetcher in `src/threatcorrelator/fetch.py`.
- Example (scaffold):
  ```python
  # In fetch.py
  def fetch_virustotal(api_key: str):
      """Fetch IOCs from VirusTotal API (scaffold)."""
      # TODO: Implement API call and parsing
      pass
  ```
- Document new API keys or config options in your config file as needed.
