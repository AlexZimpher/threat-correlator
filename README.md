# 🔐 ThreatCorrelator

![CI](https://github.com/AlexZimpher/threat-correlator/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/AlexZimpher/threat-correlator/graph/badge.svg?token=YZ0K214VR8)](https://codecov.io/gh/AlexZimpher/threat-correlator)

**ThreatCorrelator** instantly spots known malicious actors in your logs by correlating them with real-time threat intelligence feeds. No security expertise required—just point it at your logs and get clear, actionable results.

---

## 🚀 Quick Start

```bash
poetry install
poetry run streamlit run src/threatcorrelator/dashboard.py
```

*Sample logs and config are included for instant demo—no API keys needed for basic testing!*

---

## Features

- **Multi-Source Threat Feeds:** Checks your logs against AbuseIPDB, AlienVault OTX, and more.
- **IOC Correlation:** Finds both IP and domain matches in your logs.
- **MITRE ATT&CK Mapping:** Tags each threat with a known tactic/technique for context.
- **Severity & Country Context:** Flags critical threats and shows their origin.
- **Interactive Dashboard:** Visualize, filter, and download results easily.

---

## How It Works

1. **Fetch Threat Feeds** → 2. **Store in Local DB** → 3. **Correlate with Your Logs** → 4. **Enrich & Classify** → 5. **Visualize & Export**

---

## Example Use Case

- **Web Server Security:** Scan your Apache logs and instantly see if any visitors’ IPs are known malicious. Block and investigate as needed.

---

## Screenshots

![Dashboard Overview](docs/dashboard_screenshot.png)
*Dashboard showing threat breakdown and visualizations.*

---

## Extending & Contributing

- Add new threat feeds by implementing a fetcher in `src/threatcorrelator/fetch.py`.
- See code comments for scaffolds and open a PR if you want to contribute!

---

**Author:** [Alexander Zimpher](https://github.com/AlexZimpher)
