# 🔐 ThreatCorrelator

![CI](https://github.com/AlexZimpher/threat-correlator/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/AlexZimpher/threat-correlator/branch/main/graph/badge.svg)](https://codecov.io/gh/AlexZimpher/threat-correlator)

ThreatCorrelator helps you quickly identify known malicious actors in your log files by correlating them with threat intelligence feeds. Whether you’re a security analyst, system administrator, or just curious, ThreatCorrelator makes it easy to spot threats and understand their context—all with a simple interface and clear visualizations.

**Why it matters:**
- Instantly see if your systems have interacted with known bad actors.
- Get clear, actionable threat context and severity ratings.
- No security expertise required—just point it at your logs and see results.

---

## Features

- 🎯 **Multi-Source IOC Fetch**: Pulls malicious IPs/domains from sources like AbuseIPDB and AlienVault OTX.
- 🕵️ **IP & Domain Correlation**: Scans your logs for matches to known threats.
- 🛡️ **MITRE ATT&CK Mapping**: Tags each threat with a known tactic/technique.
- ⚠️ **Critical Severity**: Flags repeated or high-confidence threats as “Critical.”
- 🌍 **Country Resolution**: Shows the country of origin for each threat.
- 💻 **Streamlit Dashboard**: Visualize, filter, and download results interactively.

---

## Quick Start

```bash
poetry install
poetry run streamlit run src/threatcorrelator/dashboard.py
```

*Sample logs and config are included for instant demo—no API keys needed for basic testing!*

---

## How It Works

1. **Fetch Threat Feeds** → 2. **Store in Local DB** → 3. **Correlate with Your Logs** → 4. **Enrich & Classify** → 5. **Visualize & Export**

---

## Example Use Case

- **Web Server Security:** Scan your Apache logs and instantly see if any visitors’ IPs are known malicious. Block and investigate as needed.

---

## Extending & Contributing

- Add new threat feeds by implementing a fetcher in `src/threatcorrelator/fetch.py`.
- See code comments for scaffolds and open a PR if you want to contribute!

---

## Author

[Alexander Zimpher](https://github.com/AlexZimpher)
