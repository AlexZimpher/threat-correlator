# threat-correlator

A professional, modular cybersecurity threat correlation and enrichment tool for log analysis, threat intelligence, and visualization.

## Features
- Schema-consistent indicator correlation (IP, domain, hash, URL, file path)
- Modular enrichment (GeoIP, ASN, reverse DNS, passive DNS stub)
- Dynamic MITRE ATT&CK mapping
- Streamlit dashboard with filters, timeline, map, CSV/PDF export
- CLI for fetch, correlate, dashboard
- Configurable via YAML and environment variables
- Example logs, static feeds, and architecture docs
- CI/CD with linting, security, and coverage

## Quickstart
1. Install dependencies:
   ```bash
   poetry install
   pip install -r requirements-extra.txt
   ```
2. Set up config and environment variables (see README)
3. Fetch IOCs:
   ```bash
   threatcorrelator fetch --source abuseipdb
   ```
4. Correlate logs:
   ```bash
   threatcorrelator correlate --log data/test_logs.jsonl
   ```
5. Launch dashboard:
   ```bash
   threatcorrelator dashboard
   ```

## Docker
```bash
docker build -t threat-correlator .
docker run -p 8501:8501 --env-file .env threat-correlator
```

## Testing
```bash
poetry run pytest
```

## Linting & Security
```bash
pylint src/threatcorrelator
bandit -r src/threatcorrelator
```

## License
MIT
