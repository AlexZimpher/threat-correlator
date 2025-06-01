import requests
import yaml
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"

def load_config():
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def fetch_abuseipdb_blacklist():
    config = load_config()
    abuse_cfg = config["abuseipdb"]
    
    headers = {
        "Key": abuse_cfg["api_key"],
        "Accept": "application/json"
    }

    params = {
        "confidenceMinimum": abuse_cfg["confidence_threshold"],
        "maxAgeInDays": abuse_cfg["max_age_in_days"]
    }

    response = requests.get(abuse_cfg["endpoint"], headers=headers, params=params)
    response.raise_for_status()

    data = response.json()
    if "data" not in data:
        raise ValueError("Invalid AbuseIPDB response")

    normalized = []
    for entry in data["data"]:
        normalized.append({
            "ip": entry.get("ipAddress"),
            "confidence": entry.get("abuseConfidenceScore"),
            "country": entry.get("countryCode"),
            "last_seen": entry.get("lastReportedAt"),
            "usage": entry.get("usageType"),
            "source": "abuseipdb"
        })

    return normalized

