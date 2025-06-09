import os
import requests
import logging
from datetime import datetime, timedelta
from typing import Optional
from OTXv2 import OTXv2
from threatcorrelator.config_loader import load_config

logger = logging.getLogger(__name__)
config = load_config()

__all__ = ["fetch_abuseipdb_blacklist", "fetch_otx_feed"]

def fetch_abuseipdb_blacklist(api_key: Optional[str] = None) -> list[dict]:
    """
    Fetch IOCs from AbuseIPDB. Returns a list of dicts with keys:
    indicator, confidence, country, last_seen, usage, source, type
    """
    if api_key is None:
        api_key = os.getenv("ABUSEIPDB_API_KEY") or config["abuseipdb"]["api_key"]
    url = config["abuseipdb"]["endpoint"]
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "confidenceMinimum": config["abuseipdb"].get("confidence_minimum", 90),
        "limit": config["abuseipdb"].get("limit", 10000),
        "maxAgeInDays": config["abuseipdb"].get("max_age_in_days", 30),
    }
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json().get("data", [])
    except Exception as e:
        logger.error("AbuseIPDB fetch failed: %s", e)
        return []
    iocs = []
    for entry in data:
        iocs.append({
            "indicator": entry.get("ipAddress", ""),
            "confidence": entry.get("abuseConfidenceScore", 0),
            "country": entry.get("countryCode", ""),
            "last_seen": entry.get("lastReportedAt", ""),
            "usage": entry.get("usageType", ""),
            "source": "abuseipdb",
            "type": "ip",
        })
    return iocs

def fetch_otx_feed() -> list[dict]:
    """
    Fetch IOCs from AlienVault OTX. Returns a list of dicts with keys:
    indicator, confidence, country, last_seen, usage, source, type
    """
    try:
        api_key = config["otx"]["api_key"]
        days = config["otx"].get("pulse_days", 7)
        otx = OTXv2(api_key)
        since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        pulses = otx.getsince(since)
    except Exception as e:
        logger.error("OTX fetch failed: %s", e)
        return []
    iocs = []
    for pulse in pulses:
        pulse_name = pulse.get("name", "Unknown Pulse")
        pulse_tags = pulse.get("tags", [])
        pulse_modified = pulse.get("modified", "")
        for ind in pulse.get("indicators", []):
            type_raw = ind.get("type", "").lower()
            if type_raw.startswith("filehash"):
                indicator_type = "hash"
            elif type_raw in ("ipv4", "ipv6"):
                indicator_type = "ip"
            elif type_raw in ("domain", "hostname"):
                indicator_type = "domain"
            elif type_raw == "url":
                indicator_type = "url"
            elif type_raw == "cve":
                indicator_type = "vuln"
            else:
                indicator_type = "unknown"
            iocs.append({
                "indicator": ind.get("indicator", ""),
                "confidence": 0,
                "country": "",
                "last_seen": pulse_modified,
                "usage": f"{pulse_name} ({', '.join(pulse_tags)})",
                "source": f"OTX-{ind.get('type', 'unknown')}",
                "type": indicator_type,
            })
    return iocs
