import os
import requests
import logging
from datetime import datetime, timedelta
from typing import Optional, List
from OTXv2 import OTXv2
from threatcorrelator.config_loader import load_config

logger = logging.getLogger(__name__)
config = load_config()

__all__ = ["fetch_abuseipdb_blacklist", "fetch_otx_feed", "fetch_static_malware_feed"]

def fetch_abuseipdb_blacklist(api_key: Optional[str] = None) -> List[dict]:
    """
    Fetch IOCs from AbuseIPDB. Returns a list of dicts with keys:
    indicator, confidence, country, last_seen, usage, source, type
    API key is loaded from environment variable ABUSEIPDB_API_KEY if not provided.

    :param api_key: Optional API key for AbuseIPDB. If not provided, the function
                    will attempt to retrieve it from the environment variable
                    'ABUSEIPDB_API_KEY' or from the config file.
    :return: A list of dictionaries containing the IOCs and their associated data.
    """
    if api_key is None:
        api_key = os.environ.get("ABUSEIPDB_API_KEY") or config["abuseipdb"]["api_key"]
    url = config["abuseipdb"]["endpoint"]
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {
        "confidenceMinimum": config["abuseipdb"].get("confidence_threshold", 90),
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
        indicator = entry.get("ipAddress", "")
        iocs.append({
            "indicator": indicator,
            "confidence": entry.get("abuseConfidenceScore", 0),
            "country": entry.get("countryCode", ""),
            "last_seen": entry.get("lastReportedAt", ""),
            "usage": entry.get("usageType", ""),
            "source": "abuseipdb",
            "type": "ip",
        })
    return iocs

def fetch_otx_feed() -> List[dict]:
    """
    Fetch IOCs from AlienVault OTX. Returns a list of dicts with keys:
    indicator, confidence, country, last_seen, usage, source, type
    API key is loaded from environment variable OTX_API_KEY if not provided.

    :return: A list of dictionaries containing the IOCs and their associated data
             from the AlienVault OTX.
    """
    try:
        api_key = os.environ.get("OTX_API_KEY") or config["otx"]["api_key"]
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
            indicator = ind.get("indicator", "")
            ioc = {
                "indicator": indicator,
                "confidence": 0,
                "country": "",
                "last_seen": pulse_modified,
                "usage": f"{pulse_name} ({', '.join(pulse_tags)})",
                "source": f"OTX-{ind.get('type', 'unknown')}",
                "type": indicator_type,
            }
            if indicator_type == "ip":
                ioc["indicator"] = indicator
            elif indicator_type == "domain":
                ioc["domain"] = indicator
            iocs.append(ioc)
    return iocs

def fetch_static_malware_feed(path: str = "data/static_malware_feed.json") -> list[dict]:
    """
    Fetch IOCs from a static local JSON file for demonstration.
    """
    import json
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load static malware feed: {e}")
        return []

def fetch_virustotal(api_key: Optional[str] = None) -> List[dict]:
    """
    Fetch IOCs from VirusTotal Public API (scaffold).
    Returns a list of dicts with keys: indicator, confidence, country, last_seen, usage, source, type.
    API key is loaded from environment variable VIRUSTOTAL_API_KEY if not provided.
    
    Example usage:
        iocs = fetch_virustotal()
    """
    # TODO: Implement API call and parsing logic
    return []
