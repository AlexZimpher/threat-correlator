import os
import yaml
import requests
import logging
import csv
from io import StringIO
from pathlib import Path

logger = logging.getLogger(__name__)

from threatcorrelator.config_loader import load_config
config = load_config()


def get_abuseipdb_key() -> str:
    """
    Retrieve the AbuseIPDB API key from the environment (ABUSEIPDB_API_KEY)
    or fall back to config. Raises an exception if neither is found.
    """
    env_key = os.getenv("ABUSEIPDB_API_KEY")
    if env_key:
        logger.debug("Using AbuseIPDB API key from environment")
        return env_key.strip()

    try:
        api_key = config["abuseipdb"]["api_key"]
        if not api_key:
            raise KeyError("API key is empty in config")
        logger.debug("Using AbuseIPDB API key from config")
        return api_key.strip()
    except KeyError as e:
        logger.error("API key missing in config: %s", e)
        raise


def fetch_abuseipdb_blacklist(api_key: str = None) -> list[dict]:
    """
    Fetch high-confidence blacklisted IPs from AbuseIPDB.
    Returns a list of dicts, each containing:
    ip, confidence, country, last_seen, usage, source
    """
    if api_key is None:
        api_key = get_abuseipdb_key()

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"confidenceMinimum": config["abuseipdb"].get("confidence_minimum", 90)}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        data = response.json().get("data", [])
    except requests.HTTPError as e:
        logger.error("HTTP error from AbuseIPDB: %s", e)
        raise
    except requests.RequestException as e:
        logger.error("Network error when contacting AbuseIPDB: %s", e)
        raise
    except ValueError as e:
        logger.error("Error parsing JSON response from AbuseIPDB: %s", e)
        raise

    iocs = []
    for entry in data:
        try:
            iocs.append(
                {
                    "indicator": entry.get("ipAddress", ""),
                    "confidence": entry.get("abuseConfidenceScore", 0),
                    "country": entry.get("countryCode", ""),
                    "last_seen": entry.get("lastReportedAt", ""),
                    "usage": entry.get("usageType", ""),
                    "source": "abuseipdb",
                }
            )
        except Exception as e:
            logger.warning("Skipping malformed IOC entry: %s", e)
            continue

    return iocs


def fetch_otx_feed() -> list[dict]:
    """
    Fetch known malicious IPs and domains from AlienVault OTX CSV feeds.
    Returns a list of dicts with keys: ip, domain, country, last_seen, source
    """
    iocs = []
    feeds = {
        "IP": "https://otx.alienvault.com/otxapi/indicators/export?limit=100000&indicator_type=IPv4",
        "Domain": "https://otx.alienvault.com/otxapi/indicators/export?limit=100000&indicator_type=domain",
    }

    for typ, url in feeds.items():
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            text = response.text
        except Exception as e:
            logger.error("OTX fetch failed for %s feed: %s", typ, e)
            continue

        reader = csv.DictReader(StringIO(text))
        for row in reader:
            entry = {
                "indicator": row.get("indicator", ""),
                "country": row.get("country", ""),
                "last_seen": row.get("modified", ""),
                "source": f"OTX-{typ}",
            }
            iocs.append(entry)
    return iocs


__all__ = ["get_abuseipdb_key", "fetch_abuseipdb_blacklist", "fetch_otx_feed"]
