import json
import logging
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
import yaml

from threatcorrelator.storage import get_session, IOC
from threatcorrelator.mitre_map import MITRE_MAPPING
from threatcorrelator.country_map import COUNTRY_MAP

logger = logging.getLogger(__name__)

# Path to config.yaml (for correlation settings)
CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


def extract_indicators_from_log(log_file_path: Path) -> dict[str, int]:
    """
    Parse a newline-delimited JSON log file and return a dict mapping
    each unique indicator (IP or domain) to its occurrence count.
    """
    freq: dict[str, int] = {}
    with open(log_file_path, "r") as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON line in %s", log_file_path)
                continue

            ip = entry.get("src_ip", "")
            domain = (
                entry.get("src_domain") or entry.get("domain") or entry.get("url", "")
            )
            if domain and domain.startswith("http"):
                parsed = urlparse(domain)
                domain = parsed.netloc.lower()

            if ip:
                freq[ip] = freq.get(ip, 0) + 1
            if domain:
                freq[domain] = freq.get(domain, 0) + 1

    return freq


def rate_threat(confidence: int, count: int, last_seen: str | None, freq_thresh: int = 0, max_age_days: int = 0) -> str:
    """
    Determine severity of an IOC based on confidence, frequency, and age.
    """
    # Base severity from confidence
    if confidence >= 90:
        severity = "High"
    elif confidence >= 50:
        severity = "Medium"
    elif confidence > 0:
        severity = "Low"
    else:
        severity = "Medium"

    # Age filtering
    if max_age_days > 0 and last_seen:
        try:
            last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            if last_dt < datetime.now(timezone.utc) - timedelta(days=max_age_days): 
                return "None"
        except Exception:
            pass

    # Frequency escalation
    if freq_thresh > 0 and count > freq_thresh:
        return "Critical"

    return severity


def correlate_logs(log_file_path: Path) -> list[dict]:
    """
    Correlate indicators found in the given log file against stored IOCs.
    Returns a list of result dicts, each containing:
      - indicator, ip, confidence, country, country_name,
        last_seen, usage, source, severity, attack_technique_id,
        attack_technique_name, count_in_log
    """

    # Load correlation settings from config.yaml (frequency & age)
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = yaml.safe_load(f)
        corr_cfg = cfg.get("correlation", {})
        freq_thresh = corr_cfg.get("frequency_threshold", 0)
        max_age_days = corr_cfg.get("max_age_days", 0)
    except Exception:
        logger.warning("Unable to load correlation settings; using defaults")
        freq_thresh = 0
        max_age_days = 0

    freq = extract_indicators_from_log(log_file_path)

    session = get_session()
    all_iocs = {
        ioc.ip: {
            "ip": ioc.ip or "",
            "confidence": ioc.confidence or 0,
            "country": ioc.country or "",
            "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else "",
            "usage": ioc.usage or "",
            "source": ioc.source or "",
        }
        for ioc in session.query(IOC).all()
    }

    results: list[dict] = []

    for indicator, count in freq.items():
        if indicator not in all_iocs:
            continue

        data = all_iocs[indicator]
        severity = rate_threat(
            confidence=data.get("confidence", 0),
            count=count,
            last_seen=data.get("last_seen"),
            freq_thresh=freq_thresh,
            max_age_days=max_age_days,
        )

        if severity == "None":
            logger.debug("Skipping %s: filtered out by age", indicator)
            continue

        country_code = data.get("country", "")
        country_name = COUNTRY_MAP.get(country_code, country_code)

        usage_key = data.get("usage") or indicator
        technique_id, technique_name = MITRE_MAPPING.get(
            usage_key, MITRE_MAPPING["__default__"]
        )

        results.append(
            {
                "indicator": indicator,
                "ip": data.get("ip", ""),
                "confidence": data.get("confidence", 0),
                "country": country_code,
                "country_name": country_name,
                "last_seen": data.get("last_seen", ""),
                "usage": data.get("usage", ""),
                "source": data.get("source", ""),
                "severity": severity,
                "attack_technique_id": technique_id,
                "attack_technique_name": technique_name,
                "count_in_log": count,
            }
        )

    return results
