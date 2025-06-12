import json
import logging
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
import yaml
from typing import Optional

from threatcorrelator.storage import get_session, IOC
from threatcorrelator.mitre_map import MITRE_MAPPING
from threatcorrelator.country_map import COUNTRY_MAP

logger = logging.getLogger(__name__)
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


def rate_threat(confidence: int, count: int, last_seen: str, freq_thresh: int = 0, max_age_days: int = 0, indicator_type: str = "unknown") -> str:
    """
    Determine severity of an IOC based on confidence, frequency, age, and type.
    """
    # Frequency escalation
    if freq_thresh > 0 and count > freq_thresh:
        return "Critical"
    # Age filtering
    if max_age_days > 0 and last_seen:
        try:
            last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            if last_dt < datetime.now(timezone.utc) - timedelta(days=max_age_days):
                return "None"
        except Exception:
            pass
    # Confidence levels
    if confidence >= 85:
        return "High"
    elif confidence >= 50:
        return "Medium"
    elif confidence > 0:
        return "Low"
    else:
        return "Medium"


def correlate_logs(log_file_path: Path, session=None) -> list[dict]:
    """
    Correlate log entries with IOCs in the database. Returns a list of matches.
    """
    if session is None:
        session = get_session()
    indicators = extract_indicators_from_log(log_file_path)
    results = []
    for indicator, count in indicators.items():
        # Try to match as IP
        ioc = session.query(IOC).filter(IOC.ip == indicator).first()
        if not ioc:
            # Try to match as domain
            ioc = session.query(IOC).filter(IOC.domain == indicator).first()
        if ioc:
            confidence = getattr(ioc, 'confidence', 0)
            ioc_type = getattr(ioc, 'type', None)
            last_seen = str(getattr(ioc, 'last_seen', ''))
            freq_thresh = 0
            max_age_days = 0
            ioc_type_str = str(ioc_type) if ioc_type else "unknown"
            usage = getattr(ioc, 'usage', None)
            usage_key = str(usage) if usage else "__default__"
            technique, _ = MITRE_MAPPING.get(usage_key, MITRE_MAPPING["__default__"])
            results.append({
                "indicator": ioc.indicator,
                "ip": ioc.ip,
                "domain": ioc.domain,
                "confidence": confidence,
                "country": ioc.country,
                "last_seen": ioc.last_seen,
                "usage": ioc.usage,
                "source": ioc.source,
                "type": ioc_type,
                "count": count,
                "severity": rate_threat(confidence or 0, count, last_seen, freq_thresh, max_age_days, ioc_type_str),
                "attack_technique_id": technique,
            })
    return results
