import json
import logging
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
import yaml
from typing import Optional

from threatcorrelator.storage import get_session, IOC
from threatcorrelator.mitre_map import MITRE_MAPPING, dynamic_mitre_mapping
from threatcorrelator.country_map import COUNTRY_MAP
from threatcorrelator.enrichment import enrich_indicator

logger = logging.getLogger(__name__)
CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


def extract_indicators_from_log(log_file_path: Path) -> dict[str, int]:
    """
    Parse a log file (JSONL, CSV, Apache, or Windows XML) and return a dict mapping
    each unique indicator (IP, domain, etc.) to its occurrence count.

    Args:
        log_file_path (Path): Path to the log file.
    Returns:
        dict[str, int]: Mapping of indicator to occurrence count.
    """
    freq: dict[str, int] = {}
    ext = log_file_path.suffix.lower()
    if ext in {'.csv'}:
        import csv
        with open(log_file_path, newline='') as f:
            reader = csv.DictReader(f)
            for entry in reader:
                indicator = entry.get("src_ip") or entry.get("ip")
                domain = entry.get("src_domain") or entry.get("domain") or entry.get("url")
                if indicator:
                    freq[indicator] = freq.get(indicator, 0) + 1
                if domain:
                    freq[domain] = freq.get(domain, 0) + 1
        return freq
    elif ext in {'.xml'}:
        import xml.etree.ElementTree as ET
        tree = ET.parse(log_file_path)
        root = tree.getroot()
        for event in root.findall('.//Event'):
            for data in event.findall('.//Data'):
                name = data.attrib.get('Name', '').lower()
                value = data.text
                if name in {"ipaddress", "src_ip", "ip"} and value:
                    freq[value] = freq.get(value, 0) + 1
                if name in {"domain", "src_domain"} and value:
                    freq[value] = freq.get(value, 0) + 1
        return freq
    elif ext in {'.log', '.txt'}:
        # Try Apache access log (common/combined)
        import re
        apache_re = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+)')
        with open(log_file_path, 'r') as f:
            for line in f:
                m = apache_re.match(line)
                if m:
                    ip = m.group('ip')
                    freq[ip] = freq.get(ip, 0) + 1
        return freq
    else:
        # Default: JSONL
        with open(log_file_path, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid JSON line in %s", log_file_path)
                    continue

                indicator = entry.get("src_ip", "")
                domain = (
                    entry.get("src_domain") or entry.get("domain") or entry.get("url", "")
                )
                if domain and domain.startswith("http"):
                    parsed = urlparse(domain)
                    domain = parsed.netloc.lower()

                if indicator:
                    freq[indicator] = freq.get(indicator, 0) + 1
                if domain:
                    freq[domain] = freq.get(domain, 0) + 1

    # After populating freq, also extract hashes, URLs, file paths
    # (for JSONL and CSV, as a demonstration)
    # Anomaly detection: flag indicators with abnormally high frequency
    threshold = max(10, int(0.05 * sum(freq.values())))
    anomalies = {k: v for k, v in freq.items() if v > threshold}
    if anomalies:
        logger.info(f"Anomaly detected: {anomalies}")
    return freq


def rate_threat(
    confidence: int,
    count: int,
    last_seen: str,
    freq_thresh: int = 0,
    max_age_days: int = 0,
    indicator_type: str = "unknown"
) -> str:
    """
    Determine severity of an IOC based on confidence, frequency, age, and type.

    Args:
        confidence (int): Confidence score.
        count (int): Number of occurrences in logs.
        last_seen (str): Last seen timestamp (ISO format).
        freq_thresh (int): Frequency threshold for escalation.
        max_age_days (int): Max age in days for filtering.
        indicator_type (str): Type of indicator (ip, domain, etc.).
    Returns:
        str: Severity label (Critical, High, Medium, Low, None).
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


def lookup_ioc(session, indicator: str) -> Optional[IOC]:
    """
    Look up an IOC in the database by indicator value, trying both direct and domain-type matches.
    """
    ioc = session.query(IOC).filter(IOC.indicator == indicator).first()
    if not ioc:
        ioc = session.query(IOC).filter(IOC.indicator == indicator, IOC.type == "domain").first()
    return ioc


def format_correlation_result(ioc: IOC, count: int) -> dict:
    """
    Format a correlation result dictionary from an IOC and count.
    """
    confidence = getattr(ioc, 'confidence', 0)
    ioc_type = getattr(ioc, 'type', None)
    last_seen = str(getattr(ioc, 'last_seen', ''))
    freq_thresh = 0
    max_age_days = 0
    ioc_type_str = str(ioc_type) if ioc_type else "unknown"
    usage = getattr(ioc, 'usage', None)
    usage_key = str(usage) if usage else "__default__"
    technique, _ = MITRE_MAPPING.get(usage_key, MITRE_MAPPING["__default__"])
    return {
        "indicator": ioc.indicator,
        "confidence": confidence,
        "country": ioc.country,
        "last_seen": ioc.last_seen,
        "usage": ioc.usage,
        "source": ioc.source,
        "type": ioc_type,
        "count": count,
        "severity": rate_threat(confidence or 0, count, last_seen, freq_thresh, max_age_days, ioc_type_str),
        "attack_technique_id": technique,
    }


def correlate_logs(log_file_path: Path, geoip_db_path: Optional[str] = None, session=None) -> list[dict]:
    """
    Correlate indicators in a log file with threat intelligence and enrichment.
    Args:
        log_file_path (Path): Path to the log file.
        geoip_db_path (Optional[str]): Path to GeoIP database for enrichment.
        session: Optional database session for IOC lookup (for testing or custom DB).
    Returns:
        list[dict]: List of correlation results with enrichment.
    """
    indicator_counts = extract_indicators_from_log(log_file_path)
    results = []
    # If session is not provided, get default session
    if session is None:
        from threatcorrelator.storage import get_session
        session = get_session()
    for indicator, count in indicator_counts.items():
        enrichment = enrich_indicator(indicator, geoip_db_path)
        # Try to look up IOC in DB for additional info
        ioc = lookup_ioc(session, indicator)
        if ioc:
            result = format_correlation_result(ioc, count)
            result.update(enrichment)
            results.append(result)
        # else: skip indicators not in DB
    return results


def detect_multi_stage_behaviors(log_file_path: Path) -> list[dict]:
    """
    Stub for multi-stage behavior detection (e.g., brute force then exfiltration).
    """
    # This would parse the log and look for sequences of events by the same indicator.
    # For now, just return an empty list.
    return []
