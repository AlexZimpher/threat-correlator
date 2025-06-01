import json
import logging
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timedelta
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

    # Build frequency dictionary of indicators
    freq = extract_indicators_from_log(log_file_path)

    # Load all IOCs from the database into a dict keyed by IP (no domain in model)
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
    now = datetime.utcnow()
    age_limit = now - timedelta(days=max_age_days) if max_age_days > 0 else None

    for indicator, count in freq.items():
        if indicator not in all_iocs:
            continue

        data = all_iocs[indicator]
        confidence = data.get("confidence", 0)

        # Base severity from confidence
        if confidence >= 90:
            base_severity = "High"
        elif confidence >= 50:
            base_severity = "Medium"
        elif confidence > 0:
            base_severity = "Low"
        else:
            base_severity = "Medium"

        # Age filtering
        if age_limit and data.get("last_seen"):
            try:
                last_dt = datetime.fromisoformat(
                    data["last_seen"].replace("Z", "+00:00")
                )
                if last_dt < age_limit:
                    logger.debug(
                        "Skipping %s: last_seen older than %d days",
                        indicator,
                        max_age_days,
                    )
                    continue
            except ValueError:
                pass  # If parsing fails, do not skip

        # Frequency-based escalation
        severity = base_severity
        if freq_thresh and count > freq_thresh:
            severity = "Critical"

        # Country name resolution
        country_code = data.get("country", "")
        country_name = COUNTRY_MAP.get(country_code, country_code)

        # MITRE ATT&CK mapping
        usage_key = data.get("usage") or indicator
        technique_id, technique_name = MITRE_MAPPING.get(
            usage_key, MITRE_MAPPING["__default__"]
        )

        results.append(
            {
                "indicator": indicator,
                "ip": data.get("ip", ""),
                "confidence": confidence,
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
