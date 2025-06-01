import csv
import json
import yaml
from pathlib import Path
from typing import List
from threatcorrelator.storage import get_session, IOC

CONFIG_PATH = Path("config/config.yaml")

def load_severity_thresholds() -> dict:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        return config.get("severity_thresholds", {"high": 80, "medium": 50})
    except Exception:
        # Fallback to defaults if config is missing or malformed
        return {"high": 80, "medium": 50}

def extract_ips_from_log(file_path: Path) -> set:
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    ips = set()
    for line in lines:
        try:
            record = json.loads(line)
            for key in ["src_ip", "dest_ip", "ip"]:
                ip = record.get(key)
                if ip:
                    ips.add(ip)
        except json.JSONDecodeError:
            continue
    return ips

def rate_threat(confidence: int, thresholds: dict) -> str:
    if confidence >= thresholds["high"]:
        return "High"
    elif confidence >= thresholds["medium"]:
        return "Medium"
    else:
        return "Low"

def correlate_logs(log_path: Path) -> List[dict]:
    session = get_session()
    ips = extract_ips_from_log(log_path)
    thresholds = load_severity_thresholds()
    results = []

    for ip in ips:
        ioc = session.get(IOC, ip)
        if ioc:
            severity = rate_threat(ioc.confidence, thresholds)
            results.append({
                "ip": ip,
                "confidence": ioc.confidence,
                "country": ioc.country,
                "last_seen": ioc.last_seen.isoformat().replace("Z", ""),
                "usage": ioc.usage,
                "severity": severity
            })

    return results

def save_results(results: List[dict], path: Path, fmt: str = "csv"):
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    else:
        raise ValueError("Unsupported format")
