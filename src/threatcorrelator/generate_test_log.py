import json
import secrets
from pathlib import Path
from datetime import datetime, timedelta

from threatcorrelator.storage import get_session, IOC


def generate_test_log(
    output_path="sampledata/test_logs.jsonl", ioc_count=10, false_positive_count=5
):
    # Generate a test log file with true positives (from IOCs) and false positives
    session = get_session()
    iocs = session.query(IOC).limit(ioc_count).all()

    if not iocs:
        print("\u274c No IOCs in database. Run fetch first.")
        return

    log_entries = []

    # Add IOCs as true positives
    for ioc in iocs:
        entry = {}
        if ioc.indicator.count(".") == 3 and all(
            p.isdigit() for p in ioc.indicator.split(".")
        ):
            entry["src_ip"] = ioc.indicator
        elif "." in ioc.indicator:
            entry["src_domain"] = ioc.indicator
        else:
            continue

        entry["timestamp"] = (
            datetime.utcnow() - timedelta(minutes=secrets.randbelow(120) + 1)
        ).isoformat()
        entry["src_port"] = secrets.randbelow(65535 - 1024) + 1024
        entry["dest_port"] = secrets.choice([22, 80, 443, 3389, 8080])
        entry["protocol"] = secrets.choice(["TCP", "UDP"])
        log_entries.append(entry)

    # Add false positives (clean entries)
    for _ in range(false_positive_count):
        entry = {
            "src_ip": f"192.168.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}",
            "src_domain": f"benign{secrets.randbelow(1000) + 1}.example.com",
            "timestamp": (
                datetime.utcnow() - timedelta(minutes=secrets.randbelow(120) + 1)
            ).isoformat(),
            "src_port": secrets.randbelow(65535 - 1024) + 1024,
            "dest_port": secrets.choice([22, 80, 443, 3389, 8080]),
            "protocol": secrets.choice(["TCP", "UDP"]),
        }
        log_entries.append(entry)

    # Ensure output path exists
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write log entries to file
    with open(path, "w") as f:
        for entry in log_entries:
            f.write(json.dumps(entry) + "\n")

    print(
        f"✅ Generated test log with {len(log_entries)} entries ({len(iocs)} threats, {false_positive_count} benign) at {output_path}"
    )


if __name__ == "__main__":
    generate_test_log()
