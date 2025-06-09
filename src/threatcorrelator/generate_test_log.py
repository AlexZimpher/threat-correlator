import json
import random
from pathlib import Path
from datetime import datetime, timedelta

from threatcorrelator.storage import get_session, IOC

def generate_test_log(output_path="data/test_logs.jsonl", ioc_count=10, false_positive_count=5):
    session = get_session()
    iocs = session.query(IOC).limit(ioc_count).all()

    if not iocs:
        print("❌ No IOCs in database. Run fetch first.")
        return

    log_entries = []

    # Add IOCs as true positives
    for ioc in iocs:
        entry = {}
        if ioc.indicator.count(".") == 3 and all(p.isdigit() for p in ioc.indicator.split(".")):
            entry["src_ip"] = ioc.indicator
        elif "." in ioc.indicator:
            entry["src_domain"] = ioc.indicator
        else:
            continue

        entry["timestamp"] = (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat()
        entry["src_port"] = random.randint(1024, 65535)
        entry["dest_port"] = random.choice([22, 80, 443, 3389, 8080])
        entry["protocol"] = random.choice(["TCP", "UDP"])
        log_entries.append(entry)

    # Add false positives (clean entries)
    for _ in range(false_positive_count):
        entry = {
            "src_ip": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "src_domain": f"benign{random.randint(1, 1000)}.example.com",
            "timestamp": (datetime.utcnow() - timedelta(minutes=random.randint(1, 120))).isoformat(),
            "src_port": random.randint(1024, 65535),
            "dest_port": random.choice([22, 80, 443, 3389, 8080]),
            "protocol": random.choice(["TCP", "UDP"]),
        }
        log_entries.append(entry)

    # Ensure output path exists
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write log entries to file
    with open(path, "w") as f:
        for entry in log_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"✅ Generated test log with {len(log_entries)} entries ({len(iocs)} threats, {false_positive_count} benign) at {output_path}")

if __name__ == "__main__":
    generate_test_log()
