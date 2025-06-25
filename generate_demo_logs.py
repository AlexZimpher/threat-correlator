"""
Demo Log Generator for ThreatCorrelator
--------------------------------------
This script creates example log files (JSONL, Apache, Windows XML) using IOCs from your database.

- Ensures every log contains at least one IOC that will be flagged by the correlator.
- Use these logs for demos, screenshots, and CI tests.

Usage:
    poetry run python generate_demo_logs.py

Outputs:
    logs/example_log.jsonl      # JSONL log with IP/domain hits
    logs/example_apache.log     # Apache log with IP hit
    logs/example_windows.xml    # Windows XML log with IP/domain hits

After running, try:
    poetry run python -m threatcorrelator.cli correlate logs/example_log.jsonl
    poetry run python -m threatcorrelator.cli correlate logs/example_apache.log
    poetry run python -m threatcorrelator.cli correlate logs/example_windows.xml

This guarantees a visible detection for portfolio/demo purposes.
"""

import random
from pathlib import Path
from threatcorrelator.storage import get_session, IOC

LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

def pick_iocs(n=2):
    """Pick n random IOCs from the database."""
    session = get_session()
    iocs = session.query(IOC).all()
    if not iocs:
        print("No IOCs found in the database. Please fetch IOCs first.")
        return []
    return random.sample(iocs, min(n, len(iocs)))

def write_jsonl_log(iocs):
    log_path = LOGS_DIR / "example_log.jsonl"
    with open(log_path, "w") as f:
        for ioc in iocs:
            if ioc.type == "ip":
                f.write(f'{{"timestamp": "2024-06-23T12:00:00Z", "src_ip": "{ioc.indicator}", "event": "connection_attempt"}}\n')
            elif ioc.type == "domain":
                f.write(f'{{"timestamp": "2024-06-23T12:01:00Z", "domain": "{ioc.indicator}", "event": "dns_query"}}\n')
            elif ioc.type == "url":
                f.write(f'{{"timestamp": "2024-06-23T12:02:00Z", "url": "{ioc.indicator}", "event": "web_request"}}\n')
            elif ioc.type == "hash":
                f.write(f'{{"timestamp": "2024-06-23T12:03:00Z", "file_hash": "{ioc.indicator}", "event": "file_scan"}}\n')
    print(f"Created {log_path}")

def write_apache_log(iocs):
    log_path = LOGS_DIR / "example_apache.log"
    with open(log_path, "w") as f:
        for ioc in iocs:
            if ioc.type == "ip":
                f.write(f'{ioc.indicator} - - [23/Jun/2024:12:01:00 +0000] "POST /login HTTP/1.1" 403 512\n')
    print(f"Created {log_path}")

def write_windows_xml_log(iocs):
    log_path = LOGS_DIR / "example_windows.xml"
    xml_events = []
    for ioc in iocs:
        if ioc.type == "ip":
            xml_events.append(f"""
      <Event>
        <System><Provider Name="Microsoft-Windows-Security-Auditing"/></System>
        <EventData>
          <Data Name="IpAddress">{ioc.indicator}</Data>
        </EventData>
      </Event>""")
        elif ioc.type == "domain":
            xml_events.append(f"""
      <Event>
        <System><Provider Name="Microsoft-Windows-Security-Auditing"/></System>
        <EventData>
          <Data Name="Domain">{ioc.indicator}</Data>
        </EventData>
      </Event>""")
    xml_content = f"""<?xml version="1.0"?>
<Events>
{''.join(xml_events)}
</Events>
"""
    with open(log_path, "w") as f:
        f.write(xml_content)
    print(f"Created {log_path}")

if __name__ == "__main__":
    iocs = pick_iocs(2)
    if iocs:
        write_jsonl_log(iocs)
        write_apache_log(iocs)
        write_windows_xml_log(iocs)
    else:
        print("No demo logs created.")