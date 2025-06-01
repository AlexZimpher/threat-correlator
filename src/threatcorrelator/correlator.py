import re
import sqlite3
from .database import DB_PATH

def scan_file(log_path):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    results = {}

    with open(log_path, "r") as f:
        for line in f:
            for ip in ip_pattern.findall(line):
                cur.execute("SELECT confidence FROM iocs WHERE ip = ?", (ip,))
                row = cur.fetchone()
                if row:
                    confidence = row[0]
                    severity = ("HIGH" if confidence >= 80 else
                                "MEDIUM" if confidence >= 50 else "LOW")
                    if ip not in results:
                        results[ip] = {"confidence": confidence, "severity": severity, "count": 0}
                    results[ip]["count"] += 1
    conn.close()
    return results

