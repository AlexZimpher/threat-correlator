DB_PATH = "threats.db"

import sqlite3

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            ip TEXT PRIMARY KEY,
            confidence INTEGER,
            last_reported TEXT
        );
    """)
    conn.commit()
    conn.close()

def save_iocs(ioc_list):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    for ioc in ioc_list:
        cur.execute("INSERT OR IGNORE INTO iocs VALUES (?, ?, ?)",
                    (ioc["ip"], ioc["confidence"], ioc["last_reported"]))
    conn.commit()
    conn.close()

import csv

def export_to_csv(path):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT * FROM iocs").fetchall()
    conn.close()

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "confidence", "last_reported"])
        writer.writerows(rows)

