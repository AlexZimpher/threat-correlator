import click
import yaml
import csv
from pathlib import Path
from datetime import datetime
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.fetch import fetch_abuseipdb_blacklist
from threatcorrelator.correlate import correlate_logs, save_results

CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"

@click.group()
def cli():
    """Threat-Correlator CLI."""
    pass

@cli.command()
def greet():
    """Say hello to confirm CLI works."""
    click.echo("✅ Threat-Correlator CLI is working.")

@cli.command()
def show_config():
    """Print contents of config.yaml."""
    try:
        with open(CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)
            click.echo(config)
    except Exception as e:
        click.echo(f"❌ Failed to load config: {e}")

@cli.command()
def fetch():
    """Fetch blacklisted IPs from AbuseIPDB and store them."""
    try:
        iocs = fetch_abuseipdb_blacklist()
        session = get_session()
        added = 0

        for ioc in iocs:
            if not session.get(IOC, ioc["ip"]):
                obj = IOC(
                    ip=ioc["ip"],
                    confidence=ioc["confidence"],
                    country=ioc["country"],
                    last_seen=datetime.fromisoformat(ioc["last_seen"].replace("Z", "+00:00")),
                    usage=ioc["usage"],
                    source=ioc["source"]
                )
                session.add(obj)
                added += 1
        session.commit()
        click.echo(f"✅ Stored {added} new IOCs in database.")
    except Exception as e:
        click.echo(f"❌ Fetch/store failed: {e}")

@cli.command()
def count():
    """Count number of IOCs in database."""
    try:
        session = get_session()
        count = session.query(IOC).count()
        click.echo(f"📦 {count} IOCs stored in the database.")
    except Exception as e:
        click.echo(f"❌ Count failed: {e}")

@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
def correlate(logfile):
    """Correlate a JSON log file against stored IOCs."""
    try:
        results = correlate_logs(Path(logfile))
        click.echo(f"✅ Matched {len(results)} threats.")
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for r in results:
            severity_counts[r["severity"]] += 1
        for level, count in severity_counts.items():
            click.echo(f"- {count} {level}")
    except Exception as e:
        click.echo(f"❌ Correlation failed: {e}")

@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default="outputs/threats.csv", help="Output CSV file path")
def export(logfile, output):
    """Scan a log file and export matched IOCs to CSV."""
    try:
        results = correlate_logs(Path(logfile))
        if not results:
            click.echo("✅ No threats found.")
            return

        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "confidence", "severity", "category", "timestamp"])
            for r in results:
                writer.writerow([
                    r["ip"],
                    r["confidence"],
                    r["severity"],
                    r.get("category", ""),
                    r.get("timestamp", "")
                ])

        click.echo(f"✅ Exported {len(results)} threats to {output}")
    except Exception as e:
        click.echo(f"❌ Export failed: {e}")
