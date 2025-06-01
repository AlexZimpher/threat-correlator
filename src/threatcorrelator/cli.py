import sys
import logging
import click
import yaml
import csv

from pathlib import Path
from datetime import datetime

from threatcorrelator.logging_config import setup_logging
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.fetch import (
    fetch_abuseipdb_blacklist,
    get_abuseipdb_key,
    fetch_otx_feed,
)
from threatcorrelator.correlate import correlate_logs

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Path to config.yaml (fallback if no environment variable for API key)
CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"


@click.group()
def cli():
    """Threat-Correlator CLI."""
    pass


@cli.command()
def greet():
    """Say hello to confirm CLI works."""
    logger.info("greet command invoked")
    click.echo("✅ Threat-Correlator CLI is working.")


@cli.command()
def show_config():
    """Print contents of config.yaml."""
    try:
        with open(CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)
        logger.info("Loaded config.yaml successfully")
        click.echo(config)
    except FileNotFoundError:
        logger.error("config.yaml not found at %s", CONFIG_PATH)
        click.echo("❌ Failed to load config: config.yaml not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error("YAML parsing error: %s", e, exc_info=True)
        click.echo(f"❌ Failed to parse config.yaml: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error in show_config")
        click.echo(f"❌ Failed to load config: {e}")
        sys.exit(1)


@cli.command()
def fetch():
    """Fetch blacklisted IPs from AbuseIPDB and store them."""
    try:
        api_key = get_abuseipdb_key()
    except Exception as e:
        logger.error("Failed to retrieve AbuseIPDB API key: %s", e)
        click.echo(
            "❌ Fetch/store failed: cannot find API key in environment or config."
        )
        sys.exit(1)

    try:
        iocs = fetch_abuseipdb_blacklist(api_key=api_key)
    except Exception as e:
        logger.exception("Error fetching IOCs from AbuseIPDB")
        click.echo("❌ Fetch failed: check API key and network connectivity.")
        sys.exit(1)

    session = get_session()
    added = 0

    for ioc in iocs:
        ip_address = ioc.get("ip")
        try:
            existing = session.get(IOC, ip_address)
        except Exception as e:
            logger.error(
                "Database lookup failed for IP %s: %s", ip_address, e, exc_info=True
            )
            click.echo("❌ Fetch/store failed: database lookup error.")
            sys.exit(1)

        if not existing:
            try:
                obj = IOC(
                    ip=ip_address,
                    confidence=ioc.get("confidence", 0),
                    country=ioc.get("country", ""),
                    last_seen=datetime.fromisoformat(
                        ioc.get("last_seen", "").replace("Z", "+00:00")
                    ),
                    usage=ioc.get("usage", ""),
                    source=ioc.get("source", "AbuseIPDB"),
                )
                session.add(obj)
                added += 1
            except Exception as e:
                logger.error(
                    "Error creating IOC object for IP %s: %s",
                    ip_address,
                    e,
                    exc_info=True,
                )
                continue

    try:
        session.commit()
        logger.info("Stored %d new IOCs in database", added)
        click.echo(f"✅ Stored {added} new IOCs in database.")
    except Exception as e:
        logger.exception("Database commit failed")
        click.echo("❌ Fetch/store failed: could not commit to database.")
        sys.exit(1)


@cli.command()
def count():
    """Count number of IOCs in database."""
    try:
        session = get_session()
        total = session.query(IOC).count()
        logger.info("Counted %d IOCs in database", total)
        click.echo(f"📦 {total} IOCs stored in the database.")
    except Exception as e:
        logger.exception("Database count failed")
        click.echo(f"❌ Count failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
def correlate(logfile):
    """Correlate a JSON log file against stored IOCs."""
    logfile_path = Path(logfile)
    if not logfile_path.exists():
        logger.error("Log file not found: %s", logfile_path)
        click.echo("❌ Correlation failed: log file not found.")
        sys.exit(1)

    try:
        results = correlate_logs(logfile_path)
        logger.info("Correlation found %d threats in %s", len(results), logfile_path)
        click.echo(f"✅ Matched {len(results)} threats.")
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for r in results:
            sev = r.get("severity")
            if sev in severity_counts:
                severity_counts[sev] += 1
        for level, cnt in severity_counts.items():
            click.echo(f"- {cnt} {level}")
    except FileNotFoundError:
        logger.error("Correlate: logfile not found: %s", logfile_path)
        click.echo("❌ Correlation failed: log file not found.")
        sys.exit(1)
    except PermissionError:
        logger.error("Permission denied reading log file: %s", logfile_path)
        click.echo("❌ Correlation failed: permission denied reading log file.")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error during correlation")
        click.echo(f"❌ Correlation failed: {e}")
        sys.exit(1)


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="outputs/threats.csv",
    help="Output CSV file path",
)
def export(logfile, output):
    """Scan a log file and export matched IOCs to CSV."""
    logfile_path = Path(logfile)
    if not logfile_path.exists():
        logger.error("Export: logfile not found: %s", logfile_path)
        click.echo("❌ Export failed: log file not found.")
        sys.exit(1)

    try:
        results = correlate_logs(logfile_path)
    except Exception as e:
        logger.exception("Error during correlation in export")
        click.echo(f"❌ Export failed: correlation error - {e}")
        sys.exit(1)

    if not results:
        logger.info("Export: no threats found in %s", logfile_path)
        click.echo("✅ No threats found.")
        return

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["ip", "confidence", "country", "last_seen", "usage", "severity"]
            )
            for r in results:
                writer.writerow(
                    [
                        r.get("ip", ""),
                        r.get("confidence", ""),
                        r.get("country", ""),
                        r.get("last_seen", ""),
                        r.get("usage", ""),
                        r.get("severity", ""),
                    ]
                )
        logger.info("Exported %d threats to %s", len(results), output_path)
        click.echo(f"✅ Exported {len(results)} threats to {output}")
    except PermissionError:
        logger.error("Permission denied writing to %s", output_path)
        click.echo("❌ Export failed: permission denied writing file.")
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error during export")
        click.echo(f"❌ Export failed: {e}")
        sys.exit(1)
