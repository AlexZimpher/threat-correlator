import sys
import logging
import click
from pathlib import Path
from datetime import datetime
import csv
import yaml
from threatcorrelator.logging_config import setup_logging
from threatcorrelator.storage import get_session, IOC
from threatcorrelator.fetch import (
    fetch_abuseipdb_blacklist,
    fetch_otx_feed,
    fetch_static_malware_feed,
)
from threatcorrelator.correlate import correlate_logs
from threatcorrelator.config_loader import load_config

# Set up logging for the CLI
setup_logging()
logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    """Main entry point for the Threat-Correlator CLI."""
    pass


@cli.command()
def greet() -> None:
    """Print a message to confirm the CLI is working."""
    logger.info("greet command invoked")
    click.echo("\u2705 Threat-Correlator CLI is working.")


@cli.command()
def show_config() -> None:
    """Print the merged configuration from config.yaml and config.local.yaml."""
    try:
        config = load_config()
        logger.info("Loaded config successfully")
        click.echo(yaml.dump(config, sort_keys=False))
    except Exception as exc:
        logger.exception("Error loading config")
        click.echo(f"❌ Failed to load config: {exc}")
        sys.exit(1)


@cli.command()
@click.option(
    "--source",
    required=False,
    default="abuseipdb",
    show_default=True,
    type=click.Choice(["abuseipdb", "otx", "static", "both"]),
    help="Which IOC source to fetch: abuseipdb, otx, static, or both",
)
def fetch(source: str) -> None:
    """Fetch IOCs from selected sources and store them."""
    all_iocs = []
    if source in ("abuseipdb", "both"):
        try:
            abuse_iocs = fetch_abuseipdb_blacklist()
            all_iocs.extend(abuse_iocs)
            logger.info("Fetched %d IOCs from AbuseIPDB", len(abuse_iocs))
        except Exception as exc:
            logger.error("Error fetching from AbuseIPDB: %s", exc)
    if source in ("otx", "both"):
        try:
            otx_iocs = fetch_otx_feed()
            all_iocs.extend(otx_iocs)
            logger.info("Fetched %d IOCs from OTX", len(otx_iocs))
        except Exception as exc:
            logger.error("Error fetching from OTX: %s", exc)
    if source in ("static", "both"):
        try:
            static_iocs = fetch_static_malware_feed()
            all_iocs.extend(static_iocs)
            logger.info("Fetched %d IOCs from static malware feed", len(static_iocs))
        except Exception as exc:
            logger.error("Error fetching from static malware feed: %s", exc)
    if not all_iocs:
        logger.warning("No IOCs fetched from any source.")
        click.echo("❌ No IOCs retrieved.")
        return
    session = get_session()
    added = 0
    source_counts = {}
    for ioc in all_iocs:
        indicator = ioc.get("indicator")
        if not indicator:
            continue
        existing = session.get(IOC, indicator)
        if existing:
            continue
        try:
            allowed_fields = {
                "indicator",
                "confidence",
                "country",
                "last_seen",
                "usage",
                "source",
                "type",
            }
            ioc_data = {k: v for k, v in ioc.items() if k in allowed_fields}
            if ioc_data.get("last_seen"):
                ioc_data["last_seen"] = datetime.fromisoformat(
                    ioc_data["last_seen"].replace("Z", "+00:00")
                )
            obj = IOC(
                indicator=ioc_data.get("indicator"),
                confidence=ioc_data.get("confidence", 0),
                country=ioc_data.get("country", ""),
                last_seen=ioc_data.get("last_seen", None),
                usage=ioc_data.get("usage", ""),
                source=ioc_data.get("source", "unknown"),
                type=ioc_data.get("type", ""),
            )
            session.add(obj)
            added += 1
            source_val = ioc_data.get("source", "unknown")
            source_counts[source_val] = source_counts.get(source_val, 0) + 1
        except Exception as exc:
            logger.warning("Error processing IOC %s: %s", indicator, exc)
            continue
    try:
        session.commit()
        logger.info("Stored %d new IOCs in database", added)
        click.echo(f"✅ Stored {added} new IOCs in database.")
        for src, count in source_counts.items():
            click.echo(f"- {src}: {count}")
    except Exception as exc:
        logger.exception("Commit failed")
        click.echo(f"❌ Failed to commit IOCs to database: {exc}")


@cli.command()
def count() -> None:
    """Count and display the number of IOCs in the database."""
    try:
        session = get_session()
        total = session.query(IOC).count()
        click.echo(f"📦 {total} IOCs stored in the database.")
    except Exception as exc:
        logger.exception("Database count failed")
        click.echo(f"❌ Count failed: {exc}")
        sys.exit(1)


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
def correlate(logfile):
    """Correlate a JSON log file against stored IOCs and display matches."""
    logfile_path = Path(logfile)
    try:
        import os

        db_url = os.getenv("TC_DB_PATH")
        session = get_session(db_url) if db_url else get_session()
        results = correlate_logs(logfile_path, session=session)
        click.echo(f"✅ Matched {len(results)} threats.")
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for r in results:
            sev = r.get("severity")
            if sev in severity_counts:
                severity_counts[sev] += 1
        for level, cnt in severity_counts.items():
            click.echo(f"- {cnt} {level}")
    except Exception as exc:
        logger.exception("Correlation error")
        click.echo(f"❌ Correlation failed: {exc}")
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
@click.option(
    "--min-confidence",
    "-c",
    type=int,
    default=0,
    help="Only export IOCs with confidence ≥ this value",
)
def export(logfile, output, min_confidence):
    """Scan a log file and export matched IOCs to a CSV file."""
    logfile_path = Path(logfile)
    try:
        results = correlate_logs(logfile_path)
    except Exception as exc:
        logger.exception("Error during correlation in export")
        click.echo(f"❌ Export failed: {exc}")
        sys.exit(1)
    filtered = [r for r in results if r.get("confidence", 0) >= min_confidence]
    if not filtered:
        click.echo("✅ No threats met the confidence filter.")
        return
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "indicator",
                    "confidence",
                    "country",
                    "country_name",
                    "last_seen",
                    "usage",
                    "source",
                    "type",
                    "severity",
                    "attack_technique_id",
                ]
            )
            for r in filtered:
                writer.writerow(
                    [
                        r.get("indicator", ""),
                        r.get("confidence", ""),
                        r.get("country", ""),
                        r.get("country_name", ""),
                        r.get("last_seen", ""),
                        r.get("usage", ""),
                        r.get("source", ""),
                        r.get("type", ""),
                        r.get("severity", ""),
                        r.get("attack_technique_id", ""),
                    ]
                )
        click.echo(f"✅ Exported {len(filtered)} threats to {output}")
    except Exception as exc:
        logger.exception("Export failed")
        click.echo(f"❌ Export failed: {exc}")
        sys.exit(1)


main = cli

if __name__ == "__main__":
    cli()
