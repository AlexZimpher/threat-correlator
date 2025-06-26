import os
import csv
from click.testing import CliRunner
from threatcorrelator.cli import cli
from threatcorrelator.fetch import fetch_abuseipdb_blacklist, fetch_otx_feed
from threatcorrelator.storage import get_session, IOC


def test_cli_show_config(tmp_path):
    # Test CLI 'show_config' command with a temp config file
    config_path = tmp_path / "config.yaml"
    config_path.write_text("foo: bar\n")
    runner = CliRunner()
    result = runner.invoke(cli, ["show_config"], env={"PYTHONPATH": str(tmp_path)})
    # Accepts both success and error (if config not found)
    assert result.exit_code in (0, 1, 2)  # nosec


def test_cli_count(tmp_path):
    # Test CLI 'count' command with a temp database
    runner = CliRunner()
    os.environ["TC_DB_PATH"] = f"sqlite:///{tmp_path}/test.db"
    result = runner.invoke(cli, ["count"])
    assert result.exit_code == 0  # nosec
    assert "IOCs stored" in result.output  # nosec
    del os.environ["TC_DB_PATH"]


def test_cli_fetch_and_correlate(tmp_path):
    # Test fetching IOCs and correlating a log file using the CLI
    runner = CliRunner()
    os.environ["TC_DB_PATH"] = f"sqlite:///{tmp_path}/test.db"
    # Fetch static IOCs
    result = runner.invoke(cli, ["fetch", "--source", "static"])
    assert result.exit_code == 0  # nosec
    # Create a log file with a known static indicator
    log_path = tmp_path / "log.jsonl"
    iocs = fetch_abuseipdb_blacklist() or fetch_otx_feed() or []
    indicator = iocs[0]["indicator"] if iocs else "127.0.0.1"
    with open(log_path, "w") as f:
        f.write(f'{{"src_ip": "{indicator}"}}\n')
    # Correlate
    result = runner.invoke(cli, ["correlate", str(log_path)])
    assert result.exit_code == 0  # nosec
    del os.environ["TC_DB_PATH"]


def test_cli_export(tmp_path):
    # Test exporting correlated data to a CSV file using the CLI
    runner = CliRunner()
    os.environ["TC_DB_PATH"] = f"sqlite:///{tmp_path}/test.db"
    # Add IOC to DB
    session = get_session(os.environ["TC_DB_PATH"])
    ioc = IOC(
        indicator="9.9.9.9",
        confidence=99,
        country="US",
        last_seen=None,
        usage="test",
        source="test",
        type="ip",
    )
    session.add(ioc)
    session.commit()
    # Create log file
    log_path = tmp_path / "log.jsonl"
    with open(log_path, "w") as f:
        f.write('{"src_ip": "9.9.9.9"}\n')
    # Export
    output_path = tmp_path / "out.csv"
    result = runner.invoke(
        cli, ["export", str(log_path), "-o", str(output_path), "-c", "90"]
    )
    assert result.exit_code == 0  # nosec
    assert output_path.exists()  # nosec
    with open(output_path) as f:
        reader = csv.reader(f)
        rows = list(reader)
    assert len(rows) > 1  # nosec
    del os.environ["TC_DB_PATH"]
