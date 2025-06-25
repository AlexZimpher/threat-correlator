import importlib.util
import pytest
from click.testing import CliRunner
from threatcorrelator import dashboard
from threatcorrelator.cli import cli
from threatcorrelator.fetch import fetch_static_malware_feed, fetch_virustotal
from threatcorrelator.generate_test_log import generate_test_log


def test_dashboard_import_runs():
    # Just ensure the dashboard module can be imported and main() can be called without error
    assert importlib.util.find_spec("threatcorrelator.dashboard") is not None
    # Should not raise
    dashboard.main()

def test_cli_greet():
    runner = CliRunner()
    result = runner.invoke(cli, ["greet"])
    assert result.exit_code == 0
    assert "Threat-Correlator CLI is working" in result.output

def test_fetch_static_malware_feed():
    iocs = fetch_static_malware_feed("sampledata/static_malware_feed.json")
    assert isinstance(iocs, list)

def test_fetch_virustotal_stub():
    iocs = fetch_virustotal()
    assert iocs == []

def test_generate_test_log(tmp_path):
    output_path = tmp_path / "test_logs.jsonl"
    generate_test_log(str(output_path), ioc_count=2, false_positive_count=1)
    assert output_path.exists()
    with open(output_path) as f:
        lines = f.readlines()
    assert len(lines) > 0
