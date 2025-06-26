import importlib.util
from click.testing import CliRunner
from threatcorrelator import dashboard
from threatcorrelator.cli import cli
from threatcorrelator.fetch import fetch_static_malware_feed, fetch_virustotal
from threatcorrelator.generate_test_log import generate_test_log


def test_dashboard_import_runs():
    # Test that the dashboard module can be imported and main() runs without error
    assert importlib.util.find_spec("threatcorrelator.dashboard") is not None  # nosec
    dashboard.main()


def test_cli_greet():
    # Test that the CLI 'greet' command works and outputs the expected message
    runner = CliRunner()
    result = runner.invoke(cli, ["greet"])
    assert result.exit_code == 0  # nosec
    assert "Threat-Correlator CLI is working" in result.output  # nosec


def test_fetch_static_malware_feed():
    # Test that static malware feed loads and returns a list
    iocs = fetch_static_malware_feed("sampledata/static_malware_feed.json")
    assert isinstance(iocs, list)  # nosec


def test_fetch_virustotal_stub():
    # Test that the VirusTotal fetch stub returns an empty list
    iocs = fetch_virustotal()
    assert iocs == []  # nosec


def test_generate_test_log(tmp_path):
    # Test that a test log file is generated and contains lines
    output_path = tmp_path / "test_logs.jsonl"
    generate_test_log(str(output_path), ioc_count=2, false_positive_count=1)
    assert output_path.exists()  # nosec
    with open(output_path) as f:
        lines = f.readlines()
    assert len(lines) > 0  # nosec
