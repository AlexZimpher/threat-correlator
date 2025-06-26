from click.testing import CliRunner
from threatcorrelator.cli import cli as main


def test_cli_show_config():
    # Test that the CLI 'show-config' command runs and outputs config keys
    runner = CliRunner()
    result = runner.invoke(main, ["show-config"])
    assert result.exit_code == 0  # nosec
    assert "abuseipdb" in result.output  # nosec


def test_cli_fetch_help():
    # Test that the CLI 'fetch --help' command shows usage info
    runner = CliRunner()
    result = runner.invoke(main, ["fetch", "--help"])
    assert result.exit_code == 0  # nosec
    assert "Usage" in result.output  # nosec
