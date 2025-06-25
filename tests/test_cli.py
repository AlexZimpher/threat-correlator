from click.testing import CliRunner
from threatcorrelator.cli import main

def test_cli_show_config():
    runner = CliRunner()
    result = runner.invoke(main, ['show-config'])
    assert result.exit_code == 0
    assert "abuseipdb" in result.output

def test_cli_fetch_help():
    runner = CliRunner()
    result = runner.invoke(main, ['fetch', '--help'])
    assert result.exit_code == 0
    assert "Usage" in result.output
