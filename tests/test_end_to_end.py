import os
import json
import yaml
import pytest

from pathlib import Path
from click.testing import CliRunner

# Import CLI and modules
from threatcorrelator.cli import cli
import threatcorrelator.fetch as fetch_module
import threatcorrelator.cli as cli_module
from threatcorrelator.storage import Base, get_engine, get_session
from threatcorrelator.correlate import correlate_logs


@pytest.fixture(autouse=True)
def use_temp_db(tmp_path, monkeypatch):
    """
    Override the SQLite database to use a temp file.
    Recreate tables fresh for each test.
    """
    db_file = tmp_path / "test_tc.db"
    # Ensure get_engine() uses this path:
    monkeypatch.setenv("TC_DB_PATH", f"sqlite:///{db_file}")

    # Create engine and initialize tables
    engine = get_engine()
    Base.metadata.create_all(engine)

    yield

    # Teardown
    engine.dispose()
    monkeypatch.delenv("TC_DB_PATH", raising=False)


@pytest.fixture(autouse=True)
def patch_fetch(monkeypatch):
    """
    Monkeypatch fetch functions so they return exactly one IOC.
    Also patch CLI’s direct references.
    """
    fixed_ioc = {
        "ip": "203.0.113.5",
        "confidence": 95,
        "country": "US",
        "last_seen": "2025-05-30T12:00:00Z",
        "usage": "SSH",
        "source": "AbuseIPDB",
    }

    def fake_fetch_abuseipdb(api_key):
        return [fixed_ioc]

    def fake_fetch_otx():
        return []

    # Patch in fetch module
    monkeypatch.setattr(fetch_module, "fetch_abuseipdb_blacklist", fake_fetch_abuseipdb)
    monkeypatch.setattr(fetch_module, "fetch_otx_feed", fake_fetch_otx)

    # Also patch the CLI’s imported references
    monkeypatch.setattr(cli_module, "fetch_abuseipdb_blacklist", fake_fetch_abuseipdb)
    monkeypatch.setattr(cli_module, "fetch_otx_feed", fake_fetch_otx)

    return fixed_ioc


def test_end_to_end(tmp_path, patch_fetch):
    runner = CliRunner()

    # 1) Write a minimal config.yaml
    config = {
        "abuseipdb": {"api_key": "DUMMY_KEY"},
        "correlation": {"frequency_threshold": 0, "max_age_days": 0},
    }
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    with open(cfg_dir / "config.yaml", "w") as f:
        yaml.dump(config, f)

    # 2) Set ABUSEIPDB_API_KEY to skip reading config.yaml inside get_abuseipdb_key()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "DUMMY_KEY")

    # 3) Redirect CLI’s CONFIG_PATH so it picks up our temp config
    cli_module.CONFIG_PATH = cfg_dir / "config.yaml"
    fetch_module.CONFIG_PATH = cfg_dir / "config.yaml"

    # 4) Run 'fetch' to insert the fixed IOC into the temp DB
    result = runner.invoke(cli, ["fetch"])
    assert result.exit_code == 0
    assert "Stored 1 new IOCs" in result.output

    # 5) Create a small NDJSON log containing the IOC’s IP
    log_path = tmp_path / "sample_log.txt"
    with open(log_path, "w") as logf:
        logf.write(json.dumps({"src_ip": patch_fetch["ip"]}) + "\n")
        logf.write(json.dumps({"src_ip": "198.51.100.7"}) + "\n")

    # 6) Call correlate_logs() directly and verify results
    results = correlate_logs(log_path)
    assert isinstance(results, list)
    assert len(results) == 1

    entry = results[0]
    assert entry["ip"] == patch_fetch["ip"]
    assert entry["confidence"] == patch_fetch["confidence"]
    assert entry["country"] == patch_fetch["country"]
    assert entry["usage"] == patch_fetch["usage"]
    assert entry["severity"] == "High"  # because 95 >= 90

    # Since usage "SSH" → T1110 in mitre_map
    from threatcorrelator.mitre_map import MITRE_MAPPING

    technique, _ = MITRE_MAPPING.get(patch_fetch["usage"], MITRE_MAPPING["__default__"])
    assert entry["attack_technique_id"] == technique

    # 7) Also test CLI 'correlate' command prints correct output
    cli_result = runner.invoke(cli, ["correlate", str(log_path)])
    assert cli_result.exit_code == 0
    assert "Matched 1 threats." in cli_result.output
    assert "- 1 High" in cli_result.output

    # Cleanup monkeypatch
    monkeypatch.undo()
