import json
import yaml
import pytest
from click.testing import CliRunner

# Import CLI and modules
from threatcorrelator.cli import cli
import threatcorrelator.fetch as fetch_module
import threatcorrelator.cli as cli_module
from threatcorrelator.storage import Base, get_engine
from threatcorrelator.correlate import correlate_logs


@pytest.fixture(autouse=True)
def use_temp_db(tmp_path, monkeypatch):
    # Use a temporary SQLite database for each test and clean up after
    db_file = tmp_path / "test_tc.db"
    monkeypatch.setenv("TC_DB_PATH", f"sqlite:///{db_file}")
    engine = get_engine()
    Base.metadata.create_all(engine)
    yield
    engine.dispose()
    monkeypatch.delenv("TC_DB_PATH", raising=False)


@pytest.fixture(autouse=True)
def patch_fetch(monkeypatch):
    # Patch fetch functions to always return a fixed IOC for testing
    fixed_ioc = {
        "indicator": "203.0.113.5",
        "confidence": 95,
        "country": "US",
        "last_seen": "2025-05-30T12:00:00Z",
        "usage": "SSH",
        "source": "AbuseIPDB",
        "type": "ip",
    }

    def fake_fetch_abuseipdb(api_key=None):
        return [fixed_ioc]

    def fake_fetch_otx():
        return []

    monkeypatch.setattr(
        fetch_module,
        "fetch_abuseipdb_blacklist",
        fake_fetch_abuseipdb,
    )
    monkeypatch.setattr(
        fetch_module,
        "fetch_otx_feed",
        fake_fetch_otx,
    )
    monkeypatch.setattr(
        cli_module,
        "fetch_abuseipdb_blacklist",
        fake_fetch_abuseipdb,
    )
    monkeypatch.setattr(
        cli_module,
        "fetch_otx_feed",
        fake_fetch_otx,
    )

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

    # 2) Use a file-based SQLite DB in tmp_path
    db_path = tmp_path / "test_tc.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setenv("TC_DB_PATH", db_url)

    # 3) Redirect CLI’s CONFIG_PATH so it picks up our temp config
    cli_module.CONFIG_PATH = cfg_dir / "config.yaml"
    fetch_module.CONFIG_PATH = cfg_dir / "config.yaml"

    # 4) Run 'fetch' to insert the fixed IOC into the temp DB
    result = runner.invoke(
        cli,
        ["fetch"],
        env={"TC_DB_PATH": db_url, "ABUSEIPDB_API_KEY": "DUMMY_KEY"},
    )
    assert result.exit_code == 0  # nosec
    assert "Stored 1 new IOCs" in result.output  # nosec

    # 5) Create a small NDJSON log containing the IOC’s IP
    log_path = tmp_path / "sample_log.json"
    with open(log_path, "w") as logf:
        logf.write(json.dumps({"src_ip": patch_fetch["indicator"]}) + "\n")
        logf.write(json.dumps({"src_ip": "198.51.100.7"}) + "\n")

    # 6) Call correlate_logs() directly and verify results
    from threatcorrelator.storage import get_session

    session = get_session(db_url)
    results = correlate_logs(log_path, session=session)
    assert isinstance(results, list)  # nosec
    assert len(results) == 1  # nosec

    entry = results[0]
    assert entry["indicator"] == patch_fetch["indicator"]  # nosec
    assert entry["confidence"] == patch_fetch["confidence"]  # nosec
    assert entry["country"] == patch_fetch["country"]  # nosec
    assert entry["usage"] == patch_fetch["usage"]  # nosec
    assert entry["severity"] == "High"  # nosec

    # Since usage "SSH" → T1110 in mitre_map
    from threatcorrelator.mitre_map import MITRE_MAPPING

    technique, _ = MITRE_MAPPING.get(patch_fetch["usage"], MITRE_MAPPING["__default__"])
    assert entry["attack_technique_id"] == technique  # nosec

    # 7) Also test CLI 'correlate' command prints correct output
    cli_result = runner.invoke(cli, ["correlate", str(log_path)])
    assert cli_result.exit_code == 0  # nosec
    assert "Matched 1 threats." in cli_result.output  # nosec
    assert "- 1 High" in cli_result.output  # nosec

    # Cleanup monkeypatch
    monkeypatch.undo()
