import pytest
from threatcorrelator.config_loader import load_config

def test_load_config_example():
    config = load_config("config/config.example.yaml")
    assert "abuseipdb" in config
    assert "otx" in config

# Optionally test missing/invalid config

def test_load_config_missing():
    with pytest.raises(FileNotFoundError):
        load_config("config/does_not_exist.yaml")
