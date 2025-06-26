from threatcorrelator.config_loader import load_config
import pytest


def test_load_config():
    # Test loading a valid config file returns expected keys
    config = load_config("config/config.yaml")
    assert "abuseipdb" in config  # nosec
    assert "otx" in config  # nosec


def test_load_config_missing():
    # Test loading a missing config file raises FileNotFoundError
    with pytest.raises(FileNotFoundError):
        load_config("config/does_not_exist.yaml")
