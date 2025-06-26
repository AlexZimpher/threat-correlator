import yaml
from pathlib import Path


def deep_update(source, overrides):
    """Recursively update a dictionary with another dictionary's values."""
    for key, value in overrides.items():
        if isinstance(value, dict) and key in source and isinstance(source[key], dict):
            deep_update(source[key], value)
        else:
            source[key] = value
    return source


def load_config():
    """
    Load configuration from config.yaml, and override with config.local.yaml if present.
    Returns the merged configuration as a dictionary.
    """
    base_path = Path(__file__).resolve().parents[2] / "config"
    config_path = base_path / "config.yaml"
    local_path = base_path / "config.local.yaml"
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)
    if local_path.exists():
        with open(local_path, "r") as file:
            local_config = yaml.safe_load(file)
        if local_config:
            config = deep_update(config, local_config)
    return config
