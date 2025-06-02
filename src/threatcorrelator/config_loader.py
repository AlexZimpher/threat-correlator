import yaml
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "config" / "default.yaml"
USER_PATH = Path(__file__).resolve().parents[2] / "config" / "config.yaml"

def load_config():
    with open(DEFAULT_PATH, "r") as f:
        default_cfg = yaml.safe_load(f) or {}

    if USER_PATH.exists():
        with open(USER_PATH, "r") as f:
            user_cfg = yaml.safe_load(f) or {}
    else:
        user_cfg = {}

    # Merge user over default (shallow merge)
    merged = default_cfg.copy()
    for k, v in user_cfg.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k].update(v)
        else:
            merged[k] = v
    return merged

