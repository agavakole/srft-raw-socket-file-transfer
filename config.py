import json
import os
from types import SimpleNamespace


class ConfigError(Exception):
    pass


def _to_namespace(d):
    """Recursively convert dict to SimpleNamespace."""
    if isinstance(d, dict):
        return SimpleNamespace(**{k: _to_namespace(v) for k, v in d.items()})
    elif isinstance(d, list):
        return [_to_namespace(x) for x in d]
    else:
        return d


def load_config(path: str):
    if not os.path.exists(path):
        raise ConfigError(f"Config file not found: {path}")

    with open(path, "r") as f:
        data = json.load(f)

    # Validate required sections
    for section in ["network", "transfer", "timers"]:
        if section not in data:
            raise ConfigError(f"Missing required section: {section}")

    # Validate required network fields
    for field in ["client_ip", "server_ip", "client_port", "server_port"]:
        if field not in data["network"]:
            raise ConfigError(f"Missing network field: {field}")

    # Default values
    data.setdefault("security", {"enabled": False})
    data["transfer"].setdefault("chunk_size", 1024)
    data["transfer"].setdefault("send_window_packets", 1)
    data["timers"].setdefault("rto_ms", 2000)
    data["timers"].setdefault("ack_interval_ms", 50)

    return _to_namespace(data)