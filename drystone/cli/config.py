"""Configuration management for Drystone.

Each client gets its own saved config file under ~/.drystone/configs/, so a
`--non-interactive` run for one client can never silently pick up another
client's leftover settings (skills, report_type, output_formats, ...) -- the
failure mode of the single shared ~/.drystone/last-run.json this replaces.
`last-client.json` just remembers which client was most recently saved, so a
bare `--non-interactive` with no `--client` still means "re-run my last
audit."
"""

import json
import re
from pathlib import Path
from typing import Optional

from drystone.models import WizardConfig

CONFIG_DIR = Path.home() / ".drystone"
CONFIGS_DIR = CONFIG_DIR / "configs"
LAST_CLIENT_FILE = CONFIG_DIR / "last-client.json"


def ensure_config_dir() -> None:
    """Ensure ~/.drystone and its per-client configs directory exist."""
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)


def _slugify_client_name(client_name: str) -> str:
    """Turn a client name into a safe, unique-enough config filename stem."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", client_name.strip()).strip("_")
    return slug or "unnamed-client"


def _config_path_for_client(client_name: str) -> Path:
    return CONFIGS_DIR / f"{_slugify_client_name(client_name)}.json"


def save_config(config: WizardConfig) -> Path:
    """Save configuration to its own per-client file under ~/.drystone/configs/,
    and record it as the most recently used client.

    Args:
        config: WizardConfig to save

    Returns:
        Path where the config was saved
    """
    ensure_config_dir()

    config_path = _config_path_for_client(config.client_name)
    with open(config_path, "w") as f:
        json.dump(config.dict_for_json(), f, indent=2)

    with open(LAST_CLIENT_FILE, "w") as f:
        json.dump({"client_name": config.client_name}, f, indent=2)

    return config_path


def load_last_config(client: Optional[str] = None) -> Optional[WizardConfig]:
    """Load a saved configuration.

    Args:
        client: If given, load that specific client's saved config instead of
            whichever client ran most recently. Pass the same `--client`
            value the CLI was invoked with so CLI-arg runs never mix in a
            different client's saved skills/formats/provider settings.

    Returns:
        WizardConfig if found, None otherwise
    """
    target_client = client
    if not target_client:
        if not LAST_CLIENT_FILE.exists():
            return None
        try:
            with open(LAST_CLIENT_FILE, "r") as f:
                target_client = json.load(f).get("client_name")
        except (json.JSONDecodeError, ValueError, OSError):
            return None
        if not target_client:
            return None

    config_path = _config_path_for_client(target_client)
    if not config_path.exists():
        return None

    try:
        with open(config_path, "r") as f:
            data = json.load(f)
            return WizardConfig(**data)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"⚠️  Could not load saved config: {e}")
        return None
