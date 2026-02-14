"""Configuration management for Drystone."""

import json
from pathlib import Path
from typing import Optional

from drystone.models import WizardConfig

CONFIG_DIR = Path.home() / ".drystone"
LAST_RUN_FILE = CONFIG_DIR / "last-run.json"


def ensure_config_dir() -> None:
    """Ensure ~/.drystone directory exists."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def save_config(config: WizardConfig) -> Path:
    """Save configuration to ~/.drystone/last-run.json.

    Args:
        config: WizardConfig to save

    Returns:
        Path where config was saved
    """
    ensure_config_dir()

    with open(LAST_RUN_FILE, "w") as f:
        json.dump(config.dict_for_json(), f, indent=2)

    return LAST_RUN_FILE


def load_last_config() -> Optional[WizardConfig]:
    """Load last saved configuration.

    Returns:
        WizardConfig if exists, None otherwise
    """
    if not LAST_RUN_FILE.exists():
        return None

    try:
        with open(LAST_RUN_FILE, "r") as f:
            data = json.load(f)
            return WizardConfig(**data)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"⚠️  Could not load saved config: {e}")
        return None


def use_last_config() -> bool:
    """Check if user wants to use last saved config.

    Returns:
        True if user confirms, False otherwise
    """
    import questionary

    if not LAST_RUN_FILE.exists():
        return False

    reuse = questionary.confirm(
        "Use last saved configuration?",
        default=True,
    ).ask()

    return reuse if reuse is not None else False
