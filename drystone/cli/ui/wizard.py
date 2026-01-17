"""Interactive wizard for Drystone setup."""

from typing import List

import questionary

from drystone.models import WizardConfig


def run_setup_wizard() -> WizardConfig:
    """Run interactive 5-step wizard for audit configuration.

    Returns:
        WizardConfig with user selections
    """
    print()  # Blank line

    # Step 1: Client/Project Name
    client_name = questionary.text(
        "📋 Client or Project Name:",
        default="MyAWS",
        validate=lambda x: len(x) > 0 or "Name cannot be empty",
    ).ask()

    if client_name is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 2: AWS Profile
    aws_profile = questionary.text(
        "🔐 AWS Profile:",
        default="default",
        validate=lambda x: len(x) > 0 or "Profile cannot be empty",
    ).ask()

    if aws_profile is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 3: AWS Region
    region_choices = [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "eu-central-1",
        "ap-southeast-1",
        "ap-northeast-1",
    ]

    aws_region = questionary.select(
        "🌍 AWS Region:",
        choices=region_choices,
        default="us-east-1",
    ).ask()

    if aws_region is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 4: Skills to execute
    skills = questionary.checkbox(
        "🎯 Security Skills to Execute:",
        choices=[
            questionary.Choice("IAM Security Audit", "iam", checked=True),
            questionary.Choice("Internet Exposure Audit", "exposure"),
            questionary.Choice("Network Policies Audit", "network"),
            questionary.Choice("Vulnerability Scanning", "vulns"),
        ],
        validate=lambda x: len(x) > 0 or "Select at least one skill",
    ).ask()

    if skills is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 5: Output formats
    output_formats = questionary.checkbox(
        "📊 Output Formats:",
        choices=[
            questionary.Choice("Markdown", "markdown", checked=True),
            questionary.Choice("HTML", "html"),
            questionary.Choice("JSON", "json"),
        ],
        validate=lambda x: len(x) > 0 or "Select at least one format",
    ).ask()

    if output_formats is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Create and validate config
    try:
        config = WizardConfig(
            client_name=client_name,
            aws_profile=aws_profile,
            aws_region=aws_region,
            skills=skills,
            output_formats=output_formats,
        )
        return config
    except ValueError as e:
        print(f"❌ Configuration validation failed: {e}")
        raise


def confirm_execution(config: WizardConfig) -> bool:
    """Confirm before starting audit execution.

    Args:
        config: Configuration to confirm

    Returns:
        True if user confirmed, False otherwise
    """
    confirm = questionary.confirm(
        "✅ Start audit with this configuration?",
        default=True,
        auto_enter=False,
    ).ask()

    return confirm if confirm is not None else False
