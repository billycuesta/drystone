"""Interactive wizard for Drystone setup."""

from typing import List, Optional

import questionary

from drystone.cloud.aws import validate_aws_credentials
from drystone.models import WizardConfig


def validate_aws_creds(access_key_id: str, secret_access_key: str, region_name: str, max_retries: int = 3) -> bool:
    """Validate AWS credentials.

    Shows validation result and allows user to retry or cancel.

    Args:
        access_key_id: AWS Access Key ID
        secret_access_key: AWS Secret Access Key
        region_name: AWS region
        max_retries: Maximum number of retry attempts

    Returns:
        True if credentials are valid, False if user cancelled

    Raises:
        KeyboardInterrupt: If user cancels
    """
    retries = 0

    while retries < max_retries:
        print("\nValidating AWS credentials...")

        is_valid, message, account_id = validate_aws_credentials(access_key_id, secret_access_key, region_name)

        print(message)

        if is_valid:
            print()  # Blank line
            return True

        retries += 1

        if retries < max_retries:
            retry = questionary.confirm(
                "Retry with different credentials?",
                default=True,
                auto_enter=False,
            ).ask()

            if not retry:
                raise KeyboardInterrupt("Credential validation cancelled")

            # Ask for new credentials
            access_key_id = questionary.text(
                "AWS Access Key ID:",
                validate=lambda x: len(x) > 0 or "Access Key ID cannot be empty",
            ).ask()

            if access_key_id is None:
                raise KeyboardInterrupt("Wizard cancelled")

            secret_access_key = questionary.password(
                "AWS Secret Access Key:",
                validate=lambda x: len(x) > 0 or "Secret Access Key cannot be empty",
            ).ask()

            if secret_access_key is None:
                raise KeyboardInterrupt("Wizard cancelled")

            print()  # Blank line
        else:
            print("Max retry attempts reached")
            raise AWSValidationError("Failed to validate AWS credentials")

    return False


class AWSValidationError(Exception):
    """Raised when AWS validation fails."""

    pass


def run_setup_wizard() -> WizardConfig:
    """Run interactive 6-step wizard for audit configuration.

    Returns:
        WizardConfig with user selections
    """
    print()  # Blank line

    # Step 1: Client/Project Name
    client_name = questionary.text(
        "Client or Project Name:",
        default="MyOrg",
        validate=lambda x: len(x) > 0 or "Name cannot be empty",
    ).ask()

    if client_name is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 2: AWS Access Key ID
    access_key_id = questionary.text(
        "AWS Access Key ID:",
        validate=lambda x: len(x) > 0 or "Access Key ID cannot be empty",
    ).ask()

    if access_key_id is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 3: AWS Secret Access Key
    secret_access_key = questionary.password(
        "AWS Secret Access Key:",
        validate=lambda x: len(x) > 0 or "Secret Access Key cannot be empty",
    ).ask()

    if secret_access_key is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 4: AWS Region
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
        "AWS Region:",
        choices=region_choices,
        default="us-east-1",
    ).ask()

    if aws_region is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 4.5: Validate AWS Credentials
    try:
        validate_aws_creds(access_key_id, secret_access_key, aws_region)
    except AWSValidationError:
        raise KeyboardInterrupt("AWS credential validation failed")

    # Step 5: Skills to execute
    skills = questionary.checkbox(
        "Security Skills to Execute:",
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

    # Step 6: Output formats
    output_formats = questionary.checkbox(
        "Output Formats:",
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
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_region=aws_region,
            skills=skills,
            output_formats=output_formats,
        )
        return config
    except ValueError as e:
        print(f"Configuration validation failed: {e}")
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
