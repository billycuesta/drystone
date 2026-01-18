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


def display_config_summary(project_config: dict, ai_config: dict) -> None:
    """Display current configuration summary in a clear, formatted way.

    Args:
        project_config: Dict from run_project_menu()
        ai_config: Dict from run_ai_menu() or get_default_ai_config()
    """
    print("\n" + "━" * 60)
    print("📋 CURRENT CONFIGURATION")
    print("━" * 60)

    # Menu A: Project Scope
    print("\n📋 Project Scope:")
    print(f"   Client Name: {project_config['client_name']}")
    print(f"   AWS Region: {project_config['aws_region']}")

    # Mask credentials
    key_id = project_config['aws_access_key_id']
    masked_key = f"{key_id[:4]}...{key_id[-4:]}" if len(key_id) > 8 else "****"
    print(f"   AWS Access Key: {masked_key}")

    # Skills
    skills_display = ", ".join(project_config['skills']) if project_config['skills'] else "None"
    print(f"   Security Skills: {skills_display}")

    # Output formats
    formats_display = ", ".join(project_config['output_formats']) if project_config['output_formats'] else "None"
    print(f"   Output Formats: {formats_display}")

    # Menu B: AI Configuration
    print("\n🤖 AI Configuration:")
    print(f"   Provider: {ai_config['ai_provider']}")

    if ai_config['ai_api_key']:
        # Mask API key
        key = ai_config['ai_api_key']
        masked_api_key = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "****"
        print(f"   API Key: {masked_api_key}")
    else:
        print("   API Key: not required (using CLI)")

    print("\n" + "━" * 60 + "\n")


def run_project_menu(current_config: Optional[dict] = None) -> dict:
    """Run Menu A: Project & AWS Scope Configuration.

    Args:
        current_config: Optional dict with current values to pre-fill

    Returns:
        dict with: client_name, aws_access_key_id, aws_secret_access_key,
                   aws_region, skills, output_formats
    """
    print("\n" + "━" * 50)
    print("📋 MENU A: Review Scope")
    print("━" * 50 + "\n")

    # Use current values as defaults if provided
    defaults = current_config or {}

    # Step 1: Client/Project Name
    client_name = questionary.text(
        "Client or Project Name:",
        default=defaults.get("client_name", "MyOrg"),
        validate=lambda x: len(x) > 0 or "Name cannot be empty",
    ).ask()

    if client_name is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 2: AWS Access Key ID
    access_key_id = questionary.text(
        "AWS Access Key ID:",
        default=defaults.get("aws_access_key_id", ""),
        validate=lambda x: len(x) > 0 or "Access Key ID cannot be empty",
    ).ask()

    if access_key_id is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 3: AWS Secret Access Key (don't pre-fill for security)
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
        default=defaults.get("aws_region", "us-east-1"),
    ).ask()

    if aws_region is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 4.5: Validate AWS Credentials (ALWAYS when editing Menu A)
    try:
        validate_aws_creds(access_key_id, secret_access_key, aws_region)
    except AWSValidationError:
        raise KeyboardInterrupt("AWS credential validation failed")

    # Step 5: Skills to execute
    current_skills = defaults.get("skills", ["iam"])
    skills = questionary.checkbox(
        "Security Skills to Execute:",
        choices=[
            questionary.Choice(
                "IAM Security Audit", "iam",
                checked="iam" in current_skills
            ),
            questionary.Choice(
                "Internet Exposure Audit", "exposure",
                checked="exposure" in current_skills
            ),
            questionary.Choice(
                "Network Policies Audit", "network",
                checked="network" in current_skills
            ),
            questionary.Choice(
                "Vulnerability Scanning", "vulns",
                checked="vulns" in current_skills
            ),
        ],
        validate=lambda x: len(x) > 0 or "Select at least one skill",
    ).ask()

    if skills is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 6: Output formats
    current_formats = defaults.get("output_formats", ["markdown"])
    output_formats = questionary.checkbox(
        "Output Formats:",
        choices=[
            questionary.Choice(
                "Markdown", "markdown",
                checked="markdown" in current_formats
            ),
            questionary.Choice(
                "JSON", "json",
                checked="json" in current_formats
            ),
        ],
        validate=lambda x: len(x) > 0 or "Select at least one format",
    ).ask()

    if output_formats is None:
        raise KeyboardInterrupt("Wizard cancelled")

    return {
        "client_name": client_name,
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_access_key,
        "aws_region": aws_region,
        "skills": skills,
        "output_formats": output_formats,
    }


def run_ai_menu(current_config: Optional[dict] = None) -> dict:
    """Run Menu B: AI Configuration (optional).

    Args:
        current_config: Optional dict with current values to pre-fill

    Returns:
        dict with: ai_provider, ai_api_key
    """
    print("\n" + "━" * 50)
    print("🤖 MENU B: AI Configuration")
    print("━" * 50 + "\n")

    # Use current values as defaults if provided
    defaults = current_config or {}
    current_provider = defaults.get("ai_provider", "claude-cli")

    # Step 7: AI Provider for analysis
    ai_provider = questionary.select(
        "AI Provider for Security Analysis:",
        choices=[
            questionary.Choice(
                "Claude CLI (Free, Recommended)", "claude-cli",
                checked=(current_provider == "claude-cli")
            ),
            questionary.Choice(
                "Claude API Key", "claude-api",
                checked=(current_provider == "claude-api")
            ),
            questionary.Choice(
                "Google Gemini API", "gemini-api",
                checked=(current_provider == "gemini-api")
            ),
        ],
    ).ask()

    if ai_provider is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 8: API Key (if needed - don't pre-fill for security)
    ai_api_key = None
    if ai_provider in ["claude-api", "gemini-api"]:
        api_key_name = "Claude API" if ai_provider == "claude-api" else "Gemini API"
        ai_api_key = questionary.password(
            f"Enter your {api_key_name} key:",
            validate=lambda x: len(x) > 0 or "API key cannot be empty",
        ).ask()

        if ai_api_key is None:
            raise KeyboardInterrupt("Wizard cancelled")

    return {
        "ai_provider": ai_provider,
        "ai_api_key": ai_api_key,
    }


def get_default_ai_config() -> dict:
    """Get default AI configuration (Claude CLI, no API key).

    Returns:
        dict with default ai_provider and ai_api_key
    """
    return {
        "ai_provider": "claude-cli",
        "ai_api_key": None,
    }


def run_setup_wizard() -> WizardConfig:
    """Run interactive wizard with flexible menu navigation.

    User can choose to configure Menu A or Menu B first.
    Both menus can be edited multiple times before finishing.
    Menu A is required to continue.

    Returns:
        WizardConfig with user selections
    """
    print()  # Blank line

    # Initialize configs: Menu A is empty, Menu B has defaults
    project_config = None
    ai_config = get_default_ai_config()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # INTERACTIVE NAVIGATION LOOP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    while True:
        # Display current configuration (if Menu A is complete)
        if project_config:
            display_config_summary(project_config, ai_config)

        # Navigation menu
        choices = [
            questionary.Choice(
                "📋 Configure Menu A: Project Scope",
                value="edit_project"
            ),
            questionary.Choice(
                "🤖 Configure Menu B: AI Configuration",
                value="edit_ai"
            ),
        ]

        # Only show "Continue" if Menu A is configured
        if project_config:
            choices.append(
                questionary.Choice(
                    "✅ Continue with current configuration",
                    value="continue"
                )
            )

        action = questionary.select(
            "What would you like to do?" if project_config else "Configuration Setup",
            choices=choices,
        ).ask()

        if action is None:
            raise KeyboardInterrupt("Wizard cancelled")

        # Handle user choice
        if action == "edit_project":
            print()
            project_config = run_project_menu(current_config=project_config)
            print("\n✅ Menu A updated!")

        elif action == "edit_ai":
            print()
            ai_config = run_ai_menu(current_config=ai_config)
            print("\n✅ Menu B updated!")

        elif action == "continue":
            print("\n✅ Configuration finalized!\n")
            break

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # BUILD FINAL CONFIG
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    try:
        config = WizardConfig(
            **project_config,
            **ai_config,
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
