"""Interactive wizard for Drystone setup."""

import json
from pathlib import Path
from typing import Optional

import questionary

from drystone.cloud.aws import validate_aws_credentials
from drystone.models import WizardConfig


def validate_aws_creds(
    access_key_id: str,
    secret_access_key: str,
    session_token: Optional[str] = None,
    region_name: str = "us-east-1",
) -> bool:
    """Validate AWS credentials non-interactively.

    Args:
        access_key_id: AWS Access Key ID
        secret_access_key: AWS Secret Access Key
        session_token: Optional AWS Session Token for temporary credentials
        region_name: AWS region (default: us-east-1)

    Returns:
        True if credentials are valid, False otherwise.

    Raises:
        ValueError: If credentials are empty or invalid format
    """
    if not access_key_id or not secret_access_key:
        raise ValueError("Access Key ID and Secret Access Key cannot be empty")

    print("\nValidating AWS credentials...")
    is_valid, message, _ = validate_aws_credentials(
        access_key_id, secret_access_key, region_name, session_token
    )
    print(message)
    print()  # Blank line
    return is_valid


def validate_credentials_file(file_path: str) -> bool:
    """Validate that a credentials JSON file exists and is readable.

    Args:
        file_path: Path to credentials file

    Returns:
        True if file exists and is readable, False otherwise
    """
    expanded_path = Path(file_path).expanduser()
    if not expanded_path.exists():
        print(f"❌ Credential file not found: {expanded_path}")
        return False
    if not expanded_path.is_file():
        print(f"❌ Path is not a file: {expanded_path}")
        return False
    try:
        with open(expanded_path) as f:
            data = json.load(f)
        if not data.get("aws_access_key_id") or not data.get("aws_secret_access_key"):
            print("❌ Credential file missing 'aws_access_key_id' or 'aws_secret_access_key'")
            return False
        print(f"✅ Credential file loaded: {expanded_path}")
        return True
    except json.JSONDecodeError:
        print(f"❌ Credential file is not valid JSON: {expanded_path}")
        return False
    except Exception as e:
        print(f"❌ Error reading credential file: {e}")
        return False


def validate_aws_profile(profile_name: str) -> bool:
    """Validate that an AWS profile exists in ~/.aws/credentials.

    Args:
        profile_name: AWS profile name

    Returns:
        True if profile exists, False otherwise
    """
    try:
        import boto3

        session = boto3.Session(profile_name=profile_name)
        creds = session.get_credentials()
        if not creds:
            print(f"❌ No credentials found for profile: {profile_name}")
            return False
        print(f"✅ AWS profile found: {profile_name}")
        return True
    except Exception as e:
        print(f"❌ Error loading AWS profile '{profile_name}': {e}")
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

    # Display AWS credential source
    if project_config.get("aws_credentials_file"):
        print(f"   AWS Credentials: File ({project_config['aws_credentials_file']})")
    elif project_config.get("aws_profile"):
        print(f"   AWS Credentials: Profile ({project_config['aws_profile']})")
    elif project_config.get("aws_access_key_id"):
        key_id = project_config["aws_access_key_id"]
        masked_key = f"{key_id[:4]}...{key_id[-4:]}" if len(key_id) > 8 else "****"
        print(f"   AWS Access Key: {masked_key}")
        if project_config.get("aws_session_token"):
            print("   AWS Session Token: ✅ Configured")
    else:
        print("   AWS Credentials: Environment Variables")

    # Skills
    skills_display = ", ".join(project_config["skills"]) if project_config["skills"] else "None"
    print(f"   Security Skills: {skills_display}")

    # Output formats
    formats_display = (
        ", ".join(project_config["output_formats"]) if project_config["output_formats"] else "None"
    )
    print(f"   Output Formats: {formats_display}")

    # Add report type
    report_type_display = {
        "general": "📊 General Security Report",
        "pci-dss": "🔐 PCI DSS Compliance Report",
        "pentest": "🔬 Pentest Technical Report",
    }
    print(
        f"   Report Type: {report_type_display.get(project_config.get('report_type', 'general'))}"
    )

    # Menu B: AI Configuration
    print("\n🤖 AI Configuration:")
    print(f"   Provider: {ai_config['ai_provider']}")

    if ai_config["ai_provider"] == "bedrock":
        print("   Bedrock Region: eu-west-1")

        if ai_config.get("bedrock_use_same_credentials"):
            print("   Bedrock Credentials: Same as AWS Audit")
        elif ai_config.get("bedrock_credentials_file"):
            print(f"   Bedrock Credentials: File ({ai_config['bedrock_credentials_file']})")
        elif ai_config.get("bedrock_profile"):
            print(f"   Bedrock Credentials: Profile ({ai_config['bedrock_profile']})")
        elif ai_config.get("bedrock_access_key_id"):
            key_id = ai_config["bedrock_access_key_id"]
            masked_bedrock_key = f"{key_id[:4]}...{key_id[-4:]}" if len(key_id) > 8 else "****"
            print(f"   Bedrock Access Key: {masked_bedrock_key}")
            if ai_config.get("bedrock_session_token"):
                print("   Bedrock Session Token: ✅ Configured")
        else:
            print("   Bedrock Credentials: Environment Variables")

    if ai_config["ai_api_key"]:
        # Mask API key
        key = ai_config["ai_api_key"]
        masked_api_key = f"{key[:4]}...{key[-4:]}" if len(key) > 8 else "****"
        print(f"   API Key: {masked_api_key}")
    else:
        if ai_config["ai_provider"] not in ["bedrock", "claude-cli"]:
            print("   API Key: not required")

    print("\n" + "━" * 60 + "\n")


def run_project_menu(current_config: Optional[dict] = None) -> dict:
    """Run Menu A: Project & AWS Scope Configuration.

    Args:
        current_config: Optional dict with current values to pre-fill

    Returns:
        dict with: client_name, aws_region, skills, output_formats, and credential info
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

    # Initialize credential dict
    creds_config = {
        "aws_access_key_id": None,
        "aws_secret_access_key": None,
        "aws_session_token": None,
        "aws_credentials_file": None,
        "aws_profile": None,
    }

    # Step 2: AWS Credentials
    cred_choice = questionary.select(
        "How to provide AWS credentials?",
        choices=[
            questionary.Choice("Enter manually", "manual"),
            questionary.Choice("Read from JSON file", "file"),
            questionary.Choice("Use AWS profile (~/.aws/credentials)", "profile"),
            questionary.Choice("Use environment variables", "env"),
        ],
        default="manual",
    ).ask()
    if cred_choice is None:
        raise KeyboardInterrupt("Wizard cancelled")

    if cred_choice == "manual":
        creds_config["aws_access_key_id"] = questionary.text(
            "AWS Access Key ID:",
            default=defaults.get("aws_access_key_id", ""),
            validate=lambda x: len(x) > 0 or "Access Key ID cannot be empty",
        ).ask()
        if creds_config["aws_access_key_id"] is None:
            raise KeyboardInterrupt("Wizard cancelled")

        creds_config["aws_secret_access_key"] = questionary.password(
            "AWS Secret Access Key:",
            validate=lambda x: len(x) > 0 or "Secret Access Key cannot be empty",
        ).ask()
        if creds_config["aws_secret_access_key"] is None:
            raise KeyboardInterrupt("Wizard cancelled")

        creds_config["aws_session_token"] = questionary.password(
            "AWS Session Token (optional, press Enter to skip):",
            default="",
        ).ask()
        if creds_config["aws_session_token"] is None:
            raise KeyboardInterrupt("Wizard cancelled")
        if not creds_config["aws_session_token"].strip():
            creds_config["aws_session_token"] = None

    elif cred_choice == "file":
        # Validate file repeatedly until valid or cancelled
        while True:
            creds_config["aws_credentials_file"] = questionary.text(
                "Path to credentials JSON file:",
                default=defaults.get("aws_credentials_file", "~/.aws/drystone-creds.json"),
                validate=lambda x: len(x) > 0 or "Path cannot be empty",
            ).ask()
            if creds_config["aws_credentials_file"] is None:
                raise KeyboardInterrupt("Wizard cancelled")

            # Validate file exists and is readable
            if validate_credentials_file(creds_config["aws_credentials_file"]):
                break
            else:
                print("Please provide a valid path to a credentials JSON file.\n")

    elif cred_choice == "profile":
        # Validate profile repeatedly until valid or cancelled
        while True:
            creds_config["aws_profile"] = questionary.text(
                "AWS profile name:",
                default=defaults.get("aws_profile", "default"),
                validate=lambda x: len(x) > 0 or "Profile name cannot be empty",
            ).ask()
            if creds_config["aws_profile"] is None:
                raise KeyboardInterrupt("Wizard cancelled")

            # Validate profile exists in ~/.aws/credentials
            if validate_aws_profile(creds_config["aws_profile"]):
                break
            else:
                print("Please provide a valid AWS profile name.\n")

    elif cred_choice == "env":
        # Nothing to ask, will be loaded at runtime
        print("   INFO: Credentials will be loaded from environment variables (AWS_...).")

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

    # Note: AWS credential validation happens later in run_setup_wizard() after all config is collected
    # This allows validation of file/profile sources which need the full config context

    # Step 5: Skills to execute
    current_skills = defaults.get("skills", ["iam"])
    skills = questionary.checkbox(
        "Security Skills to Execute:",
        choices=[
            questionary.Choice("IAM Security Audit", "iam", checked="iam" in current_skills),
            questionary.Choice(
                "Internet Exposure Audit", "exposure", checked="exposure" in current_skills
            ),
            questionary.Choice(
                "Network Policies Audit", "network", checked="network" in current_skills
            ),
            questionary.Choice(
                "Vulnerability Scanning", "vulns", checked="vulns" in current_skills
            ),
            questionary.Choice(
                "Alerting & Monitoring Audit", "alerting", checked="alerting" in current_skills
            ),
            questionary.Choice(
                "Account Hardening Audit", "hardening", checked="hardening" in current_skills
            ),
            questionary.Choice(
                "ECR Container Registry Audit", "ecr", checked="ecr" in current_skills
            ),
            questionary.Choice(
                "Secrets Manager Security Audit",
                "secretsmanager",
                checked="secretsmanager" in current_skills,
            ),
            questionary.Choice("WAF Security Audit", "waf", checked="waf" in current_skills),
            questionary.Choice("KMS Key Management Audit", "kms", checked="kms" in current_skills),
            questionary.Choice(
                "Messaging (SQS/SNS) Audit", "messaging", checked="messaging" in current_skills
            ),
            questionary.Choice("CI/CD (CodeBuild) Audit", "cicd", checked="cicd" in current_skills),
            questionary.Choice(
                "Compute (ECS/EKS) Audit", "compute", checked="compute" in current_skills
            ),
            # Subtle separator: pentest preset is intentionally isolated (complex mode).
            questionary.Separator("────────────"),
            questionary.Choice(
                "Internal Pentest",
                "pentest",
                checked="pentest" in current_skills,
            ),
        ],
        validate=lambda x: (
            (len(x) > 0 or "Select at least one skill")
            if ("pentest" not in x or len(x) == 1)
            else "Pentest preset cannot be combined with other skills"
        ),
    ).ask()
    if skills is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 6: Output formats
    current_formats = defaults.get("output_formats", ["markdown"])
    output_formats = questionary.checkbox(
        "Output Formats:",
        choices=[
            questionary.Choice("Markdown", "markdown", checked="markdown" in current_formats),
            questionary.Choice("JSON", "json", checked="json" in current_formats),
            questionary.Choice("PDF", "pdf", checked="pdf" in current_formats),
        ],
        validate=lambda x: len(x) > 0 or "Select at least one format",
    ).ask()
    if output_formats is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Step 6.5: Report Type
    current_report_type = defaults.get("report_type", "general")

    # If the user selected the pentest preset, enforce core skills + report type.
    if "pentest" in skills:
        skills = ["iam", "exposure", "network", "vulns"]
        report_type = "pentest"
    else:
        report_type = None

    if report_type is None:
        report_type = questionary.select(
            "Report Type:",
            choices=[
                questionary.Choice(
                    "📊 General Security Report - Comprehensive findings with remediation guide",
                    "general",
                    checked=current_report_type == "general",
                ),
                questionary.Choice(
                    "🔐 PCI DSS Compliance Report - Control-based compliance table",
                    "pci-dss",
                    checked=current_report_type == "pci-dss",
                ),
            ],
            instruction="(Select report focus and structure)",
        ).ask()
        if report_type is None:
            raise KeyboardInterrupt("Wizard cancelled")

    # Combine all results
    project_config = {
        "client_name": client_name,
        "aws_region": aws_region,
        "skills": skills,
        "output_formats": output_formats,
        "report_type": report_type,
    }
    project_config.update(creds_config)

    return project_config


def run_ai_menu(current_config: Optional[dict] = None) -> dict:
    """Run Menu B: AI Configuration (optional).

    Args:
        current_config: Optional dict with current values to pre-fill

    Returns:
        dict with: ai_provider, ai_api_key, and bedrock credential info
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
                "Claude CLI (Free, Recommended)",
                "claude-cli",
                checked=(current_provider == "claude-cli"),
            ),
            questionary.Choice(
                "Claude API Key", "claude-api", checked=(current_provider == "claude-api")
            ),
        ],
    ).ask()

    if ai_provider is None:
        raise KeyboardInterrupt("Wizard cancelled")

    # Initialize result dict
    result = {
        "ai_provider": ai_provider,
        "ai_api_key": None,
    }

    if ai_provider == "claude-api":
        result["ai_api_key"] = questionary.password(
            "Enter your Claude API key:",
            validate=lambda x: len(x) > 0 or "API key cannot be empty",
        ).ask()

        if result["ai_api_key"] is None:
            raise KeyboardInterrupt("Wizard cancelled")

    return result


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
    project_config: Optional[dict] = None
    ai_config = get_default_ai_config()
    last_validation_status = {"aws": False, "bedrock": False}

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # INTERACTIVE NAVIGATION LOOP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    while True:
        # Display current configuration (if Menu A is complete)
        if project_config:
            display_config_summary(project_config, ai_config)

        # Navigation menu
        choices = [
            questionary.Choice("📋 Configure Menu A: Project Scope", value="edit_project"),
            questionary.Choice("🤖 Configure Menu B: AI Configuration", value="edit_ai"),
        ]

        # Only show "Continue" if Menu A is configured and validated
        if project_config and last_validation_status["aws"]:
            # Also check bedrock validation if required
            provider = ai_config.get("ai_provider")
            if provider != "bedrock" or (
                provider == "bedrock" and last_validation_status["bedrock"]
            ):
                choices.append(
                    questionary.Choice("✅ Continue with current configuration", value="continue")
                )

        action = questionary.select(
            "What would you like to do?" if project_config else "Configuration Setup",
            choices=choices,
        ).ask()

        if action is None:
            raise KeyboardInterrupt("Wizard cancelled")

        # Handle user choice
        if action == "edit_project":
            project_config = run_project_menu(current_config=project_config)
            print("\n✅ Menu A updated!")
            last_validation_status["aws"] = False  # Force re-validation

        elif action == "edit_ai":
            ai_config = run_ai_menu(current_config=ai_config)
            print("\n✅ Menu B updated!")
            last_validation_status["bedrock"] = False  # Force re-validation

        elif action == "continue":
            print("\n✅ Configuration finalized!\n")
            break

        # --- Validation Step ---
        if project_config:
            try:
                # Create a temporary config object to use validation logic
                temp_config = WizardConfig(**project_config, **ai_config)

                # 1. Validate AWS Credentials if not already done
                if not last_validation_status["aws"]:
                    try:
                        aws_creds = temp_config.get_aws_credentials()
                        # aws_creds is (access_key_id, secret_access_key, session_token)
                        is_valid = validate_aws_creds(
                            aws_creds[0],
                            aws_creds[1],
                            aws_creds[2],
                            region_name=temp_config.aws_region,
                        )
                        if not is_valid:
                            print("🚨 AWS credential validation failed. Please edit Menu A.")
                        last_validation_status["aws"] = is_valid
                    except (ValueError, FileNotFoundError) as e:
                        print(f"🚨 Error getting AWS credentials: {e}")
                        last_validation_status["aws"] = False

                # 2. Validate Bedrock Credentials if needed and AWS is valid
                if (
                    last_validation_status["aws"]
                    and temp_config.ai_provider == "bedrock"
                    and not last_validation_status["bedrock"]
                ):
                    try:
                        bedrock_creds = temp_config.get_bedrock_credentials()
                        # bedrock_creds is (access_key_id, secret_access_key, session_token)
                        is_valid = validate_aws_creds(
                            bedrock_creds[0],
                            bedrock_creds[1],
                            bedrock_creds[2],
                            region_name=temp_config.aws_region,
                        )
                        if not is_valid:
                            print("🚨 Bedrock credential validation failed. Please edit Menu B.")
                        last_validation_status["bedrock"] = is_valid
                    except (ValueError, FileNotFoundError) as e:
                        print(f"🚨 Error getting Bedrock credentials: {e}")
                        last_validation_status["bedrock"] = False

            except Exception as e:
                print(f"An unexpected error occurred during validation: {e}")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # BUILD FINAL CONFIG
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    try:
        # Verify required keys are present and not None
        if not project_config:
            raise ValueError("Project configuration is missing (Menu A not configured)")

        if not project_config.get("client_name"):
            raise ValueError("Client name is required")

        # Verify credential source is configured
        has_direct_creds = project_config.get("aws_access_key_id") and project_config.get(
            "aws_secret_access_key"
        )
        has_file = project_config.get("aws_credentials_file")
        has_profile = project_config.get("aws_profile")

        if not (has_direct_creds or has_file or has_profile):
            raise ValueError("No AWS credentials configured (expected direct, file, or profile)")

        config = WizardConfig(
            **project_config,
            **ai_config,
        )
        return config
    except (ValueError, TypeError) as e:
        print(f"\n❌ Configuration validation failed: {e}")
        import traceback

        traceback.print_exc()
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
