"""Branding and UI components for Drystone."""

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from drystone.models.config import WizardConfig


def _interpolate_color(position: float, start_rgb: tuple, end_rgb: tuple) -> str:
    """Interpolate between two RGB colors.

    Args:
        position: 0.0 to 1.0 position in gradient
        start_rgb: Starting color as (r, g, b)
        end_rgb: Ending color as (r, g, b)

    Returns:
        RGB color string for rich
    """
    r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * position)
    g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * position)
    b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * position)
    return f"rgb({r},{g},{b})"


def print_banner() -> None:
    """Print banner with decorative box (Shannon-style) with gradient colors (lilac to orange)."""
    console = Console()

    # Gradient colors: lilac (purple) → orange
    start_color = (180, 100, 220)  # Lilac/Purple
    end_color = (255, 165, 0)  # Orange

    # Border color (use the midpoint of gradient for consistent look)
    border_color = _interpolate_color(0.5, start_color, end_color)

    # DRYSTONE ASCII art (blocky/pixelated style)
    banner_text = """
 ██████╗ ██████╗ ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
 ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
 ██║  ██║██████╔╝ ╚████╔╝ ███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
 ██║  ██║██╔══██╗  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
 ██████╔╝██║  ██║   ██║   ███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
 ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝"""

    # Apply gradient to banner
    lines = banner_text.strip().split("\n")
    total_chars = sum(len(line) for line in lines)

    gradient_text = Text()
    char_count = 0

    for line in lines:
        for char in line:
            position = char_count / total_chars if total_chars > 0 else 0
            color = _interpolate_color(position, start_color, end_color)
            gradient_text.append(char, style=color)
            char_count += 1
        gradient_text.append("\n")

    # Build content for panel using Group for proper centering
    content = Group(
        gradient_text,
        "",
        Align.center(
            Text("AWS Security Audit powered by BillySlopes with AI", style=f"{border_color} bold")
        ),
        "",
        Align.center(Text("v1.0.0", style=f"{border_color}")),
        "",
        Align.center(Text("🔒 Automated AWS Security Assessment 🔒", style=f"{border_color} bold")),
    )

    # Create panel with gradient-colored border
    panel = Panel(content, border_style=border_color, padding=(1, 2), expand=False)

    console.print(Align.center(panel))
    console.print()  # Blank line


def print_summary(config: WizardConfig) -> None:
    """Print configuration summary in a nice format.

    Args:
        config: WizardConfig model with user selections
    """
    from rich.table import Table

    console = Console()

    # Create table
    table = Table(title="[cyan]Audit Configuration Summary[/cyan]", show_header=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    # Add rows
    table.add_row("Client/Project", f"[bold]{config.client_name}[/bold]")

    # Show AWS credential source
    if config.aws_access_key_id and config.aws_secret_access_key:
        # Direct credentials: mask them for display
        masked_access_key = f"{config.aws_access_key_id[:4]}...{config.aws_access_key_id[-4:]}"
        masked_secret = f"{'*' * min(len(config.aws_secret_access_key), 10)}"
        table.add_row("AWS Credentials", "[bold dim]Direct (masked)[/bold dim]")
        table.add_row("  Access Key", f"[bold dim]{masked_access_key}[/bold dim]")
        table.add_row("  Secret Key", f"[bold dim]{masked_secret}[/bold dim]")
    elif config.aws_credentials_file:
        # File-based credentials: show path
        table.add_row("AWS Credentials", "[bold dim]File[/bold dim]")
        table.add_row("  File Path", f"[bold dim]{config.aws_credentials_file}[/bold dim]")
    elif config.aws_profile:
        # Profile-based credentials: show profile name
        table.add_row("AWS Credentials", "[bold dim]Profile[/bold dim]")
        table.add_row("  Profile", f"[bold dim]{config.aws_profile}[/bold dim]")
    else:
        # Fallback: environment variables
        table.add_row("AWS Credentials", "[bold dim]Environment Variables[/bold dim]")

    table.add_row("AWS Region", f"[bold]{config.aws_region}[/bold]")
    table.add_row("Skills", f"[bold]{', '.join(config.skills)}[/bold]")
    table.add_row("Output Formats", f"[bold]{', '.join(config.output_formats)}[/bold]")
    table.add_row("Minimum Severity", f"[bold]{config.min_severity.capitalize()}[/bold]")

    console.print()
    console.print(table)
    console.print()
