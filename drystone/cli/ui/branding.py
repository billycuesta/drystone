"""Branding and UI components for Drystone."""

from rich.console import Console
from rich.text import Text


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
    """Print gemini-CLI style banner with gradient colors."""
    console = Console()

    # DRYSTONE ASCII art (blocky/pixelated style)
    banner_text = """
████████╗   ██╗   ██╗███████╗████████╗ ██████╗ ███╗   ██╗███████╗
██╔═════╝   ██║   ██║██╔════╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝
██║  ███╗   ██║   ██║███████╗   ██║   ██║   ██║██╔██╗ ██║█████╗
██║   ██║   ██║   ██║╚════██║   ██║   ██║   ██║██║╚██╗██║██╔══╝
██╔═══██║   ╚██████╔╝███████║   ██║   ╚██████╔╝██║ ╚████║███████╗
╚═╝   ╚═╝    ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    """

    # Gradient colors: cyan → blue → purple → pink
    start_color = (0, 255, 255)      # Cyan
    end_color = (255, 100, 150)      # Pink

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

    console.print(gradient_text)

    # Subtitle
    subtitle = "AWS Security Audit CLI powered by Claude"
    separator = "═" * len(subtitle)

    subtitle_text = Text()
    subtitle_text.append(subtitle, style="cyan dim")
    subtitle_text.append("\n")
    subtitle_text.append(separator, style="cyan dim")

    console.print(subtitle_text, justify="center")
    console.print()  # Blank line


def print_summary(config: "WizardConfig") -> None:
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
    table.add_row("AWS Profile", f"[bold]{config.aws_profile}[/bold]")
    table.add_row("AWS Region", f"[bold]{config.aws_region}[/bold]")
    table.add_row("Skills", f"[bold]{', '.join(config.skills)}[/bold]")
    table.add_row("Output Formats", f"[bold]{', '.join(config.output_formats)}[/bold]")

    console.print()
    console.print(table)
    console.print()
