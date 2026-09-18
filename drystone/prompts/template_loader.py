"""
Template loader for structured audit prompts.

Loads XML templates and substitutes placeholders with runtime values.
Templates provide consistent structure for Claude prompts (Shannon pattern).
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Template directory
TEMPLATE_DIR = Path(__file__).parent / "templates"


def load_template(skill_name: str) -> str:
    """Load skill-specific or base template.

    Args:
        skill_name: Skill name (e.g., 'iam', 'network', 'exposure')

    Returns:
        Template content as string
    """
    # Try skill-specific template first
    skill_template = TEMPLATE_DIR / f"{skill_name.lower()}_audit.xml"
    if skill_template.exists():
        logger.debug(f"Loading {skill_name} template from {skill_template}")
        skill_text = skill_template.read_text()

        # Support a lightweight "extends" mechanism used by some templates.
        # If the skill template declares extends="base_audit.xml", we inject the
        # inner XML of the skill template into {SKILL_ADDENDUM} in base_audit.xml.
        if 'extends="base_audit.xml"' in skill_text:
            base_template = TEMPLATE_DIR / "base_audit.xml"
            if base_template.exists():
                base_text = base_template.read_text()

                # Strip XML prolog and outer <audit_task ...> wrapper from the skill template.
                cleaned = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", skill_text).strip()
                cleaned = re.sub(r"^\s*<audit_task[^>]*>", "", cleaned)
                cleaned = re.sub(r"</audit_task>\s*$", "", cleaned)
                addendum_inner = cleaned.strip()

                if "{SKILL_ADDENDUM}" in base_text:
                    return base_text.replace("{SKILL_ADDENDUM}", addendum_inner)

                return base_text + "\n\n" + addendum_inner

        return skill_text

    # Fallback to base template
    base_template = TEMPLATE_DIR / "base_audit.xml"
    if base_template.exists():
        logger.debug(f"Using base template for {skill_name}")
        return base_template.read_text()

    raise FileNotFoundError(f"No template found for skill: {skill_name}")


def render_template(template: str, context: Dict[str, Any]) -> str:
    """Render template by substituting placeholders.

    Substitution is single-pass: every `{PLACEHOLDER}` in the original
    template is matched against the original text only, and replacement
    values are never re-scanned for further placeholders. This matters
    because context values can contain evidence-controlled text -- a
    sequential `.replace()` loop (the previous implementation) mutates the
    same string on every iteration, so an *earlier*-inserted value whose
    text happens to look like a *later* key's placeholder (e.g. a resource
    tag literally containing `{CHECKLIST_JSON}`) would get that later
    substitution spliced into it too.

    Args:
        template: Template content with {PLACEHOLDER} markers
        context: Dictionary of placeholder values

    Returns:
        Rendered template with substitutions
    """
    if not context:
        return template

    placeholder_re = re.compile("|".join(re.escape(f"{{{key}}}") for key in context))
    return placeholder_re.sub(lambda m: str(context[m.group(0)[1:-1]]), template)


def get_audit_template(skill_name: str, context: Dict[str, Any]) -> str:
    """Load and render audit template for a skill.

    Args:
        skill_name: Skill name
        context: Context with placeholders (SKILL_NAME, EVIDENCE_JSON, etc.)

    Returns:
        Fully rendered template as string
    """
    template = load_template(skill_name)
    rendered = render_template(template, context)
    return rendered


def list_available_templates() -> Dict[str, str]:
    """List all available templates.

    Returns:
        Dict mapping skill names to template paths
    """
    templates = {}

    # Base template
    base = TEMPLATE_DIR / "base_audit.xml"
    if base.exists():
        templates["_base"] = str(base)

    # Skill-specific templates
    for template_file in TEMPLATE_DIR.glob("*_audit.xml"):
        if template_file.name != "base_audit.xml":
            skill = template_file.stem.replace("_audit", "")
            templates[skill] = str(template_file)

    return templates
