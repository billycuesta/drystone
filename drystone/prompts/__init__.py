"""Structured prompt templates for AWS security audits."""

from .template_loader import (
    get_audit_template,
    list_available_templates,
    load_template,
    render_template,
)

__all__ = [
    "load_template",
    "render_template",
    "get_audit_template",
    "list_available_templates",
]
