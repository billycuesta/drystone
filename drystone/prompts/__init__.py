"""Structured prompt templates for AWS security audits."""

from .template_loader import (
    load_template,
    render_template,
    get_audit_template,
    list_available_templates,
)

__all__ = [
    "load_template",
    "render_template",
    "get_audit_template",
    "list_available_templates",
]
