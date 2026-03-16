"""Client context model for enriching reports with business context."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel


class ClientContext(BaseModel):
    """Client context parsed from a client-context.md file.

    The file uses YAML frontmatter (--- delimited) for structured data
    and markdown body sections (## Header) for free-form context.
    """

    organization: str = ""
    industry: str = ""
    project: str = ""
    code: str = ""
    version: str = "1.0"
    assessment_dates: Optional[Dict[str, str]] = None
    report_date: Optional[str] = None
    conditions: List[str] = []
    exclusions: List[str] = []
    scope_notes: str = ""
    business_context: str = ""  # from ## Business Context
    compliance_reqs: str = ""  # from ## Compliance Requirements

    @classmethod
    def from_file(cls, file_path: Path) -> "ClientContext":
        """Parse a client-context.md file into a ClientContext model.

        Args:
            file_path: Path to the client-context.md file

        Returns:
            Parsed ClientContext instance

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file cannot be parsed
        """
        expanded = Path(file_path).expanduser()
        if not expanded.exists():
            raise FileNotFoundError(f"Client context file not found: {expanded}")

        content = expanded.read_text(encoding="utf-8")
        return cls._parse(content)

    @classmethod
    def _parse(cls, content: str) -> "ClientContext":
        """Parse client context from file content."""
        frontmatter: Dict = {}
        body = content

        # Extract YAML frontmatter
        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)", content, re.DOTALL)
        if fm_match:
            fm_text = fm_match.group(1)
            body = fm_match.group(2)
            frontmatter = cls._parse_yaml_simple(fm_text)

        # Extract body sections
        body_sections = cls._parse_body_sections(body)

        return cls(
            organization=str(frontmatter.get("organization", "")),
            industry=str(frontmatter.get("industry", "")),
            project=str(frontmatter.get("project", "")),
            code=str(frontmatter.get("code", "")),
            version=str(frontmatter.get("version", "1.0")),
            assessment_dates=frontmatter.get("assessment_dates"),
            report_date=frontmatter.get("report_date"),
            conditions=frontmatter.get("conditions", []),
            exclusions=frontmatter.get("exclusions", []),
            scope_notes=str(frontmatter.get("scope_notes", "")),
            business_context=body_sections.get("business context", ""),
            compliance_reqs=body_sections.get("compliance requirements", ""),
        )

    @classmethod
    def _parse_yaml_simple(cls, text: str) -> Dict:
        """Simple YAML-like parser for frontmatter (no external dependency).

        Supports: scalars, lists (- item), nested dicts (one level).
        """
        result: Dict = {}
        lines = text.split("\n")
        i = 0

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            i += 1

            if not stripped or stripped.startswith("#"):
                continue

            # Top-level key: value (not indented)
            if not line[0].isspace() and ":" in stripped:
                k, _, v = stripped.partition(":")
                k = k.strip()
                v = v.strip()

                # Multiline scalar (|)
                if v == "|":
                    multiline_parts: List[str] = []
                    while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                        if lines[i].strip():
                            multiline_parts.append(lines[i].strip())
                        i += 1
                    result[k] = "\n".join(multiline_parts)
                    continue

                # Empty value → peek ahead to determine list or dict
                if not v:
                    # Look at next lines to determine type
                    if i < len(lines) and lines[i].strip().startswith("- "):
                        # It's a list
                        items: List[str] = []
                        while i < len(lines) and lines[i].strip().startswith("- "):
                            item = lines[i].strip()[2:].strip().strip('"').strip("'")
                            items.append(item)
                            i += 1
                        result[k] = items
                    elif i < len(lines) and lines[i].startswith("  ") and ":" in lines[i]:
                        # It's a dict
                        d: Dict[str, str] = {}
                        while i < len(lines) and lines[i].startswith("  ") and ":" in lines[i]:
                            dk, _, dv = lines[i].strip().partition(":")
                            d[dk.strip()] = dv.strip().strip('"').strip("'")
                            i += 1
                        result[k] = d
                    else:
                        result[k] = ""
                    continue

                # Scalar value
                v = v.strip('"').strip("'")
                result[k] = v
                continue

        return result

    @classmethod
    def _parse_body_sections(cls, body: str) -> Dict[str, str]:
        """Parse ## Header sections from markdown body."""
        sections: Dict[str, str] = {}
        current_header = ""
        current_content: List[str] = []

        for line in body.split("\n"):
            if line.startswith("## "):
                # Save previous section
                if current_header:
                    sections[current_header] = "\n".join(current_content).strip()
                current_header = line[3:].strip().lower()
                current_content = []
            elif current_header:
                current_content.append(line)

        # Save last section
        if current_header:
            sections[current_header] = "\n".join(current_content).strip()

        return sections
