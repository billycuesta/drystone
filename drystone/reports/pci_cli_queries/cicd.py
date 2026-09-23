"""CI/CD AWS CLI query recipes for PCI DSS evidence files."""

from __future__ import annotations

from drystone.reports.pci_cli_queries import CliQuery, OutputSpec

COMPLETE_SKILLS = frozenset({"cicd"})

SOURCE_QUERIES = {
    "cicd": {
        "codebuild-projects": CliQuery(
            commands=(
                'projects=$(aws codebuild list-projects --query "projects[]" --output text)\n'
                'aws codebuild batch-get-projects --names $projects',
            ),
            output=OutputSpec(
                source="codebuild-projects",
                rows="items",
                columns=(
                    ("name", "name"),
                    ("arn", "arn"),
                    ("serviceRole", "serviceRole"),
                    ("source.type", "source.type"),
                    ("source.insecureSsl", "source.insecureSsl"),
                    ("environment.privilegedMode", "environment.privilegedMode"),
                    ("environment.environmentVariables", "environment.environmentVariables"),
                ),
            ),
        ),
        "codebuild-source-credentials": CliQuery(
            commands=("aws codebuild list-source-credentials",),
            output=OutputSpec(
                source="codebuild-source-credentials",
                rows="items",
                columns=(
                    ("arn", "arn"),
                    ("serverType", "serverType"),
                    ("authType", "authType"),
                    ("resource", "resource"),
                    ("createdAt", "createdAt"),
                ),
            ),
        ),
    }
}

_CHECK_STEMS = {
    "CICD-001": "codebuild-source-credentials",
    "CICD-002": "codebuild-projects",
}

_DERIVED_NOTES = {
    "CICD-002": "Drystone evaluates CodeBuild insecureSsl and proxy-like environment variables as an interception heuristic.",
}

CHECK_QUERIES = {}
for _check_id, _stem in _CHECK_STEMS.items():
    _source_query = SOURCE_QUERIES["cicd"][_stem]
    CHECK_QUERIES[_check_id] = CliQuery(
        commands=_source_query.commands,
        output=_source_query.output,
        evidence_name=f"{_check_id} {_stem.replace('-', ' ')}",
        derived_note=_DERIVED_NOTES.get(_check_id) or _source_query.derived_note,
    )
