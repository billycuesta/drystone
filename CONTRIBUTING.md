# Contributing to Drystone

Thanks for looking at Drystone's internals. This covers how to set up a dev environment, the conventions the codebase follows, and how to add a new skill.

## Setup

```bash
git clone <repo>
cd drystone
pip install -e ".[dev,pdf,llm]"
```

- `dev` — pytest, ruff, mypy, black, pre-commit
- `pdf` — weasyprint, for PDF report generation (needs system libs; see the [Dockerfile](Dockerfile) for the exact packages on Debian/Ubuntu)
- `llm` — the Anthropic SDK, for the `claude-api` provider

## Running checks

```bash
pytest tests/           # full suite (2200+ tests)
pytest tests/skills/     # a subset, by path
ruff check drystone/     # lint
black drystone/          # format
mypy drystone/           # type check (known pre-existing debt in places; don't let it block an otherwise-clean PR)
```

CI (`.github/workflows/ci.yml`) runs pytest as a blocking gate; ruff/mypy run but are currently non-blocking due to pre-existing debt. Please don't add to that debt in new code even though CI won't fail on it.

For a full end-to-end run against real AWS evidence, see `scripts/README.md` (`e2e_test_runner.py`) — it needs a credentials file and is not part of the default test suite.

## Code conventions

- **Evidence:** collectors always save raw AWS API data before any analysis; wrap it via `BaseSkill._save_json`/`_wrap_indexed`/`_wrap_items`, not ad hoc `json.dump`.
- **Findings:** structured JSON with `severity`, `risk_score`, `remediation`, and evidence references — see `models/findings.py`.
- **Checklists:** one `checklist.json` per skill, CIS/PCI DSS mapped — see any existing skill's `checklist.json` for the shape.
- **Errors:** catch `botocore.exceptions.ClientError` explicitly around AWS calls; never let one service's failure abort the whole skill's collection.
- **Credentials:** never log them, never print them; existing tests (`tests/cli/test_main.py::TestAuditCredentialSafety`) assert this for the CLI output path.
- **Language:** code, identifiers, comments, and commit messages are English, regardless of the language used in an issue/PR discussion.
- **Comments:** default to none. Only add one where the *why* isn't obvious from the code (a workaround, a non-obvious invariant, a hidden constraint) — never restate what the code already says.

## Commit messages

Conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`), scoped when it helps (`feat(reports): ...`). No AI-attribution trailers.

## Adding a new skill

Thanks to the auto-discovery registry (`drystone/skills/registry.py`), a new skill needs **zero edits outside its own folder**:

1. `mkdir drystone/skills/{name}` with `__init__.py` (collector + `SkillClass`), `checklist.json`.
2. In `__init__.py`, declare the module-level registry constants:
   ```python
   SKILL_NAME = "yourskill"
   SKILL_DISPLAY_NAME = "Your Skill"
   SKILL_CLASS = YourSkillClass
   SKILL_WIZARD_SELECTABLE = True
   SKILL_WIZARD_LABEL = "Your Skill Audit"
   SKILL_WIZARD_ORDER = 17
   ```
3. Optional: `drystone/prompts/templates/{name}_audit.xml` to tighten evidence expectations for the LLM analysis step.
4. Add tests under `tests/skills/test_{name}.py`, mirroring an existing skill's `collect()` test (mocked `boto3.client`, dispatch by service — see `tests/skills/test_alerting_collect.py` for the reference pattern).

`scripts/e2e_test_runner.py` is the one deliberate exception: it runs Drystone as a subprocess and keeps its own hand-maintained skill list to avoid importing the `drystone` package at module scope — add new skills there by hand if you want E2E coverage.

See `CLAUDE.md` for the full architecture (3-tier validation pipeline, App-vs-Agent separation, report formats) before making structural changes.

## Pull requests

- Keep PRs scoped to one logical change; a bug fix doesn't need an unrelated refactor riding along.
- Run the full test suite locally before opening a PR — CI will re-run it, but a broken PR wastes a review cycle.
- Describe *why*, not just *what* — the diff already shows what changed.
