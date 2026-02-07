# Scripts

Utility scripts for developing and validating Drystone.

## E2E Test Runner

File: `scripts/e2e_test_runner.py`

Runs Drystone end-to-end across combinations of:
- skills (single-skill, optional multi-skill pairs)
- report types (`general`, `pci-dss`)
- formats (`markdown`, `json`)

### Credentials JSON format

The runner expects a JSON file with AWS credentials:

```json
{
  "aws_access_key_id": "AKIA...",
  "aws_secret_access_key": "...",
  "aws_session_token": "..." 
}
```

`aws_session_token` is optional.

Important:
- Do not commit credentials files.
- The runner uses an isolated `HOME` per test so it does not modify your real `~/.drystone` config.

### Examples

Dry run (prints the plan only):

```bash
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --dry-run
```

If you are using Claude CLI, make sure you're logged in (otherwise analysis will fail):

```bash
claude /login
```

Alternatively, use Claude API (non-interactive):

```bash
export ANTHROPIC_API_KEY="..."
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --ai-provider claude-api
```

Run IAM only (4 tests):

```bash
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --skills iam
```

Run all single-skill combinations (24 tests):

```bash
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json
```

Include multi-skill pairs (adds 60 tests):

```bash
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --multi-skill
```

Parallel execution (use with care to avoid AWS throttling):

```bash
python3 scripts/e2e_test_runner.py --credentials ~/aws-creds.json --parallel 3
```

### Output

By default, results are written to `test-results/`:

- `test-results/test-results.json` (machine-readable)
- `test-results/test-results.md` (human-readable)
- `test-results/logs/*.log` (stdout/stderr per attempt)
- `test-results/homes/` (isolated HOME dirs used by tests)
