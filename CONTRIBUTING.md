# Contributing to TriageKit

Thanks for your interest in improving TriageKit.

## Development setup

Requires **Python ≥ 3.9**.

```bash
# Clone and install in editable mode
git clone https://github.com/BYPASS-IDC/triagekit.git
cd triagekit
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Copy environment template
cp .env.example .env
# Edit .env with a GitHub token and an LLM provider key
```

## Running tests

```bash
pytest
# or the local scanner self-test fixtures
python testbench/scripts/run_testbench.py
```

## Code style

- Prefer clear, typed Python.
- Keep scanner rules in one place (`repo_scan.py` is the canonical table where possible).
- Do not add network calls or active probing without going through the authorized-use gate and the passive/active distinction documented in `skills/01-authorized-use.md`.

## Pull requests

- One concern per PR.
- Include or update tests when behavior changes.
- Do not commit secrets, `.env`, or `__pycache__`.
- Keep skill files under `skills/` in sync with the packaged copy under `src/triagekit/skills/` if you change them.

## Security reports

See [SECURITY.md](SECURITY.md).
