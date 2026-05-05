# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

ML-driven CVE risk prioritization with an end-to-end MLSecOps pipeline. XGBoost binary classifier trained on EPSS exploitation probabilities (~330k records), served via authenticated FastAPI. Final-year IBA undergraduate project: a deliberately scoped local MVP that exercises every MLSecOps control, with the production AWS deployment specified in `docs/aws-blueprint.md` rather than built.

## Common commands

Setup (Python 3.11):

```bash
pip install -e ".[dev,security,dashboard]"
cp .env.example .env   # set API_KEY (required)
pre-commit install
```

Day-to-day (also exposed as `make` targets — see `Makefile`):

```bash
ruff check src tests          # lint
ruff format src tests         # format
mypy src                      # strict type-check (configured in pyproject.toml)
pytest                        # all tests, with coverage
pytest tests/unit/test_config.py::test_name -v   # single test
pytest tests/security/ -v     # only the adversarial/input-validation suite
```

Running the pipeline locally requires MLflow up first (model is loaded from the registry at API startup):

```bash
# Terminal 1
mlflow server --backend-store-uri sqlite:///mlflow.db --default-artifact-root ./mlartifacts \
  --host 127.0.0.1 --port 5000

# Terminal 2
python -m asm.data.ingest      # pulls EPSS, hashes, validates, writes data/processed/epss.parquet
python -m asm.models.train     # logs run + registers model "cve-risk-classifier" v1
uvicorn asm.serving.api:app --host 127.0.0.1 --port 8000
```

Dockerized stack (Postgres + MLflow; the API stays out of the default `up` via the `app` profile):

```bash
docker compose up -d                         # postgres + mlflow only
docker compose --profile app up --build      # adds the API
```

CI gate to be aware of: `pytest --cov=asm --cov-fail-under=30` runs on every push (`.github/workflows/ci.yml`). The `security.yml` workflow runs five jobs (gitleaks, bandit, pip-audit, trivy + SBOM, ART) — `pip-audit` is non-`exit-zero`, so a new vulnerable transitive will fail the build.

## Architecture

Four pipeline stages live under `src/asm/`. Each one is also a DVC stage (`dvc.yaml`) and module-runnable via `python -m asm.<stage>.<entrypoint>`:

1. **`asm.data`** — `ingest.py` pulls the EPSS daily feed, writes a snapshot under `data/raw/<name>-<ts>.csv.gz` plus a sibling `.manifest.json` with SHA-256 + byte count, validates with `EPSSRecord` from `validate.py`, then writes `data/processed/epss.parquet`. The manifest pattern is the provenance contract — preserve it if you add new sources.
2. **`asm.models`** — `train.py` reads the parquet, calls `build_features` to derive `cve_year` / `cve_age_years` / `cve_seq_log` from CVE IDs, defines the label as the top 10% by EPSS (`HIGH_RISK_PERCENTILE = 0.90`), and **deliberately drops the raw EPSS score from features** so the model learns from CVE metadata alone (otherwise it trivially predicts the label). MLflow run logs `data.sha256` + `git.sha` tags so every run is pinned to exact data and exact code, and the model is registered as `cve-risk-classifier`.
3. **`asm.registry`** — `sign.py` and `promote.py` are phase-2 stubs (cosign signing + alias promotion).
4. **`asm.serving`** — `api.py` loads `models:/cve-risk-classifier/1` at FastAPI startup via `lifespan`. If the load fails the server still comes up but `/predict` returns 503 — check `_model_state` and the `model.load.fail` log line. Auth is `X-API-Key` (matched against `settings.api_key`). The `audit_middleware` wraps every request, and `/predict` writes a structured `predict` audit event with input size + max score + model version.

**Critical invariant: training/serving feature parity.** `_build_features` in `src/asm/serving/api.py` mirrors `build_features` in `src/asm/models/train.py`. They are not shared code. If you change one, change the other in the same commit, or predictions will silently drift from the training distribution.

`asm.config.get_settings()` is the single entry point for env-driven config (Pydantic `BaseSettings`, reads `.env`). `API_KEY` and `DATABASE_URL` are required — missing them fails fast at import. `tests/conftest.py` autouses a fixture that sets both for every test, so importing `asm.config` from a test never blows up.

`asm.monitoring.drift` (Evidently) is a phase-2 stub. The `security` extra installs `adversarial-robustness-toolbox`; `tests/security/` is the placeholder suite the `adversarial` CI job runs.

## Conventions worth knowing

- `ruff` is configured with a strict ruleset (`E,F,W,I,N,UP,B,S,C4,SIM,RUF`) at line-length 100; `tests/**` ignores `S101`/`S106` so asserts and hardcoded test passwords are fine.
- `mypy` runs in `strict` mode against `src/` only.
- Logs are `structlog` everywhere; the audit logger is bound to `"audit"` — keep prediction-path events going through `asm.serving.audit.audit_log` rather than ad-hoc loggers so a downstream sink can filter on logger name.
- The runtime Docker image is non-root (UID 1000), multi-stage, slim base, no build tools — keep it that way; that posture is what the threat model in `docs/threat-model.md` assumes.
- Pre-commit runs `gitleaks` + `bandit` + `ruff` (with `--fix`) + ruff-format. Don't bypass with `--no-verify`; if a hook fails, fix the underlying issue.
