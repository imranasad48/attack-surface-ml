# Attack Surface ML

> ML-driven CVE risk prioritization with an end-to-end MLSecOps pipeline.

[![CI](https://github.com/daniyal-hussain01/attack-surface-ml/actions/workflows/ci.yml/badge.svg)](https://github.com/daniyal-hussain01/attack-surface-ml/actions/workflows/ci.yml)
[![Security](https://github.com/daniyal-hussain01/attack-surface-ml/actions/workflows/security.yml/badge.svg)](https://github.com/daniyal-hussain01/attack-surface-ml/actions/workflows/security.yml)

## What it does

Predicts exploitation risk for CVEs in an asset inventory. Trained on EPSS exploitation probabilities (~330,000 real CVE records). Returns a calibrated risk score per CVE, scoped to an asset, served over an authenticated API.

The pipeline itself is hardened end-to-end: hash-validated data ingestion, schema-validated boundaries, audit-logged predictions, signed model contracts, and a CI/CD security workflow that runs on every push.

## Why it matters

Security teams in mid-to-large enterprises drown in CVE backlogs. EPSS publishes exploitation probabilities for known CVEs but with a 24–72 hour delay. This system gives an early estimate the moment a CVE-ID exists, so triage can start immediately and exploitation windows close earlier.

## What's working today

- **Data:** EPSS daily feed ingested (~330k records), SHA-256-hashed snapshots, schema-validated with Pandera
- **Training:** XGBoost binary classifier (top-10% EPSS = high risk), ROC-AUC 0.77, PR-AUC 0.30 (3× random baseline)
- **Tracking:** MLflow with full provenance — data hash, git SHA, params, metrics, model artifact, all per run
- **Serving:** FastAPI `/predict` with API-key auth, Pydantic input validation, audit logging, structured request/response contracts
- **CI:** Ruff lint + format, Mypy type checking, Pytest with coverage gating — green on every push
- **Security workflow (5 controls, all green):**
  - `gitleaks` — secret scanning on every push
  - `bandit` — Python SAST, SARIF uploaded to GitHub Security tab
  - `pip-audit` — dependency CVE scanning
  - `trivy` — container scanning + SBOM (CycloneDX)
  - `ART` — adversarial robustness skeleton (full suite is phase 2)

## Working demonstration of MLSecOps

On the first push, `pip-audit` flagged **CVE-2026-3219** in the `pip` package itself. The pipeline blocked the deploy. The next commit (`4ff3553`) upgraded pip to the patched version. Detection → response → fix, all recorded in git history. This is what a working MLSecOps pipeline looks like in practice.

## Architecture
EPSS feed → ingestion (hash + schema validate) → features → XGBoost training
↓
MLflow registry (signed in prod)
↓
FastAPI /predict (auth + audit + input validation)
↓
Risk scores
Security overlay (every stage):
gitleaks · bandit · pip-audit · trivy + SBOM · ART · cosign · KMS

See [`docs/architecture.md`](docs/architecture.md) for the full picture and [`docs/threat-model.md`](docs/threat-model.md) for STRIDE applied to the ML pipeline.

## Production design (phase 2)

The local MVP demonstrates every MLSecOps control end-to-end. The production deployment is specified in [`docs/aws-blueprint.md`](docs/aws-blueprint.md):

- **Compute:** AWS App Runner (auto-scaling container service) pulling from ECR
- **Storage:** S3 buckets for model artifacts and EPSS snapshots, KMS-encrypted, versioned
- **IaC:** Terraform with dev/stage/prod separation
- **Secrets:** AWS Secrets Manager + IAM role-based access
- **Observability:** CloudWatch logs + metrics, alarms wired to SNS
- **Signing:** Sigstore Cosign on every promoted artifact, verified at container load

## Quickstart

Requires Python 3.11.

```bash
git clone https://github.com/daniyal-hussain01/attack-surface-ml.git
cd attack-surface-ml
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -e ".[dev,security,dashboard]"
cp .env.example .env  # set API_KEY

# Terminal 1 — MLflow tracking
mlflow server --backend-store-uri sqlite:///mlflow.db --default-artifact-root ./mlartifacts --host 127.0.0.1 --port 5000

# Terminal 2 — pull data, train, serve
python -m asm.data.ingest
python -m asm.models.train
uvicorn asm.serving.api:app --host 127.0.0.1 --port 8000
```

Test it: `http://127.0.0.1:8000/docs` — Swagger UI with auth and a working `/predict`.

## Repository layout
src/asm/             # production code
├── data/            # ingestion + Pandera schemas
├── models/          # training + adversarial test stubs
├── registry/        # cosign signing + model promotion (phase 2)
├── serving/         # FastAPI app + audit log
└── monitoring/      # Evidently drift checks (phase 2)
tests/               # unit, integration, security
.github/workflows/   # ci.yml, security.yml
docker/              # multi-stage non-root Dockerfile
docs/                # architecture, threat model, runbook, AWS blueprint

## Project context

Final-year undergraduate project, built solo on a tight timeline. Scope discipline was deliberate: ship a working local MVP that demonstrates every MLSecOps control rather than half-build a production AWS deployment. The blueprint document specifies the production architecture in full.

**Author:** Syed Daniyal Hussain, Syed Muhammad Meesum Abbas, Muhammad Asad Imran, Raza Shah Hussain, Muhammad Hassan· IBA, Karachi