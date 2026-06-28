# Attack Surface ML

> ML-driven attack surface management: discovery, misconfiguration scanning, and CVE risk prioritization, integrated end-to-end behind an authenticated API. Hardened with an MLSecOps pipeline.

[![CI](https://github.com/imranasad48/attack-surface-ml/actions/workflows/ci.yml/badge.svg)](https://github.com/imranasad48/attack-surface-ml/actions/workflows/ci.yml)
[![Security](https://github.com/imranasad48/attack-surface-ml/actions/workflows/security.yml/badge.svg)](https://github.com/imranasad48/attack-surface-ml/actions/workflows/security.yml)
[![Deploy](https://github.com/imranasad48/attack-surface-ml/actions/workflows/deploy.yml/badge.svg)](https://github.com/imranasad48/attack-surface-ml/actions/workflows/deploy.yml)

## Live deployment

The production system is live at **<https://13.232.57.188.nip.io>** — single-node EC2 in `ap-south-1` (Mumbai), HTTPS via Let's Encrypt, auto-deployed on push to `main` via GitHub Actions.

Quick checks:

```bash
curl https://13-233-25-75.nip.io/health
# {"status":"ok","model_loaded":"True","model_version":"1"}
```

- Swagger UI: <https://13.232.57.188.nip.io/docs>
- Operational runbook: [`docs/deployment.md`](docs/deployment.md)
- Target HA architecture: [`docs/aws-blueprint.md`](docs/aws-blueprint.md)

## What it does

Three pillars of attack-surface management, wired together by a single orchestrator:

1. **Discovery** — given an apex domain, enumerate subdomains (`subfinder`) and port-scan each (`nmap -sV`) to produce a typed inventory of services with CPE identifiers.
2. **Misconfiguration scanning** — run `nuclei` across the discovered hosts to surface exposed admin panels, default credentials, missing security headers, and the like.
3. **CVE risk prioritization** — for every discovered service, look up known CVEs against the NVD REST API (CPE → CVE), then score each CVE with an XGBoost classifier trained on EPSS exploitation probabilities (~330,000 records). Returns a calibrated risk score per CVE, scoped to an asset.

A single `POST /scan` call kicks off all three, runs them in the background, and returns a job ID you can poll. The pipeline itself is hardened end-to-end: hash-validated data ingestion, schema-validated boundaries, audit-logged predictions, signed model contracts, per-API-key rate limiting, and a CI/CD security workflow that runs on every push.

## Why it matters

Security teams in mid-to-large enterprises drown in CVE backlogs. EPSS publishes exploitation probabilities for known CVEs but with a 24–72 hour delay. Worse, most teams don't have a clean inventory of *which* CVEs apply to *which* asset in the first place — that's the gap discovery + misconfig + per-host CPE lookup closes. This system gives an early estimate the moment a CVE-ID exists, scoped to the assets that actually expose the vulnerable software, so triage can start immediately and exploitation windows close earlier.

## How it works

```
                              ┌──────────────────┐
   apex domain  ────────────► │ POST /scan       │  X-API-Key, 10/min
                              └────────┬─────────┘
                                       │ BackgroundTasks
                                       ▼
                              ┌──────────────────┐
                              │ orchestrator     │
                              │ pipeline.run_scan│
                              └────────┬─────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
    ┌───────────────┐         ┌───────────────┐         ┌─────────────────┐
    │ asm.discovery │         │ asm.misconfig │         │ asm.orchestrator│
    │ subfinder +   │         │ nuclei        │         │ NVD CPE→CVE     │
    │ nmap -sV      │         │               │         │ (SQLite-cached) │
    └───────┬───────┘         └───────┬───────┘         └────────┬────────┘
            │                         │                          │
            │ Asset[ports[CPE]]       │ Finding[severity]        │ {cpe: [CVE-IDs]}
            └─────────────────────────┴──────────────────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │ POST /predict    │  XGBoost, in-process
                              │ (per-asset CVEs) │
                              └────────┬─────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │ UnifiedScanResult│  data/orchestrator/<target>-<ts>.json
                              │  + .manifest.json│  SHA-256 provenance
                              └──────────────────┘
```

Each pillar is also runnable on its own (`python -m asm.discovery.scan`, `python -m asm.misconfig.scan`); the orchestrator is the one that turns them into a service. The full architecture document — with stage-by-stage tables, trust boundaries, and the train/serve feature parity invariant — lives in [`docs/architecture.md`](docs/architecture.md).

## What's working today

- **Discovery:** `subfinder` + `nmap -sV` wrapped in `asm.discovery`, producing typed `Asset` records (hostname, IP, ports, services, CPEs). Per-host failures are logged and skipped — one wedged host doesn't sink the scan.
- **Misconfiguration:** `nuclei` wrapped in `asm.misconfig`, producing typed `Finding` records (template ID, severity, host, matched URL, CWE).
- **Orchestrator:** `asm.orchestrator.pipeline` runs all three pillars in sequence with per-phase failure isolation (NVD outage doesn't fail the whole scan; misconfig errors don't abort either). Results land in `data/orchestrator/<target>-<ts>.json` with a sibling `.manifest.json` that mirrors the discovery/data manifest pattern (SHA-256 + provenance).
- **NVD cache:** SQLite-backed CPE → CVE cache (`data/orchestrator/nvd_cache.db`). First scan is slow (one HTTP per unique CPE, rate-limited per NVD's documented limits); subsequent scans hit cache. CPE 2.2 → 2.3 conversion handled internally so nmap output flows cleanly into the NVD API.
- **CVE scoring:** XGBoost binary classifier (top-10% EPSS = high risk), ROC-AUC ≈ 0.77, PR-AUC ≈ 0.30 (3× random baseline).
- **Tracking:** MLflow with full provenance — data hash, git SHA, params, metrics, model artifact, all per run.
- **Serving:** FastAPI with API-key auth, Pydantic input validation, per-API-key rate limiting (`/predict` 60/min, `/scan` 10/min, `/scan/{job_id}` 60/min), audit logging, structured request/response contracts.
- **CI:** Ruff lint + format, Mypy type checking, Pytest with coverage gating — green on every push.
- **Security workflow (5 controls, all green):**
  - `gitleaks` — secret scanning on every push
  - `bandit` — Python SAST, SARIF uploaded to GitHub Security tab
  - `pip-audit` — dependency CVE scanning
  - `trivy` — container scanning + SBOM (CycloneDX)
  - `ART` — adversarial robustness skeleton (full suite is phase 2)

## Working demonstration

End-to-end against the public demo target `scanme.nmap.org` (the host nmap.org maintains for exactly this purpose):

```
1 asset discovered
141 CVEs identified across exposed services
1 misconfiguration finding
~110 seconds end-to-end (with a warm NVD cache)
```

And on the security-pipeline side: on the first push, `pip-audit` flagged **CVE-2026-3219** in the `pip` package itself. The pipeline blocked the deploy. The next commit (`4ff3553`) upgraded pip to the patched version. Detection → response → fix, all recorded in git history. This is what a working MLSecOps pipeline looks like in practice.

## Quickstart

Requires Python 3.11 plus three external scanning tools: `subfinder`, `nmap`, and `nuclei`. All three must be on `PATH`.

### Install scanning tools

**Linux / macOS:**

```bash
# nmap
sudo apt-get install nmap        # Debian/Ubuntu
brew install nmap                # macOS

# subfinder (Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# nuclei (Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

**Windows:**

```powershell
# nmap: download installer from https://nmap.org/download.html
# subfinder + nuclei: download release binaries from
#   https://github.com/projectdiscovery/subfinder/releases
#   https://github.com/projectdiscovery/nuclei/releases
# Extract to a directory on PATH, then:
nuclei -update-templates
```

### Install Python project

```bash
git clone https://github.com/daniyal-hussain01/attack-surface-ml.git
cd attack-surface-ml
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
# source .venv/bin/activate     # macOS/Linux
pip install -e ".[dev,security,dashboard]"
cp .env.example .env  # set API_KEY (required); NVD_API_KEY optional but recommended
```

### Train the model and bring up the API

```bash
# Terminal 1 — MLflow tracking
mlflow server --backend-store-uri sqlite:///mlflow.db --default-artifact-root ./mlartifacts \
  --host 127.0.0.1 --port 5000

# Terminal 2 — pull data, train, serve
python -m asm.data.ingest
python -m asm.models.train
uvicorn asm.serving.api:app --host 127.0.0.1 --port 8000
```

### Run an end-to-end scan

CLI (synchronous, blocking — useful for demos):

```bash
python -m asm.orchestrator.pipeline scanme.nmap.org
# → data/orchestrator/scanme.nmap.org-<ts>.json
```

API (asynchronous, via the `/scan` endpoint):

```bash
# Kick off a scan
curl -X POST http://127.0.0.1:8000/scan \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org"}'

# → {"job_id": "...", "target": "scanme.nmap.org", "status": "pending", ...}

# Poll for completion
curl http://127.0.0.1:8000/scan/<job_id> -H "X-API-Key: $API_KEY"

# → {"status": "completed", "result": {"assets": [...], "aggregate_summary": {...}}, ...}
```

`scanme.nmap.org` is the official safe demo target — nmap.org explicitly authorizes scanning of that host. **Do not point this at hosts you don't own or have written permission to test.**

The Swagger UI at `http://127.0.0.1:8000/docs` documents every endpoint and lets you try them with auth from the browser.

## API Reference

| Method | Path | Purpose | Rate limit |
|---|---|---|---|
| `GET` | `/health` | Liveness + model load status | none |
| `POST` | `/predict` | Score one or more CVE-IDs for an asset | 60/min per key |
| `POST` | `/scan` | Kick off an end-to-end ASM scan against a target | 10/min per key |
| `GET` | `/scan/{job_id}` | Poll a scan job for status / result | 60/min per key |

Auth: every endpoint except `/health` requires `X-API-Key: <secret>` matching `API_KEY` from `.env`. See `/docs` (Swagger UI) for full request/response schemas and live examples.

`POST /scan` returns immediately with a pending job; the actual work runs in a FastAPI background task. Scans against an empty NVD cache typically take 60–120 seconds; warm-cache reruns are seconds. The result JSON nests an `AssetRiskReport` per discovered host with `services`, `cves` (with `risk_score`, `high_risk`), `misconfigs`, and a `risk_summary`.

In-memory job storage is a known limitation of the local MVP — process restart loses pending and completed jobs. A real deployment would back this with Redis or a DB-backed task queue (specified in [`docs/aws-blueprint.md`](docs/aws-blueprint.md)).

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full picture and [`docs/threat-model.md`](docs/threat-model.md) for STRIDE applied to the ML pipeline. Highlights:

- Two trust boundaries: the EPSS feed and every authenticated HTTP request. Validation is concentrated at both.
- Train/serve feature parity is enforced by convention (two `_build_features` mirrors flagged in code comments) — see `docs/architecture.md` §4 for the failure mode and mitigation plan.
- Discovery and misconfig wrap subprocess calls behind the same hash-validated manifest pattern that `asm.data.ingest` uses for the EPSS feed — every scan output has a sibling `.manifest.json` recording SHA-256, byte count, target, and timestamp.

## Production deployment

**Live (v1):** Single-node EC2 in `ap-south-1` (Mumbai). Three Docker services — `api` (FastAPI), `mlflow` (model registry), `postgres` — behind nginx with a Let's Encrypt certificate. GitHub Actions auto-deploys on push to `main`. CloudWatch agent ships CPU/memory/disk metrics. Full runbook in [`docs/deployment.md`](docs/deployment.md).

**Target (v2):** The original blueprint targets ECS/Fargate or App Runner with an Application Load Balancer, RDS-managed Postgres, KMS-encrypted S3 for model artifacts, AWS Secrets Manager for runtime secrets, and Terraform for infrastructure-as-code. v1 was deliberately scoped to a single-node deployment to validate the orchestrator end-to-end before adding HA complexity. See [`docs/aws-blueprint.md`](docs/aws-blueprint.md) for the full target architecture.

## Repository layout

```
src/asm/             # production code
├── data/            # EPSS ingestion + Pandera schemas
├── models/          # XGBoost training
├── registry/        # cosign signing + model promotion (phase 2)
├── serving/         # FastAPI app, audit log, /predict, /scan, /scan/{job_id}
├── monitoring/      # Evidently drift checks (phase 2)
├── discovery/       # subfinder + nmap wrappers, Asset/PortInfo schemas
├── misconfig/       # nuclei wrapper, Finding/MisconfigResult schemas
└── orchestrator/    # pipeline (5-phase scan), nvd (cached CPE→CVE), jobs (in-memory store)
tests/               # unit, integration, security, discovery, misconfig, orchestrator
.github/workflows/   # ci.yml, security.yml
docker/              # multi-stage non-root Dockerfile
docs/                # architecture, threat model, runbook, AWS blueprint
```

## Project context

Master's-level project at IBA, Karachi.

This is a five-person group project. All five members — **Syed Daniyal Hussain, Syed Muhammad Meesum Abbas, Muhammad Asad Imran, Raza Shah Hussain, Muhammad Hassan** — are equal contributors to the overall project, which spans research, system design, documentation, and the broader MLSecOps thesis the codebase supports.

Within this repository, individual code authorship breaks down as follows (verifiable from `git log`):

- **Syed Daniyal Hussain** — original ML pipeline: EPSS ingestion (`asm.data`), Pandera schemas, XGBoost training (`asm.models`), MLflow tracking, FastAPI `/predict`, MLSecOps CI/security workflows, initial threat model and AWS blueprint.
- **Muhammad Asad Imran** — discovery module (`asm.discovery`: `subfinder` + `nmap` orchestration), misconfiguration module (`asm.misconfig`: `nuclei` wrapper), unified orchestrator (`asm.orchestrator`: pipeline + NVD cache + async job store), per-API-key rate limiting, `/scan` endpoints, expanded architecture and threat-model documentation.

Substantial contributions from **Syed Muhammad Meesum Abbas, Raza Shah Hussain, and Muhammad Hassan** to the wider project — research, system design, documentation, evaluation — live outside this repository and are not reflected in the file-level commit history above. The split here is a code-attribution map, not a measure of overall contribution.

The repository ships both a working local MVP for contributors and a deployed production system at <https://13.232.57.188.nip.io>. v1 was deliberately scoped to single-node EC2 to validate the full orchestrator end-to-end; v2 targets HA infrastructure as detailed in [`docs/aws-blueprint.md`](docs/aws-blueprint.md).
