# Production Deployment

**Document type:** Operational runbook for the production deployment.
**Status:** Reflects what's running on EC2 as of commit `a45aaeb`. Companion to [`architecture.md`](architecture.md) (system design), [`aws-blueprint.md`](aws-blueprint.md) (target HA architecture), and [`runbook.md`](runbook.md) (incident scenarios).
**Scope:** What runs on AWS EC2 today — image build via GitHub Actions, push to GHCR, SSH-driven deploy to a single-node EC2, nginx + Let's Encrypt, CloudWatch metrics. Does not cover local dev (see top-level README).

---

## Live URL

- **Live URL:** <https://13-233-25-75.nip.io>
- **Endpoints:** `/health`, `/docs` (Swagger UI), `/predict`, `/scan`, `/scan/{job_id}`
- **Authentication:** `X-API-Key` header (production key in EC2's `.env`, never committed)

`nip.io` is a free wildcard DNS service that maps any IP into a hostname (so `13-233-25-75.nip.io` resolves to `13.233.25.75`). We use it because Let's Encrypt's HTTP-01 challenge requires a DNS name, and we don't have a registered domain for this MVP. Real production would use a registered domain via Route 53; see [Known limitations](#known-limitations--not-yet-done).

## Architecture

Single-node EC2 in `ap-south-1` (Mumbai). Three docker services: postgres (data), mlflow (model registry), api (FastAPI app). nginx on the host terminates HTTPS via Let's Encrypt and reverse-proxies to api on `127.0.0.1:8000`. CloudWatch agent ships CPU/memory/disk metrics.

```
                              [ Internet ]
                                    |
                      https://13-233-25-75.nip.io
                                    |
                          ┌─────────────────────┐
                          │  EC2 t3.medium       │
                          │  (Ubuntu 22.04)      │
                          │                      │
                          │  nginx :443  (LE TLS)│
                          │     ↓                │
                          │  api :8000 (FastAPI) │
                          │     ↓                │
                          │  mlflow :5000        │
                          │     ↓                │
                          │  postgres :5432      │
                          └─────────────────────┘
```

## Stack

| Component | Image | Source | Notes |
|---|---|---|---|
| api | `ghcr.io/imranasad48/attack-surface-ml:latest` | this repo (`docker/Dockerfile.api`) | Bundles subfinder, nmap, nuclei + templates |
| mlflow | `ghcr.io/imranasad48/asm-mlflow:v2.11.1` | this repo (`docker/Dockerfile.mlflow`) | Vendor MLflow + psycopg2-binary |
| postgres | `postgres:16-alpine` | Docker Hub | Stock |
| nginx | apt-installed on host | Ubuntu 22.04 | Not containerized |
| Let's Encrypt | `certbot` via apt | — | Auto-renewal via systemd timer |
| CloudWatch agent | apt-installed on host | — | Reports to AWS account's CloudWatch |

## Environment variables

The `api` service reads these from `/home/ubuntu/attack-surface-ml/.env` on the EC2 (loaded via docker-compose's `env_file` directive):

- `API_KEY` — production `X-API-Key` header value (random 32+ char token)
- `NVD_API_KEY` — NVD CVE database API key (for `/scan` CVE enrichment)
- `DATABASE_URL` — `postgresql://asm:asm@postgres:5432/asm` (set in compose, not `.env`)
- `MLFLOW_TRACKING_URI` — `http://mlflow:5000` (set in compose, not `.env`)
- `LOG_LEVEL` — `INFO`

The `.env` file is mode `0600`, owner `ubuntu:ubuntu`, and listed in `.gitignore`. `.env.production.example` documents the required variables without values.

## CI/CD pipeline

- Code lives in <https://github.com/imranasad48/attack-surface-ml>
- On every push to `main`, `.github/workflows/deploy.yml` fires. `paths-ignore` excludes `docs/`, `*.md`, `.gitignore`, and the other workflows so cosmetic changes don't trigger 5-min build+deploys.
- Pipeline: `docker buildx build` → push to GHCR (`:latest` and `:<commit-sha>`) → SSH to EC2 via `webfactory/ssh-agent` → `git fetch` + `git reset --hard origin/main` → `docker compose pull api` → `docker compose up -d api` → poll `/health` for up to 2 min.
- The deploy SSH key (ed25519) is stored in GitHub Actions secret `EC2_SSH_KEY`; `EC2_HOST` and `EC2_USER` are also secrets.
- `workflow_dispatch` is enabled for manual triggers from the Actions UI.
- A concurrency group prevents racing deploys: `group: deploy-production`, `cancel-in-progress: false` (queue rather than abort, so an in-flight deploy completes before the next starts).

## Manual redeploy (emergency / debug)

SSH to the EC2 and run:

```bash
cd ~/attack-surface-ml
git fetch origin --prune
git reset --hard origin/main
docker compose -f docker-compose.prod.yml pull api
docker compose -f docker-compose.prod.yml up -d api
curl http://localhost:8000/health
```

## Rollback

GitHub Actions tags every build with two tags: `:latest` and `:<commit-sha>`. To roll back to a known-good commit:

1. SSH to the EC2: `cd ~/attack-surface-ml`
2. Edit `docker-compose.prod.yml`: change `image: ghcr.io/imranasad48/attack-surface-ml:latest` to `image: ghcr.io/imranasad48/attack-surface-ml:<good-sha>`
3. `docker compose -f docker-compose.prod.yml up -d api`
4. Confirm `/health` returns 200

This pins the api image to that specific SHA. To return to auto-deploy after fixing the root cause, revert the compose edit (or `git fetch && git reset --hard origin/main`, which resets it).

## Reboot resilience

- All containers have `restart: always` in compose.
- `docker.service` is enabled at the systemd level (`systemctl is-enabled docker` → `enabled`).
- Verified by reboot test on 2026-05-08: instance rebooted, all three containers came back automatically, `/health` returned 200 within 90 seconds.

## Known limitations / not-yet-done

- **Single-node deployment, no HA.** Real prod would use ASG + ALB + RDS-managed Postgres (target architecture in [`aws-blueprint.md`](aws-blueprint.md)).
- **Secrets in plaintext.** `.env` on the EC2 and GitHub Actions repo secrets are both plaintext at rest. Adequate for v1; production-grade would use AWS Secrets Manager.
- **`nip.io` hostname.** Free DNS, not suitable for a real product. Real deployment would use a registered domain with Route 53.
- **No automated postgres backup.** Only the docker named volume (`pgdata`). One-line manual backup: `docker compose exec postgres pg_dump -U asm asm > backup.sql`.
- **Deploy workflow doesn't gate on CI.** A failing `ci.yml` or `security.yml` run still allows a successful deploy. Acceptable for v1; production would add `needs: ci` or `workflow_run` gating.
- **nuclei templates pinned to image age.** Templates are downloaded at image build time and pinned via the Dockerfile. Templates change daily; an image older than its build age may miss new CVEs. Real prod would refresh templates per-deploy or on a cron.

## Verification commands

After any deploy, confirm the system is healthy:

```bash
# /health (no auth required)
curl https://13-233-25-75.nip.io/health
# Expected: {"status":"ok","model_loaded":"True","model_version":"1"}

# /predict (substitute production API key from EC2's .env)
curl -X POST https://13-233-25-75.nip.io/predict \
  -H "X-API-Key: <PROD_KEY>" -H "Content-Type: application/json" \
  -d '{"asset_id":"smoke-test","cve_ids":["CVE-2021-44228"]}'

# /scan async (returns job_id, poll /scan/<job_id> until status=completed)
curl -X POST https://13-233-25-75.nip.io/scan \
  -H "X-API-Key: <PROD_KEY>" -H "Content-Type: application/json" \
  -d '{"target":"scanme.nmap.org"}'
```

## Footnotes / lessons learned

- The original deploy workflow used `echo "${{ secrets.EC2_SSH_KEY }}" > ~/.ssh/deploy_key` for SSH key delivery. This is unreliable for multi-line OpenSSH keys in GitHub Actions due to secret-redaction interaction with newline handling. Switched to `webfactory/ssh-agent@v0.9.0`, which loads the key into ssh-agent in memory. See commit `3c202e4`.
- The MLflow client was originally unconstrained (`>=2.10`), resolving to 3.x. The 3.x client calls `/api/2.0/mlflow/logged-models`, which doesn't exist on the 2.11.1 server. Pinned to `==2.11.1` in commit `577acfb`.
- The api container needs the `mlflow-artifacts` named volume mounted at `/mlflow/artifacts` so the MLflow client (at training time) can write `logged_models/<run-id>/` artifacts the server will read. Captured in commit `af94bc8`.
- A failed deploy spent over an hour debugging "Permission denied (publickey)" before we found that the `EC2_USER` repo secret had been set to the literal string `EC2_SSH_KEY` (the name of a different secret) instead of `ubuntu`. sshd reports `Invalid user X` as a generic publickey rejection on the client side — a deliberate sshd hardening that prevents user enumeration but obscures this kind of mistake. Lesson: always check `/var/log/auth.log` server-side first when GHA reports publickey rejection. See commit `a45aaeb`.
