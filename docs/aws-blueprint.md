# AWS Production Blueprint

**Document type:** Production architecture specification, phase 2.
**Status:** Local MVP shipped (`main` branch). AWS deployment specified here, not yet implemented.

This document specifies how the working local MVP would be promoted to a production AWS deployment. It answers the architectural questions a security or platform reviewer would ask before approving the system for an internal pilot.

---

## 1. Problem statement and data plan

### Domain

CVE exploitation-risk prioritization for enterprise security teams. The system predicts which CVEs in an asset inventory are most likely to be exploited, giving an early signal before EPSS publishes its own probability (typically 24–72 hours after CVE disclosure).

### Data sources

| Source | Type | Use | Refresh |
|---|---|---|---|
| EPSS (FIRST.org) | Public CSV | Training labels and inference comparison baseline | Daily |
| NVD CVE feed | Public JSON | CVSS vector features, descriptions | Daily |
| CISA KEV catalog | Public JSON | Known-exploited flag (binary feature) | On-update |
| Customer asset inventory | Private | Inference input only | Customer-controlled |

### Data governance

- **Public feeds** are content-addressed (SHA-256 manifest per snapshot) and treated as untrusted upstream — schema-validated at ingestion
- **Customer asset inventories** never leave the customer's tenant; only inference results are returned
- **Training data** is reproducible from snapshots — no record-level customer data is incorporated
- **Privacy:** No PII in training or inference. Asset IDs are opaque tokens chosen by the customer

### Data pipeline (production)
EPSS/NVD/KEV (public)        Customer assets (tenant)
↓                              ↓
S3: epss-raw/                 In-tenant only
(KMS-encrypted, versioned)
↓
Lambda: ingest-validator

SHA-256 manifest
Pandera schema check
Distribution-shift check
↓
S3: features-curated/
↓
SageMaker training job (or EC2)
↓
MLflow registry → S3: models-registry/ (cosign-signed)
↓
App Runner: serving (pulls signed model on cold start)

---

## 2. Architecture and tech stack

### AWS service mapping

| Concern | Service | Rationale |
|---|---|---|
| Object storage | S3 | Versioned, KMS-encrypted, IAM-scoped per bucket |
| Container registry | ECR | Image scanning + Cosign signing |
| Compute (serving) | App Runner | Serverless container, auto-scale, simpler than EKS for this scale |
| Compute (training) | EC2 spot or SageMaker training jobs | One-shot training; spot for cost |
| Ingestion triggers | Lambda + EventBridge | Daily EPSS pull, event-driven |
| Secrets | Secrets Manager | Rotation, IAM-scoped, audit-logged |
| Encryption | KMS (per-bucket CMK) | Customer-controlled keys, audit-logged decryption |
| IAM | Role-based, least-privilege | One role per service, no shared credentials |
| Observability | CloudWatch logs + metrics | Native, IAM-integrated |
| Alerting | CloudWatch Alarms → SNS | Email + Slack webhook |

**Why App Runner over EKS/Fargate:** App Runner is the simplest service that satisfies the requirements (HTTPS endpoint, auto-scale, container-based). EKS adds Kubernetes operational overhead for no benefit at this scale. Fargate without ECS is comparable but App Runner has built-in auto-scaling without service definitions. Migrate to ECS/Fargate when multi-service orchestration is needed.

**Why not SageMaker for serving:** SageMaker Endpoints are a fit for high-throughput batch inference. For our request profile (single-asset queries with ~10–500 CVEs each), App Runner is cheaper and simpler.

### ML lifecycle

| Stage | Tool | Production setup |
|---|---|---|
| Preprocessing | pandas + Pandera | Lambda for ingestion, schema-fail-loud at boundary |
| Training | XGBoost on EC2 spot | Triggered by EventBridge schedule + manual override |
| Validation | Holdout PR-AUC + drift check | Promotion gate: PR-AUC ≥ baseline + drift score ≤ threshold |
| Packaging | Docker (multi-stage non-root) | Built in CI, scanned by Trivy, signed by Cosign |
| Deployment | App Runner blue/green | New revision deployed alongside; traffic shifted 0% → 10% → 100% |
| Monitoring | Evidently + CloudWatch metrics | Daily drift report, alarm if input distribution shifts |
| Retraining | Triggered by drift alarm or schedule | Same training pipeline, gated by promotion checks |
| Registry | MLflow on EC2 + S3 backend | All artifacts in S3, signed before promotion |

---

## 3. End-to-end pipeline with automation

### Stage gates

Each stage is a separate GitHub Actions workflow with explicit promotion criteria.
PR opened → CI workflow (lint, type, test, coverage gate)
↓
Merged to main → Security workflow (gitleaks, bandit, pip-audit, trivy + SBOM, ART)
↓
✓ All security gates pass
↓
Build image → ECR push (Cosign-signed)
↓
Deploy to dev environment (App Runner, dev account)
↓
Smoke tests against dev /health and /predict
↓
Manual approval gate
↓
Promote to stage (same image, different config)
↓
Manual approval gate
↓
Promote to prod (canary 10% → 100%)
↓
Post-deploy: SBOM diff vs previous, drift baseline reset

### Terraform module structure
infra/
├── modules/
│   ├── networking/         # VPC, subnets, security groups
│   ├── storage/            # S3 buckets + KMS keys + bucket policies
│   ├── ecr/                # ECR repo + lifecycle policy
│   ├── app-runner/         # App Runner service + auto-scaling config
│   ├── lambda-ingest/      # EPSS daily ingestion Lambda
│   ├── secrets/            # Secrets Manager + rotation
│   └── observability/      # CloudWatch + alarms + SNS
├── envs/
│   ├── dev/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── terraform.tfvars
│   ├── stage/
│   └── prod/
└── README.md

Each environment has its own state file, its own AWS account (or VPC at minimum), and its own KMS keys. No shared resources across environments. Terraform plan is run on every PR, apply requires manual approval.

### Sample Terraform module (S3 + KMS)

```hcl
# modules/storage/main.tf
resource "aws_kms_key" "data" {
  description             = "${var.env}-${var.bucket_name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_policy.json
}

resource "aws_s3_bucket" "data" {
  bucket = "${var.env}-${var.bucket_name}"
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Sample GitHub Actions deploy workflow

```yaml
name: Deploy to AWS
on:
  push:
    branches: [main]
permissions:
  id-token: write   # OIDC, no long-lived AWS keys
  contents: read

jobs:
  deploy-dev:
    needs: [security]   # gate on existing security workflow
    runs-on: ubuntu-latest
    environment: dev
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::${{ secrets.AWS_ACCOUNT_DEV }}:role/github-deploy
          aws-region: us-east-1
      - name: Build, sign, push to ECR
        run: |
          docker build -t $ECR_REPO:$GITHUB_SHA -f docker/Dockerfile.api .
          aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REGISTRY
          docker push $ECR_REPO:$GITHUB_SHA
          cosign sign --key awskms:///$KMS_KEY_ARN $ECR_REPO:$GITHUB_SHA
      - name: Deploy to App Runner
        run: aws apprunner start-deployment --service-arn $APPRUNNER_ARN
      - name: Smoke test
        run: |
          curl --fail --retry 5 --retry-delay 10 https://${{ env.APPRUNNER_URL }}/health
```

---

## 4. Security and compliance

### Encryption

- **At rest:** S3 with KMS customer-managed keys per bucket. EBS volumes encrypted with default account key. App Runner's environment variables stored in Secrets Manager (KMS-encrypted)
- **In transit:** HTTPS-only on App Runner. TLS 1.2+ between services. S3 bucket policies enforce `aws:SecureTransport`

### Access control

- **IAM:** One role per service. App Runner role can read `models-registry/` only. Lambda ingestion role can write `epss-raw/` only. No human IAM users — engineers federate via SSO
- **API auth:** API key in `Authorization` header for MVP. Phase 2: JWT with per-tenant scoping
- **Network:** App Runner has a public HTTPS endpoint with optional VPC connector for accessing internal resources. No direct database exposure

### Secrets management

- **Storage:** AWS Secrets Manager
- **Access:** IAM role-scoped per service
- **Rotation:** Automatic for database credentials (Lambda-driven). Manual rotation for API keys via runbook
- **Audit:** All Secrets Manager reads are logged in CloudTrail

### Audit logging

- **CloudTrail:** All AWS API calls (account-level, multi-region trail to S3)
- **Application audit:** Every `/predict` call logs input hash + model version + timestamp via structlog → CloudWatch Logs
- **Retention:** CloudTrail 1 year, application logs 90 days, then archived to S3 Glacier

### Threat modeling (STRIDE summary, full doc in `docs/threat-model.md`)

| Threat | Mitigation |
|---|---|
| Spoofing — unsigned model loaded | Cosign signature verified at container start |
| Tampering — poisoned training data | SHA-256 manifest + Pandera + distribution-shift check |
| Repudiation — untraced predictions | Audit log with input hash + model version |
| Information disclosure — secrets in code | gitleaks pre-commit + CI |
| Denial of service — large payloads | Pydantic max_length, App Runner concurrency limits |
| Elevation of privilege — container escape | Non-root user, minimal base image, no shell tools |

### Incident response (sketch)

1. **Detection:** CloudWatch Alarm fires (drift, error rate, or auth failures)
2. **Triage:** On-call paged via SNS → Slack. Runbook in `docs/runbook.md`
3. **Containment:** App Runner traffic flag flips to previous version (rollback ~30s)
4. **Eradication:** Identify root cause via CloudTrail + audit logs
5. **Recovery:** Patched version deployed via standard pipeline (security gates intact)
6. **Lessons learned:** Post-incident review, runbook updated, threat model updated if novel

---

## 5. MVP plan and success metrics

### Phase 1 (shipped, this repo)

- Local pipeline end-to-end
- 5 security controls in CI/CD
- Real CVE caught and patched in dependency scan
- Documented architecture and threat model

### Phase 2 (4–6 weeks)

| Week | Deliverable |
|---|---|
| 1 | Terraform modules for storage, ECR, IAM. Manual deploy to dev |
| 2 | Lambda ingestion + EventBridge schedule. App Runner serving in dev |
| 3 | Cosign signing + verification at load. NVD + KEV ingestion |
| 4 | Promotion pipeline (dev → stage), Evidently drift monitoring |
| 5 | Stage → prod canary deploy. Full ART adversarial test suite |
| 6 | Load test, cost analysis, hardening, prod cutover |

### Success criteria

| Metric | Target |
|---|---|
| Pipeline green-rate on `main` | ≥ 95% |
| `/predict` p50 latency | < 200ms |
| `/predict` p99 latency | < 1s |
| Container CVE backlog (Trivy CRITICAL) | 0 unfixed for > 7 days |
| Model PR-AUC on holdout | ≥ 0.50 (after NVD + KEV features) |
| Drift alarm false-positive rate | < 5% / week |
| Mean time to deploy (commit → prod) | < 30 min |

### Cost estimate (steady state, prod env only)

| Item | Monthly |
|---|---|
| App Runner (1 vCPU, 2 GB, ~24 req/min) | $40 |
| ECR storage + scans | $5 |
| S3 storage (snapshots + models, ~5 GB) | $1 |
| Lambda + EventBridge | $1 |
| KMS keys (4 keys × $1) | $4 |
| CloudWatch logs + metrics | $20 |
| Data transfer | $5 |
| **Total** | **~$76/mo** |

Dev + stage approximately the same again, total ~$230/mo across all environments. Conservative — actual is typically lower.

---

## 6. Deliverables (what already exists in this repo)

- ✅ `src/asm/` — production code (data, training, serving, monitoring stubs)
- ✅ `tests/` — unit, integration, security
- ✅ `.github/workflows/ci.yml` — lint, type, test, coverage
- ✅ `.github/workflows/security.yml` — 5 security controls, all green
- ✅ `docker/Dockerfile.api` — multi-stage non-root, HEALTHCHECK
- ✅ `docs/architecture.md` — system architecture
- ✅ `docs/threat-model.md` — STRIDE applied to ML pipeline
- ✅ `docs/runbook.md` — operational playbook (drift, container CVE, lost API key)
- ✅ `docs/aws-blueprint.md` — this document

### Gap (phase 2)

- ⏳ `infra/` — Terraform modules
- ⏳ `.github/workflows/deploy.yml` — AWS deployment with OIDC
- ⏳ `src/asm/registry/sign.py` — Cosign integration
- ⏳ `src/asm/monitoring/drift.py` — Evidently scheduled job
- ⏳ Lambda ingestion handler (currently runs as Python module)

---

## Production readiness checklist

- [ ] All 5 security workflow gates green for 30 consecutive days
- [ ] Threat model reviewed and signed off by security stakeholder
- [ ] Runbook tested via game-day exercise (simulated drift alarm)
- [ ] Terraform plan reviewed by platform team (no IAM `*` resource access)
- [ ] KMS keys rotated within last 12 months
- [ ] Trivy backlog: 0 unfixed CRITICAL/HIGH for 7+ days
- [ ] App Runner auto-scaling tested under 10× expected load
- [ ] CloudWatch alarms verified by triggering each one in dev
- [ ] Cosign signing verified — unsigned image is rejected by serving container
- [ ] On-call rotation defined, paging tested
- [ ] Data retention policy documented and enforced via S3 lifecycle rules
- [ ] Model rollback tested via App Runner blue-green