# Architecture

**Document type:** System architecture for the local MVP.
**Status:** Reflects what's actually in `main` as of this commit. Phase-2 production
architecture is in [`aws-blueprint.md`](aws-blueprint.md); the STRIDE threat model is
in [`threat-model.md`](threat-model.md). Where this document and the AWS blueprint
disagree, this document is authoritative for what runs *today*.

---

## 1. System overview

The MVP is a four-stage local pipeline. Public CVE risk data flows in, gets
hashed and validated, becomes a small Parquet, gets trained into an XGBoost
classifier, gets registered to MLflow, and is served behind an authenticated
FastAPI process. Every stage emits structured logs; security controls live both
in the code path (validation, auth, audit) and in CI (gitleaks, bandit,
pip-audit, trivy + SBOM, ART).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL                                       │
│   epss.empiricalsecurity.com (public CSV.gz, ~330k records, daily)          │
└──────────────────────────────────┬──────────────────────────────────────────┘
                                   │ httpx + tenacity retries (3 attempts)
                                   ▼
                         ┌─────────────────────┐
                         │  asm.data.ingest    │  TRUST BOUNDARY ◄──────────┐
                         │  - SHA-256 manifest │                            │
                         │  - Pandera schema   │  EPSSRecord validates      │
                         │    validation       │  cve / epss / percentile   │
                         └──────────┬──────────┘                            │
                                    │                                       │
                  ┌─────────────────┴─────────────────┐                     │
                  ▼                                   ▼                     │
       data/raw/epss-<ts>.csv.gz         data/processed/epss.parquet        │
       data/raw/epss-<ts>.manifest.json  (clean, schema-conformant)         │
       (immutable snapshot + provenance)                                    │
                                                      │                     │
                                                      ▼                     │
                                           ┌─────────────────────┐          │
                                           │  asm.models.train   │          │
                                           │  - build_features   │ ──┐      │
                                           │  - XGBoost fit      │   │      │
                                           │  - MLflow log       │   │ FEATURE PARITY
                                           └──────────┬──────────┘   │ INVARIANT
                                                      │              │ (see §4)
                  ┌───────────────────────────────────┤              │      │
                  ▼                                   ▼              │      │
       MLflow tracking server          Model registry:               │      │
       (mlflow.db + mlartifacts/)      "cve-risk-classifier" v1      │      │
       params / metrics / artifacts    (signed in phase 2)           │      │
                                                      │              │      │
                                                      │ models:/.../1│      │
                                                      ▼              │      │
                                           ┌─────────────────────┐   │      │
                                           │  asm.serving.api    │   │      │
                                           │  - lifespan loads   │   │      │
                                           │  - X-API-Key auth   │   │      │
                                           │  - Pydantic input   │ ◄─┘      │
                                           │  - _build_features  │          │
                                           │  - audit middleware │          │
                                           └──────────┬──────────┘          │
                                                      │                     │
                                                      ▼                     │
                              ┌──────────────────────────────────────┐      │
                              │ POST /predict                        │ ◄────┘
                              │ X-API-Key: <secret>                  │  TRUST
                              │ {asset_id, cve_ids: [...]}           │  BOUNDARY
                              └──────────────────────────────────────┘
```

ASCII art is used deliberately: it renders the same in `cat`, `less`, GitHub,
and a printed PDF. Mermaid hides the structure behind a renderer.

---

## 2. Stage-by-stage breakdown

### Stage 1 — Data ingestion (`src/asm/data/`)

| | |
|---|---|
| **Entrypoint** | `python -m asm.data.ingest` |
| **DVC stage** | `ingest` (`dvc.yaml`) |
| **Module** | `asm.data.ingest`, schemas in `asm.data.validate` |
| **Inputs** | `EPSS_URL` (constant: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`) |
| **Outputs** | `data/raw/epss-<ts>.csv.gz`, `data/raw/epss-<ts>.manifest.json`, `data/processed/epss.parquet` |
| **Security controls** | Retries with backoff; SHA-256 hash + manifest; Pandera schema validation; `lazy=True` so all violations surface together rather than one-at-a-time |

The manifest is the provenance contract. Every snapshot is recorded with
`{file, sha256, ts, bytes, source}` so a downstream consumer can verify the
exact bytes that produced a model run. `train.py` reads the *processed* parquet
and re-hashes it as `data.sha256` on the MLflow run, which means the chain is
"raw bytes → manifest → parquet → run tag" and any link can be checked
independently.

`EPSSRecord` (in `validate.py`) constrains the three columns that exist today:
`cve` matches `^CVE-\d{4}-\d{4,7}$`, `epss` and `percentile` are floats in
`[0, 1]`. `CVERecord` is also defined in the same file but is not yet wired up
— it's the schema for an NVD ingestion that hasn't been written.

### Stage 2 — Feature engineering (`src/asm/features/`)

| | |
|---|---|
| **Entrypoint** | `python -m asm.features.build` (declared in `dvc.yaml`) |
| **Status** | **Stub.** `build.py` contains a single `TODO` comment. |

`features/build.py` exists in `dvc.yaml` as a stage that produces
`data/processed/features.parquet`, but the file itself has no implementation.
In the current code path, feature engineering happens *inline* in two places:

- `build_features` in `src/asm/models/train.py` — used at training time
- `_build_features` in `src/asm/serving/api.py` — used at inference time

Both functions parse the CVE ID with the same regex and produce the same three
columns: `cve_year`, `cve_age_years`, `cve_seq_log`. Neither uses any external
data — the EPSS score itself is **deliberately dropped** at training time
because the label is derived from it (see §3). This is documented further in §4
as the train/serve feature parity invariant.

When `features/build.py` is implemented, the pipeline gains a fourth stage and
both inline functions should be replaced with a single shared call. Until then,
the duplication is the system's single biggest correctness hazard.

### Stage 3 — Training (`src/asm/models/`)

| | |
|---|---|
| **Entrypoint** | `python -m asm.models.train` |
| **DVC stage** | `train` |
| **Inputs** | `data/processed/epss.parquet` |
| **Outputs** | MLflow run (params, metrics, artifact, signature, tags), `metrics/train.json`, registered model `cve-risk-classifier` |
| **Tracking URI** | `MLFLOW_TRACKING_URI` (default `http://localhost:5000`) |
| **Security controls** | Run is tagged with `data.sha256` (parquet hash) + `git.sha` (HEAD commit) so every model is pinned to exact data and exact code |

The label is `epss >= quantile(0.90)` — top 10% by EPSS score is "high risk."
The `0.90` cutoff is the `HIGH_RISK_PERCENTILE` constant. The model is
`xgb.XGBClassifier` with `n_estimators=200, max_depth=5, learning_rate=0.1,
objective="binary:logistic", eval_metric="aucpr"`. Train/test split is 80/20
stratified on the label, `random_state=42`.

Reported metrics on the current snapshot: ROC-AUC ≈ 0.77, PR-AUC ≈ 0.30 (per
README — the README is currently the source of truth for held-out performance,
because there's no automated evaluation gate yet). PR-AUC is the headline
number — with a 10% positive class the random baseline is ~0.10, so 0.30 is
~3× random.

### Stage 4 — Serving (`src/asm/serving/`)

| | |
|---|---|
| **Entrypoint** | `uvicorn asm.serving.api:app --host 127.0.0.1 --port 8000` |
| **Module** | `asm.serving.api`, audit logger in `asm.serving.audit` |
| **Inputs** | HTTP `POST /predict`, `X-API-Key` header, JSON body `{asset_id, cve_ids: [...]}` |
| **Outputs** | JSON `{asset_id, model_version, max_risk_score, scores: [...]}`, audit log line per request |
| **Security controls** | API-key auth (`require_api_key` dep); Pydantic input validation (asset_id length, cve_ids length, CVE regex); audit middleware; non-root container |

The model is loaded **once** at startup via `lifespan`, from
`models:/cve-risk-classifier/1`. If the load fails (MLflow down, no run yet,
wrong tracking URI), the server still starts but `/predict` returns 503. This
is intentional — it lets `/health` come up so the container's `HEALTHCHECK`
passes and an orchestrator can keep restarting the API while the operator
fixes the registry.

Audit logging is deliberately bound to the structlog logger named `"audit"` so
that a downstream sink can filter on logger name and ship the audit stream to
a separate destination from the application stream. Every `/predict` call logs
`asset_id`, number of CVEs, `max_score`, `model_version`. The audit middleware
also logs request start/end with status codes for the entire HTTP surface.

The CVE-ID regex in the API (`CVE_RE`) matches the one in the Pandera schema
and the one in `train.py`. All three are independent copies of the same
pattern; if one changes, the others must change too.

---

## 3. Key design decisions and rationale

The MVP is deliberately small. Each piece was picked for a reason; the
rationale matters more than the choice itself, because it tells you what would
have to change to justify swapping the piece out.

### XGBoost over deep learning

Tabular features (CVE year, sequence number, log-sequence, eventually CVSS
vector + KEV flag) with a few hundred thousand rows. XGBoost is the dominant
algorithm on this kind of data — there's no spatial or sequence structure for
a neural network to exploit, and training fits comfortably on a laptop CPU in
seconds. Deep learning would add a GPU dependency, training-time
non-determinism, and explainability friction (SHAP for trees is cheap and
exact; for neural nets it's an approximation) for no measurable accuracy
improvement on this data shape.

If the input ever grows to include CVE descriptions or NVD reference text, a
sentence-transformer embedding fed *into* XGBoost would be the natural step
before going end-to-end neural.

### MLflow for tracking and registry

Need: every model in production must be traceable to (a) the exact dataset it
was trained on, (b) the exact code that trained it, (c) the metrics on a
fixed holdout, and (d) a downloadable artifact. MLflow gives all four out of
the box, with a SQLite backend for local and a Postgres backend in the docker
compose file. Alternatives considered:

- **Weights & Biases / Neptune** — hosted, would mean exfiltrating run metadata
  to a third party. Rejected for an MLSecOps project where the whole point is
  controlling the supply chain.
- **A directory of pickle files + a JSON manifest** — works, but loses the
  registry semantics (named model, versioned aliases) that the FastAPI loader
  depends on (`models:/cve-risk-classifier/1`).

The MLflow run tags (`data.sha256`, `git.sha`) are the bits that turn MLflow
from a UI into a provenance record.

### FastAPI for serving

ASGI, automatic OpenAPI/Swagger UI, dependency-injection-based auth, and
Pydantic for free request validation. The Pydantic model is the input
trust-boundary check: `asset_id` length, `cve_ids` length, individual CVE
regex. The audit middleware is ~10 lines because FastAPI's middleware API is a
single async function.

The alternative (Flask + a hand-written validator + `@before_request`) would
have been ~3× the code with no upside.

### Pandera for schema validation

Data validation is a *boundary* concern, not a logic concern. Pandera lets the
schema live next to the data layer (`src/asm/data/validate.py`) and run with
one line at the end of ingestion. `lazy=True` reports every violation rather
than failing on the first row — important when triaging an upstream format
change.

The schema is *strict on what it validates*: CVE format, value ranges. It does
not validate cardinality (e.g. "EPSS should always have ~330k rows") because
that's a distribution-shift concern, handled separately by drift monitoring
(Evidently, phase 2).

### Structured logging (structlog) everywhere

Every log line is a JSON dict. This matters for two reasons: (1) the audit
stream is a sub-logger that can be split out by name, and (2) CloudWatch /
Loki / any modern aggregator queries on fields, not regex over text. The cost
is one extra dependency; the benefit is that the day someone needs to ask
"what's the p99 of `max_score` for asset X over the last week" the answer is a
log query, not a re-instrumentation.

### Non-root multi-stage Docker

Build wheels in a builder stage, install them with `--no-index --find-links`
in a slim runtime stage, run as UID 1000. No build tools, no shell utilities,
no package manager in the final image. This is what the threat model
"Elevation of privilege — container escape" mitigation assumes; deviating from
it (e.g. adding `apt-get install` to the runtime stage) breaks that
assumption silently.

---

## 4. The train/serve feature parity invariant

There are two functions in this codebase that engineer features:

- `build_features(df)` in `src/asm/models/train.py` — takes the EPSS DataFrame,
  returns `(X, y)` for XGBoost
- `_build_features(cve_ids)` in `src/asm/serving/api.py` — takes a list of CVE
  ID strings from a request, returns `X` for `model.predict_proba`

They produce the same three columns by the same regex parse:

```
cve_year       = int from CVE-YYYY-NNN
cve_age_years  = current_year - cve_year
cve_seq_log    = log1p(int from CVE-YYYY-NNN sequence)
```

**They are not shared code.** They are two implementations of the same
contract, in two different modules, that happen to agree today. This is a
deliberate trade-off: pulling them into a shared module would couple the
serving package to the training package's heavier dependencies (sklearn,
xgboost are pulled in transitively). The cost is that any change to feature
engineering must be made in both places in the same commit.

**Failure mode if they drift:** the model is trained on one feature
distribution and asked to predict on a slightly different one. There is no
runtime check that catches this — XGBoost will happily score whatever
three-column DataFrame you hand it. The result is silent accuracy degradation,
not an exception.

**Concrete example, today:** `cve_age_years` calls `datetime.now(UTC).year` in
both functions, but the call resolves at *training time* in `build_features`
(values are frozen into the trained DataFrame) and at *request time* in
`_build_features` (re-evaluated on every call). On January 1 of any year after
training, every CVE is one year older at inference than the model ever saw —
no exception, no log line, just a permanent off-by-one shift in one of three
features that grows by one again each subsequent New Year's Day.

**Mitigation today:** the column order is identical, the regex is the
literal same string, and there's a comment in `_build_features` flagging the
mirror relationship. Reviewers should fail any PR that changes one without
the other.

**Mitigation when `features/build.py` is implemented (phase 2):** both
inline functions get replaced with a single call into `asm.features.build`,
the duplication goes away, and this section of the doc gets shortened to "see
`features/build.py`."

---

## 5. Trust boundaries

There are exactly two places where untrusted bytes enter the system:

### Boundary 1 — The EPSS feed

| | |
|---|---|
| **Source** | `https://epss.empiricalsecurity.com/...` over HTTPS |
| **Trust assumption** | The feed is public and the upstream is reputable, but the bytes are still untrusted — they could change schema without notice, contain malformed rows, or in a worst case be served from a hijacked CDN |
| **Validation** | (1) HTTPS so transport tampering is caught; (2) SHA-256 manifest so the operator can correlate two snapshots; (3) Pandera schema with regex + value-range checks so a schema break fails loudly at ingestion, not silently at training |
| **What is *not* validated** | The semantic correctness of the values — if EPSS started publishing all-zeros, the schema would still pass. Distribution-shift / sanity checks are phase 2 (Evidently) |

### Boundary 2 — The `/predict` API

| | |
|---|---|
| **Source** | Any HTTP client with the API key |
| **Trust assumption** | Authenticated, but possibly buggy or malicious |
| **Validation** | (1) `require_api_key` dependency rejects requests without a matching `X-API-Key`; (2) `PredictRequest` Pydantic model bounds `asset_id` (1-128 chars) and `cve_ids` (1-500 items); (3) `_build_features` rejects any CVE ID that doesn't match `^CVE-\d{4}-\d{4,7}$` with a 422 |
| **What is *not* validated** | Rate limiting (no per-key throttle today — flagged in `threat-model.md` under DoS); request body size (relies on uvicorn defaults); duplicate CVE IDs (allowed, will produce duplicate scores) |

Everything *between* those two boundaries — the parquet on disk, the MLflow
artifact, the loaded model in memory — is trusted. It's trusted because it
came from validated sources via processes the operator controls. The phase-2
Cosign signing is the bit that lets the *artifact* be trusted independently of
the operator who produced it; until then, "trust" means "trust the host
filesystem."

---

## 6. What is not implemented yet

The README and the AWS blueprint both gesture at things that don't exist in
this repo. To save the next reader an hour of grep:

| Feature | Status | Where it would live |
|---|---|---|
| NVD CVE ingestion | Schema defined (`CVERecord`), no fetcher | `src/asm/data/` — new module alongside `ingest.py` |
| CISA KEV ingestion | Not started | Same |
| `features/build.py` | One-line `TODO` stub | Replaces inline `build_features` / `_build_features` |
| Cosign artifact signing | One-line `TODO` stub | `src/asm/registry/sign.py` |
| Model promotion (registry alias) | Not started | `src/asm/registry/promote.py` |
| Evidently drift monitoring | One-line `TODO` stub | `src/asm/monitoring/drift.py` |
| Full ART adversarial test suite | Skeleton in `tests/security/test_adversarial.py` | Same path |
| FastAPI rate limiting | Not started (flagged in threat model) | Middleware in `src/asm/serving/api.py` |
| AWS deployment | Specified in `aws-blueprint.md`, not built | `infra/`, `.github/workflows/deploy.yml` |
| JWT / per-tenant auth | Not started; current auth is single shared API key | `src/asm/serving/api.py` |
| Automated evaluation gate (PR-AUC ≥ baseline) | Not started; `metrics/train.json` is written but unused by CI | New job in `.github/workflows/ci.yml` |

The AWS blueprint marks `docs/architecture.md` with a green check as a
shipped deliverable. Until this rewrite landed that was inaccurate — the
file was a 7-line stub. It is now an actual architecture document. The other
green-checked items (`src/asm/`, tests, CI workflows, Dockerfile,
threat-model.md, runbook.md) do exist as claimed.

---

## 7. Where to look first

If you are reading this for the first time and want to understand the system
in 15 minutes, in this order:

1. `src/asm/data/ingest.py` — the smallest end-to-end illustration of the
   project's house style: hash, validate, log structured, fail loud.
2. `src/asm/models/train.py` — see how MLflow tags pin a run to its data and
   code.
3. `src/asm/serving/api.py` — see the auth + Pydantic + lifespan pattern, and
   note the duplicated `_build_features`.
4. `.github/workflows/security.yml` — five jobs, one per MLSecOps control. The
   real demonstration of the project's thesis is here.
5. `docs/threat-model.md` and `docs/aws-blueprint.md` for the wider context.
