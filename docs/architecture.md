# Architecture

**Document type:** System architecture for the local MVP.
**Status:** Reflects what's actually in `main` as of this commit. Phase-2 production
architecture is in [`aws-blueprint.md`](aws-blueprint.md); the STRIDE threat model is
in [`threat-model.md`](threat-model.md). Where this document and the AWS blueprint
disagree, this document is authoritative for what runs *today*.

---

## 1. System overview

The system has two layers. An **ML pipeline** turns the public EPSS feed
into a trained risk-scoring model and serves it behind an authenticated
FastAPI process. An **ASM pipeline** wraps that model: discovery and
misconfiguration scanning produce an asset inventory with known-CVE
attribution, and the orchestrator coordinates those two pillars together
with the existing `/predict` into a single end-to-end scan.

The architecture is best read as **ASM pipeline (discovery → misconfig
→ CVE-risk-scoring) plus the underlying ML pipeline (data → features →
training → serving)**. The outer ASM pipeline calls into the inner ML
pipeline at one specific seam: the orchestrator's per-asset CVE list is
posted to the local `/predict` endpoint to obtain risk scores. Every
other interaction between the two layers is one-directional (the ML
pipeline never calls into the ASM pipeline).

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              ASM PIPELINE                                    │
│                                                                              │
│   apex domain  ──►  POST /scan  ──►  orchestrator.run_scan                   │
│                                            │                                 │
│            ┌───────────────────────────────┼────────────────────────┐        │
│            ▼                               ▼                        ▼        │
│     asm.discovery                    asm.misconfig          asm.orchestrator │
│     (subfinder + nmap)                  (nuclei)               (NVD CPE→CVE) │
│            │                               │                        │        │
│            └─────────────────┬─────────────┴────────────────────────┘        │
│                              ▼                                               │
│                       POST /predict (in-process loopback)                    │
│                              │                                               │
│                              ▼                                               │
│                  UnifiedScanResult + manifest                                │
└──────────────────────────────┬───────────────────────────────────────────────┘
                               │ /predict crosses into the ML pipeline ⇣
                               ▼
```

The orchestrator's data-flow contract — three pillars in, one
hash-validated unified report out — is documented in §8. Below the
seam, the inner ML pipeline is the same four-stage local pipeline this
document originally described. Public CVE risk data flows in, gets
hashed and validated, becomes a small Parquet, gets trained into an
XGBoost classifier, gets registered to MLflow, and is served behind an
authenticated FastAPI process. Every stage emits structured logs;
security controls live both in the code path (validation, auth, audit)
and in CI (gitleaks, bandit, pip-audit, trivy + SBOM, ART).

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

### Stage 5 — Asset discovery (`src/asm/discovery/`)

| | |
|---|---|
| **Entrypoint** | `python -m asm.discovery.scan <target>` |
| **Module** | `asm.discovery.scan`, wrappers in `asm.discovery.subfinder` and `asm.discovery.nmap` |
| **Inputs** | Apex domain (e.g. `example.com`), capped by `--max-assets` (default 50) |
| **Outputs** | `data/discovery/<target>-<ts>.json` (DiscoveryResult), `<target>-<ts>.manifest.json` |
| **Security controls** | Pydantic-validated typed records (`Asset`, `PortInfo`); per-host failures isolated (one wedged nmap doesn't sink the run); SHA-256 manifest mirroring Stage 1's contract |

Discovery wraps two external binaries: `subfinder` for subdomain enumeration
and `nmap -sV` for port + service detection. Output is `Asset` records with
`PortInfo` per open port (port number, protocol, service, product, version,
CPE). Closed/filtered ports are dropped before the typed object is built —
they don't help CVE matching downstream. The target itself is always scanned
in addition to its subdomains, so a cleanly-deployed apex with no separate
subdomains still produces a non-empty asset list.

### Stage 6 — Misconfiguration scan (`src/asm/misconfig/`)

| | |
|---|---|
| **Entrypoint** | `python -m asm.misconfig.scan <hosts...>` |
| **Module** | `asm.misconfig.scan`, wrapper in `asm.misconfig.nuclei` |
| **Inputs** | List of hosts (typically the output of `asm.discovery`) |
| **Outputs** | `data/misconfig/misconfig-<ts>.json` (MisconfigResult), `misconfig-<ts>.manifest.json` |
| **Security controls** | Pydantic-validated `Finding` records; severity filter (default `medium,high,critical`); SHA-256 manifest |

Misconfiguration scanning wraps `nuclei` against a list of hosts. Output is
`Finding` records (template ID, severity, host, matched URL, CWE, CVSS where
the template provides one). Empty host lists short-circuit without invoking
nuclei — the function returns an empty `MisconfigResult` and writes no files,
so an upstream discovery that found zero assets doesn't produce a misleading
"clean scan" artifact.

Stages 5 and 6 are *standalone* by design — they each work end-to-end without
the orchestrator. The orchestrator (§8) is what combines them with the inner
ML pipeline into a single ASM scan.

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

There are three places where untrusted bytes enter the system:

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

### Boundary 3 — External tool output and the NVD REST API

| | |
|---|---|
| **Source** | stdout of `subfinder`, `nmap -sV`, and `nuclei`; HTTPS responses from `services.nvd.nist.gov` |
| **Trust assumption** | The binaries are operator-installed (so the binaries themselves are inside the operator-trusted zone), but the *bytes they emit* cross a process boundary and are parsed text. NVD is a public third-party API; its TLS terminates at our process. |
| **Validation** | (1) nmap output is XML, parsed with `xml.etree.ElementTree` (closed/filtered ports dropped before object build); (2) nuclei output is JSONL, validated row-by-row into the `Finding` Pydantic model; (3) subfinder output is line-delimited hostnames, filtered by basic shape; (4) NVD responses are JSON, parsed defensively (missing `vulnerabilities` → empty list, rows missing `cve.id` → dropped); (5) the `target` parameter that reaches subprocess wrappers is pre-validated by `ScanRequest.target` regex (`^[a-zA-Z0-9.-]+$`, max 253 chars) before any subprocess is invoked, so shell metacharacters never reach the wrappers; (6) NVD's CPE 2.3 requirement is enforced by `_to_cpe_23` in `asm.orchestrator.nvd`, which converts nmap's CPE 2.2 output to 2.3 before the HTTP query — passthrough for input already in 2.3 form, log + return-original for unparseable input so a 404 surfaces from NVD rather than a silent rewrite |
| **What is *not* validated** | The semantic correctness of any of these sources. A tampered nmap could report fake ports; a poisoned NVD response could omit known CVEs to suppress alerts. NVD's TLS uses the system trust store with no certificate pinning. See `threat-model.md` §1.4 (subprocess substitution) and §2.4 (NVD response tampering). |

Everything *between* those three boundaries — the parquet on disk, the MLflow
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
| NVD bulk-feed ingestion | Schema defined (`CVERecord`), no fetcher. Per-CPE lookup against the NVD REST API *is* implemented in `asm.orchestrator.nvd` — that's a separate concern from ingesting the full NVD feed for training-data enrichment. | `src/asm/data/` — new module alongside `ingest.py` |
| CISA KEV ingestion | Not started | Same |
| `features/build.py` | One-line `TODO` stub | Replaces inline `build_features` / `_build_features` |
| Cosign artifact signing | One-line `TODO` stub | `src/asm/registry/sign.py` |
| Model promotion (registry alias) | Not started | `src/asm/registry/promote.py` |
| Evidently drift monitoring | One-line `TODO` stub | `src/asm/monitoring/drift.py` |
| Full ART adversarial test suite | Skeleton in `tests/security/test_adversarial.py` | Same path |
| Durable ScanJob store | In-memory dict + threading.Lock today (§8.4); a process restart loses every pending and completed job | Replace `_JOBS` in `src/asm/orchestrator/jobs.py` with a Redis or DynamoDB backend per `aws-blueprint.md` |
| AWS deployment | Specified in `aws-blueprint.md`, not built | `infra/`, `.github/workflows/deploy.yml` |
| JWT / per-tenant auth | Not started; current auth is single shared API key | `src/asm/serving/api.py` |
| Automated evaluation gate (PR-AUC ≥ baseline) | Not started; `metrics/train.json` is written but unused by CI | New job in `.github/workflows/ci.yml` |

**Closed since the previous revision:** FastAPI rate limiting (now per-API-key
on `/predict`, `/scan`, and `/scan/{job_id}` — see `threat-model.md` §5.2 and
§5.4); asset discovery (Stage 5); misconfiguration scanning (Stage 6); the
unified scan orchestrator (§8).

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
   note the duplicated `_build_features`. Also the home of `/scan` and
   `/scan/{job_id}`, which dispatch into the orchestrator.
4. `src/asm/orchestrator/pipeline.py` — see how the three ASM pillars wire
   together: a five-phase scan with explicit per-phase failure isolation,
   reusing the manifest-provenance pattern from §2 Stage 1. §8 of this
   document covers the rationale.
5. `.github/workflows/security.yml` — five jobs, one per MLSecOps control. The
   real demonstration of the project's thesis is here.
6. `docs/threat-model.md` and `docs/aws-blueprint.md` for the wider context.

---

## 8. Orchestrator pipeline

The orchestrator (`src/asm/orchestrator/`) is the ASM-pipeline wrapper added
on top of the ML pipeline described in §2. It coordinates `asm.discovery`,
`asm.misconfig`, the NVD CPE → CVE lookup, and the local `/predict` endpoint
into a single end-to-end scan. Where the ML pipeline produces a trained model,
the orchestrator produces a `UnifiedScanResult`: a per-asset risk + misconfig
report keyed to a target.

### 8.1 The five-phase scan

`pipeline.run_scan(target)` executes five phases. Each phase has explicit
failure isolation — one phase raising does not necessarily abort the rest.
The trade-off in each row is between "this phase is load-bearing for what
follows" (hard fail) and "this phase is enrichment we can do without"
(soft fail with the gap surfaced in the result).

| Phase | Module | Output | On failure |
|---|---|---|---|
| 1. Discovery | `asm.discovery.scan.discover` | `DiscoveryResult` (per host: hostname, ports, CPEs) | **Hard fail.** Without an asset list, nothing else has a target. Returns `status="failed"` with the discovery exception in `result.error`. |
| 2. Misconfig | `asm.misconfig.scan.scan` | `MisconfigResult` (Findings keyed by host) | **Soft fail.** Logged as `pipeline.misconfig.error`, scan continues with empty findings on every asset. |
| 3. NVD lookup | `asm.orchestrator.nvd.lookup_cves_for_cpes` | `dict[cpe → list[CVE-IDs]]` | **Soft fail.** Logged as `pipeline.nvd.error`, error string surfaced in `result.error`, scan completes with empty CVE lists per asset. The result still has `status="completed"` so the partial output is consumable. |
| 4. Scoring | `httpx POST /predict` (in-process loopback) | per-asset `risk_score`, `high_risk` merged into `AssetRiskReport.cves` | **Soft fail per asset.** A failed scoring call leaves `risk_score=None` for that asset's CVEs. |
| 5. Persist | `_write_result` + `_write_manifest` | `data/orchestrator/<target>-<ts>.json` plus a sibling `.manifest.json` | Always runs — including for status="failed" results from phase 1, so the failed scan is itself a forensically traceable artifact. |

The Phase 5 manifest pattern mirrors `data/raw/*.manifest.json` from the
EPSS ingestion (§2 Stage 1) — same `{file, sha256, ts, bytes, target,
status}` shape. Unifying the manifest contract across data, discovery,
misconfig, and orchestrator means a downstream forensic question ("what
did we scan, when, and is the artifact intact?") has the same answer
shape regardless of which pillar emitted it.

### 8.2 Two invocation paths: CLI and API

The orchestrator is exposed two ways, with deliberately different
semantics:

**CLI (synchronous):** `python -m asm.orchestrator.pipeline <target>`. The
shell blocks until the scan completes (60–120 seconds against a cold NVD
cache; seconds against a warm cache). The CLI prints the path of the
resulting JSON file on success. Suitable for demos, scripted use, debugging
a specific target.

**API (asynchronous):** `POST /scan` returns immediately with a `ScanJob`
record (`status="pending"`, with a UUID `job_id`) and dispatches
`run_scan_in_background` via FastAPI's `BackgroundTasks`. The caller polls
`GET /scan/{job_id}` until `status` flips to `"completed"` or `"failed"`,
at which point the response contains the full `UnifiedScanResult`. Both
endpoints require `X-API-Key` and are rate-limited per key — `/scan` at
10 requests/minute (reflecting the 60–120 second cost of each scan) and
`/scan/{job_id}` at 60/minute (polling is cheap). Implementation is in
`src/asm/serving/api.py:172` (POST) and `:186` (GET).

The CLI path bypasses the API entirely — it does not require the FastAPI
process to be running. The async path requires it, because the
orchestrator's Phase 4 scoring call is itself a `POST /predict` against
the same FastAPI process. This is a deliberate loopback that makes the
orchestrator an ordinary client of the existing `/predict` contract;
the trade-off is documented in `threat-model.md` §7.5.

### 8.3 NVD CPE → CVE cache

`asm.orchestrator.nvd` translates each discovered CPE into a list of known
CVE-IDs via NVD's REST API at `services.nvd.nist.gov/rest/json/cves/2.0`.
NVD's documented unauthenticated rate limit is 5 requests per 30-second
rolling window; with an API key it's 50 per 30 seconds. The orchestrator
sleeps `NVD_RATE_LIMIT_NO_KEY = 6.0s` or `NVD_RATE_LIMIT_WITH_KEY = 0.6s`
between requests accordingly. A typical single-asset scan produces 5–10
unique CPEs, so an unauthenticated cold scan spends ~30–60 seconds in NVD
calls alone; with an API key the same scan is ~3–6 seconds.

Subsequent scans hit the SQLite cache at `data/orchestrator/nvd_cache.db`
and complete in seconds regardless of whether an NVD API key is set.
The cache is keyed on the *original* CPE string nmap emitted (CPE 2.2
form, e.g. `cpe:/a:openbsd:openssh:6.6.1p1`) — this is intentional, so a
re-scan of the same asset hits the cache regardless of the conversion
that happened internally before the original NVD call.

The HTTP fetch internally converts CPE 2.2 to CPE 2.3 (`cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*`)
before querying NVD. The REST API only accepts CPE 2.3, but `nmap -oX`
emits 2.2. The conversion lives in `_to_cpe_23` in `nvd.py`: passthrough
for input already in 2.3 form, and log + return-original for input that
matches neither format (so an unparseable CPE produces a useful 404 from
NVD rather than a hidden conversion bug).

Rate-limit sleeps fire only on cache miss. Cache hits return without
sleeping, which is what makes warm-cache 500-CVE scans interactive.

### 8.4 In-memory job store

`asm.orchestrator.jobs` keeps a module-level `dict[str, ScanJob]` guarded by
a `threading.Lock`. `create_job`, `update_job`, `get_job`, and `list_jobs`
all acquire the lock for their critical section. `ScanJob` is a Pydantic
v2 model with `ConfigDict(frozen=True)`, so `update_job` does
`existing.model_copy(update=...)` under the lock and reassigns the dict
entry — atomic relative to concurrent readers, with no risk of a partially
mutated record being observed mid-update. `BackgroundTasks` may schedule the
worker on FastAPI's thread pool, so the lock is load-bearing rather than
defensive.

This is a deliberate MVP limitation. A process restart (uvicorn crash,
container redeploy, OS reboot) loses every pending and completed job. There
is no durable record of historical scans except for the
`data/orchestrator/<target>-<ts>.json` artifacts, which exist on disk but
are not indexed by `job_id`. The blueprint specifies Redis or DynamoDB for
the production deployment of this store; the local MVP demonstrates the API
surface and the concurrency model without paying for durable infrastructure.

The corresponding entry in §6 ("Durable ScanJob store") is the migration
path: replace the `_JOBS` dict with a Redis-backed implementation behind the
same `create_job` / `update_job` / `get_job` interface, and the rest of the
orchestrator is unchanged.
