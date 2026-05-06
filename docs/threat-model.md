# Threat model

**Document type:** STRIDE threat model for the local MVP, plus a section
covering ML-specific threats that don't map cleanly onto STRIDE. Companion
to [`architecture.md`](architecture.md) — read its §4 (train/serve parity
invariant) and §5 (trust boundaries) before this.

**Status:** First real pass. The previous version of this file was a
37-line outline; this one extends each STRIDE category with adversary
model, attack scenario, detection plan, today's mitigation, residual
risk, and a phase-2 plan.

**Scope:** What runs in this repo today — local FastAPI + MLflow + the
GitHub Actions workflows. Phase-2 controls (Cosign, Evidently, AWS
deployment) are referenced where they close gaps but are not assumed to
exist.

**Format:** Each threat is documented in six fields:

- **Threat:** the adversary and what they want
- **Attack scenario:** how it works against this codebase, with file paths
- **Detection:** how we'd notice (or "not detected today")
- **Mitigation today:** what's in `main`, with file references
- **Residual risk:** what remains uncovered after the mitigation
- **Phase 2:** what closes the gap and where the work lands

---

## 1. Spoofing

### 1.1 API client without a valid key

**Threat:** An external attacker with network reach to the FastAPI process
attempts to call `/predict` without a valid API key, hoping for free risk
scoring or to probe the endpoint for misconfiguration.

**Attack scenario:** Attacker sends a `POST /predict` with a guessed key,
no key, or a key drawn from a leaked `.env` fragment. Each attempt is
rejected at the dependency layer before the handler runs.

**Detection:** The audit middleware logs `request.start` and `request.end`
events for every request, including the path and HTTP status. A spike of
401s on `/predict` is observable in the structured logs; no alarm exists
today.

**Mitigation today:** `require_api_key` in `src/asm/serving/api.py:52`
checks the `X-API-Key` header against `settings.api_key`, returning 401 if
absent or mismatched. `auto_error=False` on the `APIKeyHeader` is
deliberate so the rejection is uniform whether the header is missing or
wrong.

**Residual risk:** A single shared API key is the entire authentication
surface. There's no rate limit on failed attempts, no lockout, no
per-actor distinction. A leaked key gives full access until rotated.

**Phase 2:** JWT-based auth with per-tenant scoping (planned in
`aws-blueprint.md` §4). New module `src/asm/serving/auth.py`. IP-based
rate-limit middleware on 401 responses.

### 1.2 Tampered model loaded from the registry

**Threat:** An attacker with write access to the MLflow artifact store or
the host filesystem holding `mlartifacts/` replaces the registered
`cve-risk-classifier/1` artifact — e.g. a backdoored model that scores
everything `high_risk=False` to suppress alerts on real exploits.

**Attack scenario:** Attacker compromises the MLflow tracking host, the
artifact bucket, or the local `mlartifacts/` directory. They overwrite the
model file. On the next API restart, `lifespan` in
`src/asm/serving/api.py:33` calls `mlflow.xgboost.load_model` against the
URI and the FastAPI process serves the attacker's model. There is no
signature check.

**Detection:** Not detected today. The `model.load.ok` log line emits but
contains no integrity result — only the URI string.

**Mitigation today:** None at the artifact level. The host filesystem and
MLflow process are trusted by assumption — see `architecture.md` §5
("Everything *between* those two boundaries is trusted").

**Residual risk:** The entire post-training supply chain is unsigned. Any
attacker who reaches the artifact bytes wins.

**Phase 2:** Cosign signing at training time, signature verification at
load time. Code lands in `src/asm/registry/sign.py` (currently a one-line
TODO), called from `train.py` after `log_model` and from `api.py`
`lifespan` before `load_model`. AWS production uses keyless `awskms:///`
signing per `aws-blueprint.md` §3.

### 1.3 Hijacked EPSS upstream

**Threat:** An attacker compromises the EPSS hosting (DNS takeover of
`epss.empiricalsecurity.com`, CDN edge compromise, or TLS-stripping MitM
on the operator's network) and serves a malicious feed.

**Attack scenario:** Operator runs `python -m asm.data.ingest`. The httpx
client connects to the hijacked endpoint. The attacker's CSV is returned
under valid HTTPS (their cert) with content of their choosing — labels
flipped on specific CVE families, or the entire feed shaped to bias the
eventual model.

**Detection:** A schema-conformant feed passes Pandera silently. A row
count or distribution deviation would be visible in the `epss.parsed` and
`epss.written` log lines (`rows=` field), but no alarm fires today.

**Mitigation today:** TLS via httpx (default verification, no certificate
pinning). `EPSSRecord` Pandera schema in `src/asm/data/validate.py:7`
rejects malformed rows. Per-snapshot SHA-256 manifest in
`data/raw/epss-<ts>.manifest.json` records exactly which bytes were
ingested, so the post-hoc question "what did we train on?" is answerable.

**Residual risk:** A schema-valid but semantically poisoned feed is not
caught — see §7.1.

**Phase 2:** Distribution-shift check at ingestion (Evidently report
comparing today's snapshot to a rolling baseline; alert on KS-statistic
> threshold). Lands in `src/asm/data/ingest.py` as a post-validate step,
with the report saved alongside the manifest.

---

## 2. Tampering

### 2.1 Training data modified between ingest and train

**Threat:** An attacker with write access to `data/processed/` modifies
`epss.parquet` after ingestion has validated it but before `train.py`
reads it.

**Attack scenario:** Operator runs `ingest`; the parquet is written and
schema-validated. A malicious co-tenant on the host, a compromised CI
runner, or a developer with write permission modifies the parquet — flips
labels in the top decile, removes high-risk rows, etc. Operator runs
`train` later. The MLflow run records the *modified* file's hash via
`_data_sha256`, so the run looks self-consistent but the model is
biased.

**Detection:** The `data.sha256` tag on the MLflow run will not match the
hash recorded in the ingestion manifest. An operator (or CI job)
comparing the two would notice. No automation does this comparison today.

**Mitigation today:** The ingestion manifest records the SHA-256 of the
*raw* CSV.gz; the MLflow run records the SHA-256 of the *processed*
parquet. Together they form an audit chain — but only if someone follows
it.

**Residual risk:** No automatic enforcement that the parquet hasn't been
modified between ingest and train. Filesystem permissions are the only
real defense.

**Phase 2:** A `verify` DVC stage between `ingest` and `features` that
re-derives the processed parquet from the raw snapshot and asserts hash
equality. Alternatively, sign the parquet at write time and verify at
read time — same `sign.py` module as model signing.

### 2.2 Silent feature contract tampering (train/serve parity drift)

**Threat:** Anyone with commit rights changes feature engineering on one
side of the train/serve boundary without changing the other, breaking the
contract that `architecture.md` §4 calls the "train/serve feature parity
invariant."

**Attack scenario:** This is mostly an unintentional-tampering threat,
but it has a malicious form. A contributor edits `build_features` in
`src/asm/models/train.py` to add a column, rename one, or change a
transform, and forgets — or deliberately omits — the matching change in
`_build_features` in `src/asm/serving/api.py`. The training pipeline
succeeds. The model deploys. Inference now scores a different feature
distribution than the model learned on. For a column-shape mismatch
XGBoost would raise; for a *value* mismatch (same shape, different
semantics) it would not.

A concrete instance of this drift exists in `main` today even without any
edit: `cve_age_years` is computed as `datetime.now(UTC).year - year` in
both functions, but resolves at *training time* in `build_features`
(values frozen into the trained DataFrame) and at *request time* in
`_build_features` (re-evaluated every call). On January 1 of any year
after training, every CVE is one year older at inference than the model
ever saw — silent off-by-one, no log line, no exception.

**Detection:** Not detected today. There is no canary-input regression
test that scores a known CVE list and compares to a stored expected
output.

**Mitigation today:** Reviewer discipline. Both functions are flagged in
`architecture.md` §4 as a known parity hazard. Column order matches;
regex matches; comments in both files reference the mirror.

**Residual risk:** Anything a reviewer might miss on a PR — particularly
the year-tick-over above, which no code change is required to trigger.

**Phase 2:** Two complementary fixes. (a) A regression test in `tests/`
that loads the registered model and scores a fixed CVE list, asserting
within tolerance against checked-in expected values. (b) Unification of
feature engineering into `src/asm/features/build.py` (currently a TODO
stub), called by both `train.py` and `api.py`. The year-tick bug
specifically gets fixed by passing the model's training year as a
constant loaded from MLflow tags rather than reading wall-clock at
request time.

### 2.3 Tampered request body in transit

**Threat:** An attacker on the path between a legitimate API client and
the server modifies the request body en route.

**Attack scenario:** Client sends `cve_ids=[CVE-A, CVE-B]`. MitM rewrites
to `cve_ids=[CVE-A]`. Server scores fewer CVEs than the client believes;
client uses an incomplete result.

**Detection:** N/A at the API; integrity is the transport's job.

**Mitigation today:** TLS terminates at uvicorn in dev (or App Runner in
phase 2). Within a single host (dev) there's no MitM surface; across the
internet, TLS provides integrity.

**Residual risk:** Client-side TLS misconfiguration or pinning failures
are out of scope for the server.

**Phase 2:** No additional server-side action needed. Operator
documentation should require TLS 1.2+ for any non-localhost client.

---

## 3. Repudiation

### 3.1 Predictions made without traceability

**Threat:** A prediction influences a downstream decision (an analyst
deprioritizes a CVE because the model said `high_risk=False`), and later
the team needs to determine which model produced the score and on what
input. Without lineage, neither operator nor auditor can answer.

**Attack scenario:** Less an attack than a forensic gap. An incident
occurs — a CVE the model scored low gets exploited. The team needs to
know which model version, which input, which time. If audit data is
missing, blame is unassignable and process improvement is impossible.

**Detection:** Audit log queryable on `event=predict`.

**Mitigation today:** `audit_log` in `src/asm/serving/audit.py` is bound
to the structlog logger named `"audit"`. Every `/predict` call emits an
event with `asset_id`, `n_cves`, `max_score`, `model_version`. The audit
middleware in `src/asm/serving/api.py:62` also logs `request.start` and
`request.end` for the entire HTTP surface with path, method, and status.

**Residual risk:** The audit log doesn't include the *full input* (every
CVE ID) or a hash of it; per-CVE scores aren't logged. If the question is
"what exactly did this model say about CVE-X for asset-Y on date-Z?" the
answer is partial. Audit lines today go to stdout — there's no separate
sink, so retention is whatever the orchestrator does. Logged `asset_id`
is also as sensitive as the customer makes it: the
`aws-blueprint.md` §1 contract says asset IDs are opaque tokens, but
nothing in the API enforces that.

**Phase 2:** Add an input-hash field to the predict audit event (SHA-256
of the sorted CVE list). Configure structlog to emit audit events on a
separate handler shipping to a dedicated sink (CloudWatch log group with
longer retention). Hash `asset_id` with a per-tenant salt before logging.
Documented in `aws-blueprint.md` §4 "Audit logging."

### 3.2 Training runs without code/data lineage

**Threat:** A model is trained, registered, and served, but no record
exists of which code revision and which data snapshot produced it.
Asked "reproduce this," the team can't.

**Attack scenario:** A data scientist runs `train.py` in a dirty git
working tree with uncommitted changes. The model registers. They roll
back their working tree. The model in production now reflects code that
exists nowhere.

**Detection:** Compare `git.sha` tag on the MLflow run against the
repository's commit graph. If the SHA is `unknown` or not a known commit,
that's the signal.

**Mitigation today:** `train.py:34` (`_git_sha`) records `HEAD`'s commit
SHA as a tag on the MLflow run; `_data_sha256` (line 46) records the
parquet hash. Both go onto the run as tags so the registered model can be
correlated back. `git.sha` falls back to `"unknown"` if `git` isn't
available — that string is itself a signal that the run is
unreproducible.

**Residual risk:** The git SHA is HEAD, not "the SHA of the training
code." A dirty working tree (`git status` shows modifications) registers
as the parent commit's SHA, which is wrong.

**Phase 2:** Add `git.dirty` boolean tag to the run (1 if `git status
--porcelain` is non-empty). Refuse to promote any model with
`git.dirty=1` to a production alias. Lands in
`src/asm/registry/promote.py`.

### 3.3 Shared API key collapses actor identity

**Threat:** Multiple human or service consumers share one API key. The
audit log records that "the key" called `/predict`, not which actor.

**Attack scenario:** An incident requires answering "who scored asset-X
at 3am?" The audit log says "the API key did." If the team has 5
services and 12 humans using that one key, the answer is irreducible.

**Detection:** N/A — the gap is structural.

**Mitigation today:** None. There is one key.

**Residual risk:** Repudiation is essentially uncovered for any
multi-actor setup.

**Phase 2:** Per-tenant JWTs with `sub` claim, audit-logged. Same module
as 1.1.

---

## 4. Information disclosure

### 4.1 Secrets in code or version control

**Threat:** A developer commits a credential (API key, NVD API key,
database password, AWS key) into the repository.

**Attack scenario:** Bad day, copy-paste, fast review. The credential
lands on `main`, gets pushed, gets indexed.

**Detection:** `gitleaks` in `.pre-commit-config.yaml:15` runs on every
commit; the same scanner runs in `.github/workflows/security.yml` job
`secrets` on every PR and push to `main`. A finding fails the workflow.

**Mitigation today:** Pre-commit hook + CI job. `.env` is in
`.gitignore`. The README quickstart explicitly tells operators to copy
`.env.example` and edit, never commit.

**Residual risk:** Pre-commit can be bypassed with `--no-verify`; the CI
job catches it post-push, but the secret has by then existed in the
remote's reflog. Standard mitigation: rotate the moment a leak is found
(`runbook.md` "Lost API key").

**Phase 2:** GitHub push protection (server-side pre-receive hook).
Already a standard GitHub feature; needs to be enabled at the
organization level.

### 4.2 Sensitive feature leakage in model outputs

**Threat:** The model echoes feature values or training-data fragments
in its response, allowing inference about the training set or about
other tenants' inputs.

**Attack scenario:** Attacker calls `/predict` with crafted inputs and
observes the response. Today's response is bounded — `cve_id`,
`risk_score`, `high_risk`, `model_version`, `max_risk_score`. No feature
values, no training-set CVE IDs, no internal identifiers.

**Detection:** N/A — the response schema is the mitigation.

**Mitigation today:** `PredictResponse` and `CVEScore` Pydantic models in
`src/asm/serving/api.py:84` constrain the output shape. The model returns
probabilities, not feature vectors.

**Residual risk:** The probability itself is information — see §7.3 for
membership inference. For today's three trivial features this is
uninteresting; it becomes interesting when phase-2 features include CVSS
vectors and KEV flags.

**Phase 2:** Output rounding (e.g., 2-decimal `risk_score`) reduces
fingerprinting bandwidth. Per-tenant rate limits cap query volume.

### 4.3 Verbose error messages echo input

**Threat:** An error response includes attacker-supplied input verbatim,
enabling reflection-style attacks (XSS if rendered in a browser,
log-poisoning if interpreted by a downstream log analyzer).

**Attack scenario:** Attacker sends a malformed CVE ID containing markup
or control characters. The 422 response from `_build_features`
(`src/asm/serving/api.py:102`) includes the offending CVE in the body:
`f"Invalid CVE ID format: {cve}"`. A downstream consumer that renders
this into HTML, or a log collector that splits on newlines, sees
attacker-controlled bytes.

**Detection:** Not flagged by Bandit; this is a classic "intended" echo.

**Mitigation today:** FastAPI serializes the `detail` as JSON, so HTML
interpretation requires a downstream consumer doing something dangerous,
not the API itself. The input regex `^CVE-\d{4}-\d{4,7}$` only fails
*because* the input doesn't match, so by the time it's echoed it can
contain arbitrary bytes.

**Residual risk:** A misconfigured downstream that renders errors as
HTML, or a log collector that splits on newlines, would be exploitable.

**Phase 2:** Don't echo the offending value. Replace with
`"Invalid CVE ID format"` and log the full value to the audit stream
instead. Single-line fix in `src/asm/serving/api.py`.

---

## 5. Denial of service

### 5.1 Unbounded `/predict` payload

**Threat:** Attacker sends a request with a very large `cve_ids` list
hoping to exhaust CPU or memory in the prediction path.

**Attack scenario:** Authenticated attacker sends
`{"asset_id": "x", "cve_ids": [<10_000 IDs>]}`. Without input bounds, the
server allocates a 10k-row DataFrame, runs XGBoost, returns 10k scores,
and one request consumes seconds of CPU.

**Detection:** Pydantic raises 422 for any list longer than 500. The
audit middleware logs the request status, so a flood of 422s is visible
in the log. No alarm today.

**Mitigation today:** `PredictRequest.cve_ids` has `max_length=500` and
`asset_id` has `max_length=128` (`src/asm/serving/api.py:79`). Pydantic
rejects oversized payloads before the handler executes.

**Residual risk:** 500 CVEs is fine for one request, but a parallel flood
of 500-CVE requests is not bounded — see 5.2.

**Phase 2:** Lower the cap if real workloads stay well under 500. Add a
total request size limit at the uvicorn / proxy layer.

### 5.2 No rate limit on `/predict` (TODO from previous version, still open)

**Threat:** An authenticated client (legitimate or attacker with a
leaked key) issues unbounded requests, saturating the API process.

**Attack scenario:** Attacker has a key. They run
`for i in $(seq 1 100000); do curl ... &; done`. FastAPI is
single-process by default; CPU pegs; the model holds the GIL through
`predict_proba`; latency for legitimate clients climbs into the seconds.

**Detection:** Audit middleware logs every request. A spike of `/predict`
from one client is visible in retrospect, not in real time.

**Mitigation today:** **None — this is the standing TODO inherited from
the previous version of this document and it has not been resolved.**
The entry is preserved deliberately. See `src/asm/serving/api.py` —
there is no rate-limit middleware registered, and the threat-model entry
in §5 of `architecture.md` lists rate limiting as "not validated."

**Residual risk:** A misbehaving (or hostile) authenticated client can
denial-of-service the entire instance.

**Phase 2:** Per-key (eventually per-tenant-JWT) rate-limit middleware
in `src/asm/serving/api.py` — `slowapi` or a hand-rolled token bucket
keyed on the `X-API-Key`. Tracked as the open TODO; when resolved this
section moves to "Mitigation today." Production additionally gets
concurrency limits on the App Runner service per `aws-blueprint.md` §2.

### 5.3 Large EPSS feed exhausting disk

**Threat:** An adversary controlling the EPSS endpoint serves a
multi-gigabyte payload to fill the operator's disk.

**Attack scenario:** Operator runs daily ingestion via cron / EventBridge.
The hijacked feed serves 10 GB. `data/raw/` fills, the next stage fails,
unrelated services on the host fail too as the disk approaches full.

**Detection:** The manifest records `bytes`. A radically larger snapshot
than yesterday's is visible to anyone reading manifests; no automation
checks.

**Mitigation today:** `httpx.Client(timeout=60.0)` in
`src/asm/data/ingest.py:54` will time out a slow upload but doesn't cap
size. Tenacity retries up to 3 times, which could amplify a partial
payload by 3× in the worst case.

**Residual risk:** No size cap. A fast pipe can deliver multiple GB
inside 60 seconds.

**Phase 2:** Stream the response and abort if running byte count exceeds
a configurable cap (e.g., 200 MB; EPSS is normally ~10 MB). Lands in
`_fetch` in `src/asm/data/ingest.py`.

---

## 6. Elevation of privilege

### 6.1 Container escape from the API process

**Threat:** A vulnerability in FastAPI, uvicorn, or any Python
dependency allows code execution; the attacker tries to escape the
container to the host.

**Attack scenario:** Hypothetical RCE in any of the Python deps.
Attacker shells in. Tries to read host filesystem, escalate to root,
lateral-move.

**Detection:** Trivy scans the container image in the
`security.yml#container` job for known CVEs in the runtime image and
dependencies. SARIF lands in the GitHub Security tab on every push. New
CRITICAL/HIGH findings are visible there.

**Mitigation today:** Multi-stage `docker/Dockerfile.api` runs the API as
UID 1000 (`useradd --system`), uses `python:3.11-slim` as runtime base,
has no build tools (`gcc`, `apt`) in the runtime layer, and contains no
shell utilities beyond `/bin/sh`. `HEALTHCHECK` uses `python -c` rather
than `curl` to avoid pulling extra binaries in.

**Residual risk:** `slim` still has `/bin/sh`, `dpkg`, and the Python
interpreter — all useful to an attacker. A successful Python-deps RCE
could read in-process memory (the API key, the loaded model).

**Phase 2:** Distroless or `python:3.11-alpine` runtime base, depending
on dependency compatibility. Read-only root filesystem at the
orchestrator layer. AppArmor / seccomp profile in production.

### 6.2 CI runner privilege

**Threat:** A workflow job has more permissions than it needs, and a
compromised dependency in the workflow uses them.

**Attack scenario:** A malicious version of a third-party action (e.g., a
typosquatted SARIF uploader) is added to a workflow. It reads
`GITHUB_TOKEN` and pushes back to the repo, or exfiltrates secrets.

**Detection:** Dependabot for actions; manual review on workflow PRs.

**Mitigation today:** `.github/workflows/ci.yml` declares
`permissions: contents: read` at workflow level.
`.github/workflows/security.yml` declares `contents: read` plus
`security-events: write` (only for SARIF upload). Each job inherits these
— least-privilege by default. Most actions are pinned with major version
tags (`@v4`, `@v5`, `@v3`); Trivy is pinned to `@master` deliberately
(documented in commit `4ff3553`) to get fixes faster, accepting the
supply-chain risk in exchange.

**Residual risk:** Tag pinning means a compromised maintainer of an
upstream action can publish a malicious version to the same tag. Trivy
on `@master` is more exposed still.

**Phase 2:** Pin all third-party actions to commit SHAs (or use a
renovate bot that pins SHAs and updates them with diff review). GitHub
OIDC for AWS deploy jobs (no long-lived `AWS_ACCESS_KEY_ID` in Actions
secrets) per `aws-blueprint.md` §3 sample workflow.

### 6.3 Model deserialization

**Threat:** `mlflow.xgboost.load_model` deserializes a model file. If the
file format permits arbitrary code execution on load, a tampered
artifact (1.2) becomes RCE on the API process — not just
mis-prediction.

**Attack scenario:** Attacker (per 1.2) replaces the registered
artifact. On API restart, `load_model` runs the attacker's code with the
privileges of the FastAPI process.

**Detection:** None at load time. Trivy scans the image, not the model.

**Mitigation today:** XGBoost's native model format is a JSON-like
structured file, *not* Python pickle, so a swapped XGBoost model file is
limited to the "wrong predictions" outcome covered in 1.2. However, the
MLflow `python_function` flavor that wraps the model does involve
cloudpickle on the wrapper side, which broadens the surface.

**Residual risk:** If the registered flavor ever changes (e.g., moving
to a custom `pyfunc` wrapper for ensembling), the load path becomes
pickle-based and the threat becomes RCE.

**Phase 2:** Document explicitly that the registered flavor is
`xgboost`. Verify Cosign signature *before* invoking `load_model`.
Reject any artifact whose `MLmodel` metadata flavor doesn't match the
expected one.

---

## 7. ML-specific threats

The categories above are general security threats that happen to land on
an ML system. The threats below are ones an ML system has *because it is
an ML system* — they don't have natural homes in STRIDE, though §2.2
(silent feature contract tampering) is arguably one.

### 7.1 Training-data poisoning

**Threat:** An adversary influences the EPSS feed or any other training
data source so that the model learns a wrong relationship — most usefully,
to score the adversary's preferred CVEs as low-risk.

**Attack scenario:** Two paths. (a) Direct: the EPSS upstream is
compromised (1.3) or a man-in-the-middle delivers a poisoned snapshot.
(b) Indirect: the adversary influences EPSS's own scoring methodology by
publishing fake exploit-attempt telemetry that EPSS's sensors ingest. The
indirect path is out of scope for this system to defend; the direct one
is in scope. Poisoned snapshot lands, passes Pandera (it's
schema-conformant), trains a biased model.

**Detection:** Distribution-shift monitoring (Evidently, phase 2) would
flag a snapshot whose label distribution differs sharply from the
historical baseline. Today, no such check exists. The manifest records
the bytes but doesn't compare them to anything.

**Mitigation today:** SHA-256 manifest provides forensic traceability
after the fact. Pandera schema rejects malformed but not "wrong-but-valid"
data. TLS to upstream prevents naive MitM but not upstream compromise.

**Residual risk:** The schema-conformant poisoned-snapshot scenario is
fully uncovered.

**Phase 2:** Evidently distribution-shift report run as part of the
ingestion stage; alert on KS > threshold. Lands in
`src/asm/monitoring/drift.py` (currently a TODO stub). Holdout PR-AUC
gate before promotion (model-side check that complements the data-side
check) lands in `src/asm/registry/promote.py`.

### 7.2 Model evasion at inference

**Threat:** An adversary crafts input that scores misleadingly —
typically "score this dangerous CVE as safe" so it gets deprioritized.

**Attack scenario:** Attacker has an asset they want left unpatched.
Today's model uses only three derived features (`cve_year`,
`cve_age_years`, `cve_seq_log`) parsed from the CVE ID itself, which
means the attacker has *no* control over the input given a fixed CVE
ID. The "evasion" surface today is essentially "pick a CVE ID the model
scores low" — a property of the model's accuracy, not a crafted-input
attack. There is no equivalent of an L_∞-perturbation attack against a
CVE ID.

**Detection:** N/A in today's narrow feature set.

**Mitigation today:** The narrowness of the feature set is itself the
mitigation — there's nothing to perturb. Pydantic + regex rejects any
CVE ID that doesn't match `^CVE-\d{4}-\d{4,7}$`.

**Residual risk:** Becomes substantially larger when CVSS, NVD
descriptions, or KEV flags are added in phase 2. Then the attacker
controls real feature values, and adversarial-perturbation attacks
become meaningful.

**Phase 2:** Once richer features land, run ART's evasion attacks
(FGSM-equivalent for tabular, HopSkipJump for query-only) against the
trained model on a held-out adversarial set. Lands in
`tests/security/test_adversarial.py` (currently a skeleton). Promotion
gate: median adversarial accuracy ≥ 80% of clean accuracy.

### 7.3 Membership inference and model inversion

**Threat:** An attacker queries the API to determine whether a given
record was in the training set (membership inference) or to reconstruct
training-data features from API responses (model inversion).

**Attack scenario:** Attacker submits queries and observes `risk_score`.
With enough queries, they fit a shadow model approximating the
production model, then probe its decision boundary to learn about
training data. For today's system, training data is the *public* EPSS
feed — there is nothing private to recover, so the threat is
structurally mitigated by data choice.

**Detection:** Per-key request volume monitoring (phase 2). High-volume
single-key queries are not flagged today.

**Mitigation today:** Training data is fully public. Inference responses
include only `risk_score`, `high_risk`, and `model_version` — no
per-feature attribution. The `asset_id` from a request is not stored
anywhere a future query could read.

**Residual risk:** When customer asset inventories influence training
(they don't today, and `aws-blueprint.md` §1 says they never will), the
threat reactivates. Membership inference also matters once per-tenant
fine-tuned models exist.

**Phase 2:** Per-tenant rate limits (reuses the rate-limit work from
5.2) cap shadow-model query budgets. Differential privacy in training
(DP-SGD or label noise) is the textbook mitigation but probably overkill
as long as training data stays public.

### 7.4 Adversarial-robustness regression

**Threat:** A model deploys with worse robustness than its predecessor,
silently. This is the meta-threat that 7.2 becomes once any defense is
in place: the defense itself can regress.

**Attack scenario:** Phase 2 lands an evasion test against ART. Six
months later, a contributor refactors the model's hyperparameters and the
test stops being run regularly because it's slow, or its threshold gets
relaxed in a hurry. The next release is more evadable than the previous
one. Nobody notices.

**Detection:** Regression check in CI: ART evasion accuracy must be
within ε of the previous run. Doesn't exist today.

**Mitigation today:** The ART suite is a skeleton —
`tests/security/test_adversarial.py` exists and the `adversarial` job in
`security.yml:84` runs it, but the test bodies are placeholders. There
is no robustness baseline to regress from. The README acknowledges this
("ART — adversarial robustness skeleton (full suite is phase 2)").

**Residual risk:** The entire ML-security frontier for this project is
open until the suite is built out.

**Phase 2:** Implement the full ART suite (FGSM, PGD-equivalent for
tabular, HopSkipJump for query-only). Store baseline robustness metrics
in `metrics/adversarial.json` (paralleling `metrics/train.json`). Gate
promotion on no-regression vs the previous baseline.

---

## 8. Out of scope

- **Browser-app concerns** (CSRF, CORS misconfiguration). The API is
  service-to-service with no session state; CSRF is structurally absent.
  CORS is uvicorn default (none), correct for a service API.
- **L3/L4 DDoS.** Infrastructure concern — App Runner / CloudFront in
  phase 2.
- **Insider threat by the operator.** Anyone with shell on the host can
  do anything. The trust model is "the operator is trusted." Phase-2 AWS
  deployment narrows this via IAM least-privilege.
- **Supply-chain attacks against unreported Python dep compromises.**
  `pip-audit` only catches known-reported CVEs. SBOM (Trivy + Anchore)
  gives forensic traceability after the fact.

---

## 9. Standing open items

- **Resolve the FastAPI rate-limit TODO (5.2).** Longest-running gap in
  this document.
- **Implement Cosign signing (1.2, 6.3).** Until this lands, the trust
  boundary in `architecture.md` §5 is broader than a security reviewer
  would normally accept.
- **Replace stubs in `src/asm/registry/sign.py` and
  `src/asm/monitoring/drift.py`** — they are referenced as mitigations
  across this document and are currently one-line TODO files.
- **Build out the ART skeleton (7.2, 7.4).**
- **Pin GitHub Actions to commit SHAs (6.2).**

This document should be updated whenever any of these items lands. A
threat model that lags the code is worse than no threat model.
