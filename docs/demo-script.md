# Demo script

**Audience:** viva examiners. **Format:** read-along, top-to-bottom.
**Duration:** ~16 minutes across four acts, plus Q&A.
**Tone:** show the system working. No marketing voice.

---

## At-a-glance

| Act | Duration | Goal | Primary terminal |
|---|---|---|---|
| 1. End-to-end via CLI | ~3 min | Prove the pipeline runs against a real host in one command | B |
| 2. Same pipeline, async API | ~4 min | Show the production-shape interface (`/scan` + polling) | B + C |
| 3. Security and MLSecOps controls | ~5 min | Show the controls that make this MLSecOps, not just ML | A + B |
| 4. Where the ML model fits in | ~4 min | Trace one CVE from discovery to risk score, end-to-end | C |

---

## Pre-flight checklist

Run every item below at least 10 minutes before the viva starts. If any
item fails, fix it before the examiner walks in.

- [ ] **MLflow up.** Open `http://127.0.0.1:5000` in a browser. The
  experiments page must render. If not: `mlflow server --backend-store-uri
  sqlite:///mlflow.db --default-artifact-root ./mlartifacts --host 127.0.0.1
  --port 5000` in Terminal A.
- [ ] **API up.** Open `http://127.0.0.1:8000/docs`. Swagger UI must load
  and show four endpoints: `/health`, `/predict`, `/scan`, `/scan/{job_id}`.
  If not: `uvicorn asm.serving.api:app --host 127.0.0.1 --port 8000` in
  Terminal A.
- [ ] **Model loaded.** `curl http://127.0.0.1:8000/health` returns
  `"model_loaded":"True"`. If `False`, MLflow isn't reachable from the API
  process — fix MLflow first.
- [ ] **Scanning tools on PATH.** Run all three:
  ```powershell
  subfinder -version
  nmap --version
  nuclei -version
  ```
  Each must print a version. If any errors: see README "Install scanning
  tools."
- [ ] **NVD cache warm.** `Test-Path data\orchestrator\nvd_cache.db` is
  `True`. A warm cache turns a 60–90 second scan into a 10–15 second one;
  the demo timing depends on it.
- [ ] **Recent scan present.** At least one
  `data/orchestrator/scanme.nmap.org-*.json` exists. Confirms the live demo
  will have a fallback.
- [ ] **Tests green.** Run `pytest -q` one more time. All 40 tests should
  pass, 1 skipped. **If any fail, do not start the demo** — fix first.
- [ ] **Three terminals visible** on screen, sized so all are readable.
  Layout below.

---

## Three-terminal layout

| Terminal | Purpose | Leave running? | Visible to examiner |
|---|---|---|---|
| **A** | MLflow + uvicorn API. Streams audit-log lines as they happen. | Yes — never close. | Yes — they should see logs flow as you scan. |
| **B** | Where you run scan commands. | No — type fresh per act. | Yes. |
| **C** | File inspection: `cat`, `jq`, `curl`. | No. | Yes. |

Tile A on the left half of screen, B top-right, C bottom-right.

---

## ACT 1 — End-to-end via CLI (~3 min)

**Goal:** prove the pipeline runs against a real internet host, end-to-end,
in one command.

### SAY (30 seconds, before running anything)

> "I'll start with the simplest path through the system — one command, one
> host, one unified report. The target is `scanme.nmap.org`, which nmap.org
> maintains as an authorized scan target for exactly this kind of demo. The
> orchestrator runs four phases: discover assets, scan for misconfigurations,
> look up known CVEs against NVD, and score each CVE through the trained ML
> model. About 90 seconds with a warm cache."

### DO (Terminal B)

```powershell
python -m asm.orchestrator.pipeline scanme.nmap.org
```

Bash equivalent if Terminal B is WSL/Linux:

```bash
python -m asm.orchestrator.pipeline scanme.nmap.org
```

### POINT AT (as lines stream)

| Log line you'll see | What to say |
|---|---|
| `discovery.subdomains.found target=scanme.nmap.org count=0` | "subfinder found no subdomains — scanme is a single host. The target itself is always scanned regardless." |
| `nmap.done host=scanme.nmap.org open_ports=2` | "Two open ports — 22 SSH, 80 HTTP. Real internet host." |
| `misconfig.complete findings=1` | "nuclei flagged one misconfiguration. We'll look at it in a moment." |
| `nvd.cache.hit cpe=... count=N` (multiple) | "Cache hits — first time we ran this it took ~60 seconds for NVD. This run is seconds." |
| `pipeline.complete target=scanme.nmap.org duration=...` | "Done. Path printed at the bottom is the unified result." |

### DO (Terminal C — open the result)

```powershell
$path = (Get-ChildItem data\orchestrator\scanme.nmap.org-*.json |
         Where-Object { $_.Name -notmatch 'manifest' } |
         Sort-Object LastWriteTime | Select-Object -Last 1).FullName
Get-Content $path | ConvertFrom-Json | ConvertTo-Json -Depth 4 | more
```

### POINT AT in the JSON

- `assets[0].services` — the 2 ports nmap found, with CPEs.
- `assets[0].cves` — **141 entries**. Say: "Each one is a known CVE for the
  OpenSSH or Apache version exposed on this host."
- `assets[0].misconfigs[0].template_id` — `apache-mod-negotiation-listing`.
  Say: "Real-world finding with a real CWE."
- `assets[0].risk_summary` — one-glance numbers.
- `aggregate_summary.scan_duration_seconds` — proves the timing claim.

### WHAT CAN GO WRONG

- **scanme.nmap.org unreachable** → discovery phase fails. Use the cached
  result file from Recovery scenarios below. Say: "Pulling up an earlier
  run from the same target — the orchestrator always writes one even on
  failure, see the manifest contract."
- **NVD rate-limits / 503** → scan still completes (`status="completed"`)
  but `result.error` mentions NVD. Point at it: "Per-phase failure isolation
  — NVD outage doesn't kill the whole scan, the result surfaces the gap."

### CHEAT SHEET (fallback if you blank)

> "One command, four phases, hash-validated output. Discovery via subfinder
> plus nmap. Misconfig via nuclei. CVE lookup via NVD with a SQLite cache.
> Scoring via the trained XGBoost model over `/predict`. Output is a single
> JSON file with a SHA-256 manifest beside it."

---

## ACT 2 — Same pipeline through the production API (~4 min)

**Goal:** show the same scan running asynchronously through the
production-shape interface.

### SAY (30 seconds)

> "The CLI path is fine for ops. For production, scans run as background
> jobs — `POST /scan` returns immediately with a job ID, the work runs in a
> FastAPI background task, and the caller polls `GET /scan/{job_id}` until
> it's done. Same orchestrator underneath; different surface."

### DO (Terminal B — start a scan)

```powershell
$apiKey = (Get-Content .env | Select-String '^API_KEY=').ToString().Split('=')[1]
$resp = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scan `
  -Headers @{ "X-API-Key" = $apiKey } `
  -ContentType "application/json" `
  -Body '{"target":"scanme.nmap.org"}'
$resp | ConvertTo-Json
$jobId = $resp.job_id
```

### POINT AT in the response

- `job_id` — UUID. Say: "Returned in milliseconds. The actual work hasn't
  started yet."
- `status: "pending"` — Say: "FastAPI's BackgroundTasks dispatched the
  worker after this response went out."
- `created_at` ≈ `updated_at` — Say: "One-millisecond gap. Confirms it's
  truly async."

### DO (Terminal A — show the audit log)

Examiner already sees uvicorn logs in Terminal A. Point at:

- `event=request.start path=/scan` — middleware audit.
- `event=scan.start asset_id=scanme.nmap.org job_id=...` — handler audit.
- `event=request.end path=/scan status=200` — response left.
- `event=scan.job.running job_id=... target=scanme.nmap.org` — background
  worker picked it up.

### DO (Terminal B — poll, ~once every 20 seconds)

```powershell
Invoke-RestMethod -Method Get `
  -Uri "http://127.0.0.1:8000/scan/$jobId" `
  -Headers @{ "X-API-Key" = $apiKey } | ConvertTo-Json -Depth 6
```

Run it 3–4 times across the next ~80 seconds. Say each time:

1. First poll: `status: "running"`. "Discovery phase."
2. Second poll: still `"running"`. Mention NVD: "Per-CPE lookups happening
   under the rate limit."
3. Third or fourth: `status: "completed"` with the full
   `UnifiedScanResult` nested in `result`.

### POINT AT in the completed response

- `result.assets[0].cves[0..3]` — same shape as Act 1's output.
- `result.aggregate_summary.scan_duration_seconds` — should match Act 1's
  ballpark.

### WHAT CAN GO WRONG

- **API not running** → `Invoke-RestMethod` errors with a connection
  refused. Recovery: switch back to the CLI demo from Act 1 and skip the
  rest of Act 2. Say: "The API is the same orchestrator; CLI proves the
  underlying flow."
- **API key wrong** → 401. Recovery: re-read `.env`,
  `$apiKey = $env:API_KEY` if loaded as a process env var.
- **Polling shows status: "failed"** → look at `result.error` and
  `Terminal A` logs. Common cause: NVD timeout. Say: "Per-phase failure
  isolation — discovery succeeded, NVD failed, scan finished with a partial
  result and the error surfaced."

### CHEAT SHEET

> "POST returns a job ID, GET polls. Background-task dispatch. Same
> orchestrator under both. The async pattern is what production needs —
> a 90-second scan can't block an HTTP request."

---

## ACT 3 — Security and MLSecOps controls (~5 min)

**Goal:** show that this is a *secured* pipeline, not just a working one.

### SAY (45 seconds)

> "MLSecOps means security controls live at every stage, not bolted on at
> the end. Five places to look: the GitHub workflow that gates every push,
> the audit log that records every prediction, the rate limit that bounds
> abuse, the SHA-256 manifests that prove provenance, and the non-root
> container the API runs in. I'll show the first four; the container is
> documented in `architecture.md` §3."

### DO (Terminal C — open the security workflow)

```powershell
code .github\workflows\security.yml   # or: more .github\workflows\security.yml
```

### POINT AT

- The five jobs at the top: `secrets` (gitleaks), `sast` (bandit),
  `dependencies` (pip-audit), `container` (trivy + SBOM), `adversarial`
  (ART skeleton).
- Say: "Every push to `main`. Each job has a single responsibility. The
  README documents a real bite from `pip-audit` — it caught CVE-2026-3219
  in pip itself, blocked the deploy, the next commit fixed it."

### DO (Terminal B — trigger /scan and watch the audit stream)

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/scan `
  -Headers @{ "X-API-Key" = $apiKey } `
  -ContentType "application/json" `
  -Body '{"target":"scanme.nmap.org"}' | Out-Null
```

Examiner sees in Terminal A:

- `event=request.start` — middleware audit.
- `event=scan.start` — handler audit.
- (Later) `event=predict asset_id=... n_cves=N max_score=...` — the
  orchestrator's loopback `/predict` call. Say: "Every prediction is
  audit-logged. Asset, CVE count, max score, model version. Forensic
  trace if a score is ever questioned later."

### DO (Terminal B — trigger the rate limit)

`/scan` is capped at 10/minute per API key. Hit it 11 times rapidly:

```powershell
1..11 | ForEach-Object {
  try {
    $r = Invoke-WebRequest -Method Post -Uri http://127.0.0.1:8000/scan `
      -Headers @{ "X-API-Key" = $apiKey } `
      -ContentType "application/json" `
      -Body '{"target":"scanme.nmap.org"}'
    "$_  -> $($r.StatusCode)"
  } catch {
    "$_  -> $([int]$_.Exception.Response.StatusCode)"
  }
}
```

### POINT AT

- Requests 1–10 return `200`.
- Request 11 returns `429`. Say: "Per-API-key bucket. Threat-model.md §5.4
  documents the residual risk — 10/minute is still 600/hour, so phase 2
  adds a global concurrency cap."

### DO (Terminal C — open a manifest)

```powershell
$manifest = Get-ChildItem data\orchestrator\*.manifest.json |
            Sort-Object LastWriteTime | Select-Object -Last 1
Get-Content $manifest.FullName
```

### POINT AT

- `sha256` — Say: "Hex digest of the result file beside it. Same pattern
  as `data/raw/epss-*.manifest.json` — provenance contract is unified
  across every pillar."
- `target`, `status`, `bytes`, `ts` — the rest of the receipt.

### WHAT CAN GO WRONG

- **Rate-limit doesn't trigger** → another test or the previous act burnt
  the budget. Wait 60 seconds and retry, or change the API key for this
  demo only (set a temporary value in `.env` and restart uvicorn).
- **No audit lines appearing** → check Terminal A is the uvicorn process,
  not MLflow. Audit goes to stdout of the uvicorn process.

### CHEAT SHEET

> "Five CI gates on every push. Audit log on every prediction. Rate limit
> per API key. SHA-256 manifest on every artifact. Non-root container.
> Each one is one row in the threat model with mitigation, residual risk,
> and a phase-2 plan."

---

## ACT 4 — Where the ML model fits in (~4 min)

**Goal:** trace one CVE from discovery through to risk score; pre-empt
the obvious "but no high-risk CVEs?" follow-up.

### SAY (30 seconds)

> "I want to close the loop on where the trained model actually lives in
> all this. The orchestrator's job is to *give the model something to
> score*. Discovery finds CPEs; NVD turns CPEs into CVE-IDs; the model
> turns CVE-IDs into risk scores. The model itself is the same XGBoost
> classifier from the original ML pipeline — `/predict` is just called
> internally."

### DO (Terminal C — open the architecture diagram)

```powershell
more docs\architecture.md   # scroll to §1 ASCII diagram
```

### POINT AT

The §1 ASCII diagram. Trace with finger:

1. `apex domain` → `POST /scan` → `orchestrator.run_scan`
2. Three pillars in parallel: discovery, misconfig, NVD CPE→CVE
3. Bottom: `POST /predict (in-process loopback)`
4. Output: `UnifiedScanResult + manifest`

Say: "The seam between the ASM pipeline and the ML pipeline is one HTTP
call. Threat-model §7.5 has the phase-2 plan to swap that for a direct
in-process call."

### DO (Terminal C — find the highest-scoring CVE)

```powershell
$path = (Get-ChildItem data\orchestrator\scanme.nmap.org-*.json |
         Where-Object { $_.Name -notmatch 'manifest' } |
         Sort-Object LastWriteTime | Select-Object -Last 1).FullName
$result = Get-Content $path | ConvertFrom-Json
$result.assets[0].cves |
  Where-Object { $_.risk_score -ne $null } |
  Sort-Object -Property risk_score -Descending |
  Select-Object -First 5 |
  Format-Table cve_id, risk_score, high_risk
```

### POINT AT

- Top row likely **CVE-2006-20001** at `risk_score ≈ 0.46`. Say: "Old
  Apache CVE — 2006, network-facing, affects mod_negotiation, exactly the
  shape of CVE the model was trained to flag. Old CVEs in long-running
  services tend to score high because EPSS data shows they're still being
  exploited."
- All rows show `high_risk: false`. Pre-empt: "Question you're about to
  ask: why is nothing flagged `high_risk=true`? The model uses CVE-ID
  metadata only — year, age, sequence-number-log — not the semantic CVE
  description. It's deliberately conservative; the threshold is at the
  90th percentile of EPSS, and shared-library CVEs sit in the 60–80
  percentile band. Documented in `architecture.md` §4 as the train/serve
  feature parity invariant."

### WHAT CAN GO WRONG

- **No CVE has a risk_score** → Phase 4 scoring failed or was skipped.
  Run `--no-score` would do this; check that the API was up during the
  scan. Recover with the cached file from Recovery scenarios.
- **Examiner pushes hard on "why no high-risk?"** → don't oversell.
  Say: "It's a known limitation. The phase-2 feature set adds CVSS,
  vendor, KEV flag, and product family — that's where high_risk
  predictions become reliable. The architecture supports it; the
  training data and feature engineering for it are open work."

### CHEAT SHEET

> "Discovery finds CPEs. NVD turns CPEs into CVE-IDs. The model turns
> CVE-IDs into risk scores via the same `/predict` endpoint exposed
> publicly. The model uses only CVE-ID metadata today — that's
> deliberately narrow and is the parity-invariant section of the
> architecture doc."

---

## Recovery scenarios

Consolidated list of what to do when things break mid-demo.

- **Live scan fails (any reason).** Use this specific known-good cached
  scan: **`data/orchestrator/scanme.nmap.org-20260506T172848Z.json`** — the
  113-second CLI scan that produced 141 CVEs and 1 misconfig. Verified
  before the viva. Use this path directly if the live demo fails.
- **API died mid-act 2 or 3.** Restart it in Terminal A: `uvicorn
  asm.serving.api:app --host 127.0.0.1 --port 8000`. Job IDs from before
  the restart are gone (in-memory store) — say so explicitly: "Process
  restart loses jobs. Documented limitation, replaced by Redis in phase 2."
- **MLflow died.** API will return 503 on `/predict` and `/scan` will
  fail in phase 4. Restart MLflow. If running short on time, skip to
  Act 4 and use the cached scan file.
- **NVD is down or slow.** A live cold scan can take >60s for NVD alone.
  Either show it patiently and use the time to talk through the rate-limit
  rationale, or switch to the cached scan.
- **scanme.nmap.org down.** Use the cached scan above. Mention that the
  manifest pattern means even *failed* scans leave a forensic trace —
  show a `status="failed"` example if one happens to exist.
- **Terminal A logs scrolling too fast.** Pause uvicorn output with
  `Ctrl+S`, resume with `Ctrl+Q`. Or just don't try to read every line —
  point at the patterns.

---

## Likely Q&A

Six likely faculty questions, with prepared answers. Keep answers ≤60
seconds each — examiners will follow up if they want more.

### Q1. Why XGBoost instead of deep learning?

The features are tabular — CVE year, age, sequence-number-log — three
columns parsed from the CVE-ID string. There's no spatial structure or
sequence to exploit. XGBoost is the dominant algorithm on tabular data of
this shape; training fits on a laptop CPU in seconds. A neural network
would add a GPU dependency and training non-determinism for no measurable
accuracy gain. If we extend to NVD descriptions in phase 2, the natural
step is a sentence-transformer embedding fed *into* XGBoost, not end-to-end
neural.

### Q2. What stops me running this against a host I don't own?

Today: nothing technical. The `target` is validated as a hostname-shaped
string, but there's no allowlist or authorization check. This is
deliberately documented as an MVP limitation — the README explicitly
states "do not point this at hosts you don't own or have written
permission to test." For production, the threat model proposes per-tenant
JWTs scoped to a list of authorized assets. Operationally, today, the
control is the API-key being treated as a sensitive credential by the
operator.

### Q3. How do I know the orchestrator's NVD lookup is accurate?

Two layers. **Today's mitigations:** httpx default TLS verification on
the connection to NVD, the SQLite cache means a previously-seen CPE
returns a known-good result without re-fetching, and the NVD response is
parsed defensively (missing fields drop the row, not crash the scan).
**Residual risk** is documented in threat-model §2.4 — no certificate
pinning, so a corporate MitM proxy or compromised CA can return tampered
responses for new CPEs. Phase-2 mitigation is pinning NVD's certificate
fingerprint and cross-checking sampled results against a second source
like CIRCL CVE-Search.

### Q4. Why didn't you build the AWS deployment?

Scope discipline. The decision was to ship a working local MVP that
exercises *every* MLSecOps control end-to-end, rather than half-build a
production deployment that demonstrates fewer controls. Every control in
the local pipeline — signed model contracts, audit logging, rate limiting,
hash-validated provenance, the security workflow — has a phase-2
counterpart specified in `aws-blueprint.md`. The AWS deployment is the
*delivery mechanism*; the security thesis is what we built. Examiner can
read the blueprint to see exactly what would change.

### Q5. What's the gap between this MVP and production?

Five concrete gaps, all documented as standing items in
`threat-model.md` §9 and `architecture.md` §6:

1. Cosign artifact signing (model + parquet).
2. Durable ScanJob store — Redis or DynamoDB to replace the in-memory
   dict.
3. JWT auth with per-tenant scoping to replace the single shared API key.
4. Evidently distribution-shift monitoring on EPSS ingestion.
5. Full ART adversarial-robustness suite, currently a skeleton.

Plus the AWS infrastructure itself — Terraform, App Runner, ECR, KMS-
encrypted S3, CloudWatch. The blueprint specifies all of it.

### Q6. Can the model be poisoned by adversarial CVE metadata?

In principle, yes — that's the §7.1 training-data poisoning threat. In
practice today, it's narrow because the only training data source is the
public EPSS feed, and the only features the model uses are derived from
the CVE-ID string itself (year, age, sequence-log). An attacker would
have to influence EPSS's underlying scoring methodology — feasible but
out of scope for this system to defend against. The mitigation today is
the SHA-256 manifest, which gives forensic traceability. Phase 2 is
Evidently distribution-shift monitoring at ingestion: the snapshot is
compared to a rolling baseline, and a KS-statistic over threshold alarms
before training. For evasion at *inference* time, today's three-feature
input gives the attacker no input control given a fixed CVE ID — that
threat reactivates when we add CVSS/KEV features in phase 2.

---

**End of script.** Total time including 5 minutes of Q&A: ~21 minutes.
