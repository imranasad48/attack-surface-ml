# Threat model (STRIDE for ML pipeline)

A first-pass threat model. Update as the system evolves.

## Spoofing
- Unsigned model artifacts loaded into production
  - Mitigation: cosign signature verified at load time
- Forged API requests
  - Mitigation: API key auth, scoped to per-tenant later

## Tampering
- Poisoned training data slipping past validation
  - Mitigation: schema (pandera) + distribution checks pre-train; signed snapshots
- Modified model file in transit
  - Mitigation: SHA-256 + cosign signature verified before promotion

## Repudiation
- Predictions made without traceability
  - Mitigation: audit log records input hash + model version + timestamp

## Information disclosure
- Secrets in code or logs
  - Mitigation: gitleaks pre-commit + CI; structured logger redacts known fields
- Sensitive feature leakage in model outputs
  - Mitigation: outputs limited to a single risk score, no raw features echoed

## Denial of service
- Unbounded prediction payloads
  - Mitigation: pydantic max_length on cve_ids; FastAPI rate limit middleware (TODO)
- Large data feeds exhausting disk
  - Mitigation: feed size capped per snapshot; manifest tracks bytes

## Elevation of privilege
- Container escape
  - Mitigation: non-root user, slim base, no shell tools in runtime image
- Pipeline runner stealing artifacts
  - Mitigation: GHA permissions: contents:read by default; security-events:write only where needed
