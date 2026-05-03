# Attack Surface ML

ML-driven vulnerability prioritization with an MLSecOps pipeline.

Predicts exploitation risk for assets given their CVEs, EPSS scores, and KEV
status. The pipeline itself is hardened end-to-end: signed artifacts, SBOMs,
schema-validated data, adversarial robustness checks, and audit logging.

## Architecture

Four-stage ML pipeline (data → training → registry → serving) with parallel
security controls at every stage. See `docs/architecture.md`.

## Quickstart

```bash
# 1. Clone, then install
make install-dev

# 2. Wire up pre-commit hooks
make hooks

# 3. Bring up local stack (postgres + mlflow)
make compose-up

# 4. Pull data, train baseline model
make data
make train

# 5. Run API + dashboard
make run-api          # http://localhost:8000
make run-dashboard    # http://localhost:8501
```

## Security tooling

| Concern         | Tool                                     |
|-----------------|------------------------------------------|
| Secret scanning | gitleaks (pre-commit + CI)               |
| Python SAST     | bandit                                   |
| Dep vulns       | pip-audit                                |
| Container scan  | trivy                                    |
| SBOM            | syft                                     |
| Artifact sign   | cosign                                   |
| Adv. robustness | adversarial-robustness-toolbox           |
| Data validation | pandera                                  |
| Drift           | evidently                                |

Run everything: `make security`.

## License

MIT
