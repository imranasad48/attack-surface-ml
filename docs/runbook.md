# Runbook

Operational playbook for common scenarios. Fill in as you encounter them.

## Drift alert fired
1. Check Evidently report for which features drifted.
2. Compare current input distribution to training snapshot (DVC has the hash).
3. If legitimate population shift → trigger retraining via `train.yml` workflow.
4. If suspected poisoning → freeze feed, investigate manifest + source.

## Trivy CRITICAL on new image
1. Read SARIF in GitHub Security tab.
2. Bump base image or pin patched dep version.
3. Re-run security workflow.

## Lost API key
1. Rotate via `.env` + redeploy.
2. Revoke old key in audit log queries.
