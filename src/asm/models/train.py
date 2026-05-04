"""Train a CVE risk-classifier from EPSS data. Logs to MLflow with full provenance."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import mlflow
import mlflow.xgboost
import numpy as np
import pandas as pd
import structlog
import xgboost as xgb
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from asm.config import get_settings

log = structlog.get_logger()

DATA = Path("data/processed/epss.parquet")
HIGH_RISK_PERCENTILE = 0.90  # top 10% by EPSS = "high risk"
RANDOM_STATE = 42


def _git_sha() -> str:
    """Best-effort git commit sha for provenance. Returns 'unknown' if not a repo yet."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _data_sha256(path: Path) -> str:
    """Hash the training file. Pins exact data to exact run."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Engineer cheap features from a CVE id + EPSS percentile.

    The label is 'high risk' = top 10% by EPSS score. We DROP the raw EPSS score
    from features (otherwise the model trivially predicts it). Features are CVE
    metadata only — year, id magnitude — so the model learns a useful prior even
    for fresh CVEs that don't have an EPSS score yet.
    """
    cve_re = re.compile(r"^CVE-(\d{4})-(\d+)$")
    parsed = df["cve"].str.extract(cve_re)
    parsed.columns = ["year", "seq"]
    parsed["year"] = parsed["year"].astype(int)
    parsed["seq"] = parsed["seq"].astype(int)

    features = pd.DataFrame(
        {
            "cve_year": parsed["year"],
            "cve_age_years": datetime.now(UTC).year - parsed["year"],
            "cve_seq_log": np.log1p(parsed["seq"]),
        }
    )
    label = (df["epss"] >= df["epss"].quantile(HIGH_RISK_PERCENTILE)).astype(int)
    return features, label


def main() -> None:
    settings = get_settings()
    mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
    mlflow.set_experiment("risk-prioritization")

    log.info("train.load", path=str(DATA))
    df = pd.read_parquet(DATA)
    data_hash = _data_sha256(DATA)
    git_sha = _git_sha()

    X, y = build_features(df)  # noqa: N806  # ML convention (sklearn/xgboost)
    X_train, X_test, y_train, y_test = train_test_split(  # noqa: N806
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    params = {
        "n_estimators": 200,
        "max_depth": 5,
        "learning_rate": 0.1,
        "objective": "binary:logistic",
        "eval_metric": "aucpr",
        "random_state": RANDOM_STATE,
        "n_jobs": -1,
    }

    with mlflow.start_run() as run:
        # Provenance: every run is traceable to exact data + exact code
        mlflow.set_tag("data.sha256", data_hash)
        mlflow.set_tag("git.sha", git_sha)
        mlflow.set_tag("data.rows", len(df))
        mlflow.log_params(params)
        mlflow.log_param("high_risk_percentile", HIGH_RISK_PERCENTILE)

        model = xgb.XGBClassifier(**params)
        model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

        # Evaluate
        proba = model.predict_proba(X_test)[:, 1]
        preds = (proba >= 0.5).astype(int)
        roc_auc = roc_auc_score(y_test, proba)
        pr_auc = average_precision_score(y_test, proba)

        mlflow.log_metric("roc_auc", roc_auc)
        mlflow.log_metric("pr_auc", pr_auc)
        mlflow.log_metric("test_size", len(y_test))
        mlflow.log_metric("positive_rate", float(y_test.mean()))

        report = classification_report(y_test, preds, output_dict=True, zero_division=0)
        mlflow.log_dict(report, "classification_report.json")

        # Save metrics for downstream gating
        Path("metrics").mkdir(exist_ok=True)
        Path("metrics/train.json").write_text(
            json.dumps(
                {"roc_auc": roc_auc, "pr_auc": pr_auc, "data_sha256": data_hash},
                indent=2,
            )
        )

        # Log model with input example so MLflow infers the signature
        mlflow.xgboost.log_model(
            model,
            name="model",
            input_example=X_train.head(3),
            registered_model_name="cve-risk-classifier",
        )

        log.info(
            "train.done",
            run_id=run.info.run_id,
            roc_auc=round(roc_auc, 4),
            pr_auc=round(pr_auc, 4),
            data_sha256=data_hash[:16],
        )


if __name__ == "__main__":
    main()
