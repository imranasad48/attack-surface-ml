.PHONY: help install install-dev hooks lint format type test security \
	data train evaluate run-api run-dashboard compose-up compose-down \
	docker-build sbom sign clean

help:
	@echo "Common commands:"
	@echo "  install-dev   Install package + dev/security/dashboard extras"
	@echo "  hooks         Install pre-commit hooks"
	@echo "  lint          Ruff lint"
	@echo "  format        Ruff format"
	@echo "  type          Mypy"
	@echo "  test          Pytest with coverage"
	@echo "  security      Bandit + pip-audit + gitleaks"
	@echo "  data          Run data ingestion stage"
	@echo "  train         Run training stage"
	@echo "  run-api       Start FastAPI server"
	@echo "  run-dashboard Start Streamlit dashboard"
	@echo "  compose-up    Start postgres + mlflow"
	@echo "  sbom          Generate SBOM for current image"
	@echo "  sign          Sign image + model with cosign"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev,security,dashboard]"

hooks:
	pre-commit install
	pre-commit install --hook-type commit-msg

lint:
	ruff check src tests

format:
	ruff format src tests

type:
	mypy src

test:
	pytest

security:
	bandit -c pyproject.toml -r src
	pip-audit
	gitleaks detect --source . --no-banner

data:
	python -m asm.data.ingest

train:
	python -m asm.models.train

evaluate:
	python -m asm.models.evaluate

run-api:
	uvicorn asm.serving.api:app --reload --host 0.0.0.0 --port 8000

run-dashboard:
	streamlit run dashboard/app.py

compose-up:
	docker compose up -d

compose-down:
	docker compose down

docker-build:
	docker build -f docker/Dockerfile.api -t asm-api:dev .

sbom:
	syft asm-api:dev -o cyclonedx-json > sbom-api.json

sign:
	cosign sign --yes asm-api:dev

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
