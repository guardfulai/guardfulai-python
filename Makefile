.DEFAULT_GOAL := help
.PHONY: help setup check package-check
help:
	@echo 'setup: explicit dependency install; check: offline checks; package-check: offline artifacts and clean installs'
setup:
	uv sync --frozen
	uv run --frozen --no-sync python scripts/prepare_package_cache.py
check:
	uv run --frozen --no-sync ruff check .
	uv run --frozen --no-sync ruff format --check .
	uv run --frozen --no-sync mypy
	uv run --frozen --no-sync pytest
	uv run --frozen --no-sync python scripts/package_acceptance.py --audit-only
package-check:
	uv run --frozen --no-sync python scripts/package_acceptance.py
	uv run --frozen --no-sync twine check --strict dist/*.whl dist/*.tar.gz
