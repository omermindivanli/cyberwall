.PHONY: setup check test lint types imports

setup:
	uv sync --all-groups
	uv run pre-commit install

check: lint types imports test

lint:
	uv run ruff check .

types:
	uv run mypy

imports:
	uv run lint-imports

test:
	uv run coverage run -m pytest -q
	uv run coverage report --fail-under=100 --include='src/cyberwall/core/evaluator.py,src/cyberwall/core/normalize.py'
