lint:
	poetry run black --check .
	poetry run isort -c .
	poetry run flake8 .

format:
	poetry run black .
	poetry run isort .

typecheck:
	poetry run mypy --show-error-codes --pretty .


all: lint typecheck

.PHONY: typecheck lint format

.DEFAULT_GOAL := all