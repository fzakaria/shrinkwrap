lint:
	black --check .
	isort -c .
	flake8 .

format:
	black .
	isort .

typecheck:
	mypy --show-error-codes --pretty .


all: lint typecheck

.PHONY: typecheck lint format

.DEFAULT_GOAL := all