lint:
	black --check .
	isort -c .
	flake8 .

format:
	black .
	isort .

typecheck:
	mypy --show-error-codes --pretty .

test:
	pytest

all: lint typecheck pytest

.PHONY: typecheck lint format

.DEFAULT_GOAL := all