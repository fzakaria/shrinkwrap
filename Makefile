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

clean:
	rm -f *_stamped

.PHONY: typecheck lint format

.DEFAULT_GOAL := all
