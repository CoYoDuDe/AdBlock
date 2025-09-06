.PHONY: fmt lint test all
fmt:
	ruff check . --fix || true
	black .
lint:
	flake8 .
test:
	pytest -q
all: fmt lint test
