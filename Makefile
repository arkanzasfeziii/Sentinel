.PHONY: help install lint format test test-cov clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -r requirements.txt

lint: ## Run linter
	ruff check sentinel/ tests/

format: ## Format code
	ruff format sentinel/ tests/

test: ## Run tests
	pytest tests/ -v

test-cov: ## Tests with coverage
	pytest tests/ --cov=sentinel --cov-report=term-missing

clean: ## Remove caches
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
