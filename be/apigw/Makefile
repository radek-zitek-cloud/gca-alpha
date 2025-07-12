.PHONY: help install dev test run clean lint format check-format check-lint check-types test-unit test-integration test-quick test-coverage test-watch test-debug test-parallel test-specific test-marker test-deps qa check-all validate ci-test ci-setup

# Default target
help:
	@echo "Available targets:"
	@echo "  install     Install dependencies"
	@echo "  dev         Install development dependencies"
	@echo "  test        Run tests"
	@echo "  run         Run the application"
	@echo "  clean       Clean cache files"
	@echo "  lint        Run linting"

# Install base dependencies
install:
	pip install -r requirements/base.txt

# Install development dependencies
dev:
	pip install -r requirements/base.txt
	pip install -r requirements/development.txt

# Run the application
run:
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Run in production mode
run-prod:
	uvicorn app.main:app --host 0.0.0.0 --port 8000

# Clean cache files
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +

# Create development requirements file if it doesn't exist
requirements/development.txt:
	touch requirements/development.txt
	echo "# Development dependencies" > requirements/development.txt
	echo "-r base.txt" >> requirements/development.txt
	echo "pytest>=7.0.0" >> requirements/development.txt
	echo "pytest-asyncio>=0.21.0" >> requirements/development.txt
	echo "black>=22.0.0" >> requirements/development.txt
	echo "flake8>=4.0.0" >> requirements/development.txt
	echo "isort>=5.0.0" >> requirements/development.txt

# Testing targets
test: ## Run all tests
	python scripts/run_tests.py --type all

test-unit: ## Run unit tests only
	python scripts/run_tests.py --type unit

test-integration: ## Run integration tests only
	python scripts/run_tests.py --type integration

test-quick: ## Run quick tests (exclude slow tests)
	python scripts/run_tests.py --type quick

test-coverage: ## Run tests with coverage report
	python scripts/run_tests.py --coverage --html-report

test-watch: ## Run tests in watch mode (requires pytest-watch)
	ptw -- --tb=short

test-debug: ## Run tests with detailed output for debugging
	python scripts/run_tests.py --verbose --failfast --no-cov

test-parallel: ## Run tests in parallel
	python scripts/run_tests.py --parallel

test-specific: ## Run specific test file (usage: make test-specific FILE=test_file.py)
	python scripts/run_tests.py --file $(FILE)

test-marker: ## Run tests with specific marker (usage: make test-marker MARKER=slow)
	python scripts/run_tests.py --marker $(MARKER)

test-deps: ## Install test dependencies
	python scripts/run_tests.py --install-deps

# Linting and code quality
lint: ## Run linting with flake8
	flake8 app tests scripts

format: ## Format code with black and isort
	black app tests scripts
	isort app tests scripts

check-format: ## Check if code formatting is correct
	black --check app tests scripts
	isort --check-only app tests scripts

check-lint: ## Check linting without fixing
	flake8 app tests scripts

check-types: ## Run type checking with mypy (if available)
	-mypy app --ignore-missing-imports

# Quality assurance
check-all: check-format check-lint test-coverage ## Run all checks and tests

qa: check-all ## Alias for check-all

validate: ## Validate project structure and configuration
	@echo "🔍 Validating project structure..."
	@test -f pyproject.toml || (echo "❌ Missing pyproject.toml" && exit 1)
	@test -d app || (echo "❌ Missing app directory" && exit 1)
	@test -d tests || (echo "❌ Missing tests directory" && exit 1)
	@test -d config || (echo "❌ Missing config directory" && exit 1)
	@echo "✅ Project structure is valid"

# Continuous Integration helpers
ci-setup: ## Set up CI environment
	pip install -e .[dev]
	python scripts/run_tests.py --install-deps

ci-test: ## Run tests in CI environment
	python scripts/run_tests.py --type all --coverage --verbose
