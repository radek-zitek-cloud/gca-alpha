.PHONY: help install dev test run clean lint

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

# Run tests
test:
	python -m pytest tests/ -v

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

# Run linting
lint:
	flake8 app/
	black --check app/
	isort --check-only app/

# Format code
format:
	black app/
	isort app/

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
