# Makefile for DLL Analyzer
# Professional development automation

.PHONY: help install install-dev test lint format clean run web docs package

# Default target
help:
	@echo "DLL Analyzer - Professional Development Commands:"
	@echo ""
	@echo "  install      Install the package"
	@echo "  install-dev  Install with development dependencies"
	@echo "  test         Run all tests"
	@echo "  lint         Run code linting"
	@echo "  format       Format code with black"
	@echo "  clean        Clean temporary files"
	@echo "  run          Run the main analyzer"
	@echo "  web          Start web interface"
	@echo "  docs         Generate documentation"
	@echo "  package      Create distribution package"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e ".[dev,web,docs]"
	pre-commit install

# Testing
test:
	python -m pytest tests.py -v
	python tests.py

test-coverage:
	python -m pytest tests.py --cov=. --cov-report=html

# Code quality
lint:
	flake8 *.py
	mypy *.py --ignore-missing-imports

format:
	black *.py
	isort *.py

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache
	rm -rf *.db
	rm -rf *.log

# Running the application
run:
	python dll_analyzer.py

web:
	python web_interface.py

# Documentation
docs:
	sphinx-build -b html docs/ docs/_build/html
	@echo "Documentation available at docs/_build/html/index.html"

# Packaging
package:
	python setup.py sdist bdist_wheel
	@echo "Package created in dist/"

# Development helpers
dev-setup: install-dev
	@echo "Development environment ready!"

check: lint test
	@echo "All checks passed!"

# Quick analysis example
analyze-example:
	python dll_analyzer.py "C:\\Windows\\System32\\kernel32.dll"

# Database operations
init-db:
	python -c "from database import AnalysisDatabase; AnalysisDatabase()"

# Plugin development
create-plugin:
	@echo "Creating plugin template..."
	mkdir -p plugins
	echo 'from plugin_system import AnalysisPlugin\n\nclass CustomPlugin(AnalysisPlugin):\n    @property\n    def name(self):\n        return "custom_plugin"\n    \n    @property\n    def version(self):\n        return "1.0.0"\n    \n    @property\n    def description(self):\n        return "Custom analysis plugin"\n    \n    def analyze(self, pe_file, config):\n        return {"result": "custom_analysis"}' > plugins/custom_plugin.py

# Security audit
security-audit:
	bandit -r . -f json -o security-report.json
	safety check

# Performance testing
benchmark:
	python -m timeit -s "from dll_analyzer import DLLAnalyzer" "DLLAnalyzer('test_file')"
