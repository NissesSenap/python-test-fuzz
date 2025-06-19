# Makefile for API Fuzzing Test Suite
# Provides convenient commands for running tests, security scans, and development tasks

.PHONY: help install test test-basic test-comprehensive test-security test-all
.PHONY: security bandit pip-audit lint format clean server server-bg server-stop
.PHONY: reports verify-setup dev-install ci-install
.DEFAULT_GOAL := help

# Variables
PYTHON := python
PIP := pip
VENV_DIR := .venv
REPORTS_DIR := reports
SERVER_PID_FILE := server.pid
API_URL := http://localhost:8000

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)API Fuzzing Test Suite$(NC)"
	@echo "======================="
	@echo ""
	@echo "$(GREEN)Available commands:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(BLUE)Examples:$(NC)"
	@echo "  make install          # Install dependencies"
	@echo "  make test-all         # Run all tests and security scans"
	@echo "  make server-bg test-basic  # Start server and run basic tests"
	@echo "  make reports          # Generate comprehensive reports"

install: ## Install production dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

dev-install: ## Install development dependencies (includes security tools)
	@echo "$(GREEN)Installing development dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install bandit pip-audit pytest-html pytest-json-report pytest-cov safety ruff black isort

ci-install: ## Install CI/CD dependencies
	@echo "$(GREEN)Installing CI/CD dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	$(PIP) install bandit pip-audit pytest-html pytest-json-report pytest-cov pytest-timeout

verify-setup: ## Verify the setup is working
	@echo "$(GREEN)Verifying setup...$(NC)"
	@$(PYTHON) --version
	@$(PIP) --version
	@echo "$(GREEN)✓ Python and pip are working$(NC)"
	@$(PYTHON) -c "import schemathesis; print(f'✓ Schemathesis {schemathesis.__version__} installed')"
	@$(PYTHON) -c "import pytest; print(f'✓ Pytest installed')"
	@$(PYTHON) -c "import requests; print('✓ Requests installed')"
	@echo "$(GREEN)✓ All dependencies verified$(NC)"

# Server Management
server: ## Start the FastAPI server (foreground)
	@echo "$(GREEN)Starting FastAPI server...$(NC)"
	$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

server-bg: ## Start the FastAPI server in background
	@echo "$(GREEN)Starting FastAPI server in background...$(NC)"
	@$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8000 & echo $$! > $(SERVER_PID_FILE)
	@echo "$(YELLOW)Waiting for server to start...$(NC)"
	@timeout 30 bash -c 'until curl -f $(API_URL)/health > /dev/null 2>&1; do sleep 1; done' || (echo "$(RED)Server failed to start$(NC)" && exit 1)
	@echo "$(GREEN)✓ Server is running (PID: $$(cat $(SERVER_PID_FILE)))$(NC)"

server-stop: ## Stop the background FastAPI server
	@if [ -f $(SERVER_PID_FILE) ]; then \
		echo "$(YELLOW)Stopping server (PID: $$(cat $(SERVER_PID_FILE)))...$(NC)"; \
		kill $$(cat $(SERVER_PID_FILE)) 2>/dev/null || true; \
		rm -f $(SERVER_PID_FILE); \
	fi
	@pkill -f "uvicorn main:app" 2>/dev/null || true
	@echo "$(GREEN)✓ Server stopped$(NC)"

server-status: ## Check if the server is running
	@if curl -f $(API_URL)/health > /dev/null 2>&1; then \
		echo "$(GREEN)✓ Server is running and healthy$(NC)"; \
		curl -s $(API_URL)/health | jq . 2>/dev/null || curl -s $(API_URL)/health; \
	else \
		echo "$(RED)✗ Server is not running or unhealthy$(NC)"; \
		exit 1; \
	fi

# Testing
test: test-basic ## Run basic tests (alias for test-basic)

test-basic: ## Run basic API fuzzing tests
	@echo "$(GREEN)Running basic API fuzzing tests...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) -m pytest test_api_fuzz.py::TestAPIFuzzing::test_api_fuzzing_basic \
		-v \
		--tb=short \
		--maxfail=10 \
		--timeout=300 \
		--durations=10

test-comprehensive: ## Run comprehensive API fuzzing tests
	@echo "$(GREEN)Running comprehensive API fuzzing tests...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) -m pytest test_api_fuzz.py::TestAPIFuzzing::test_api_fuzzing_comprehensive \
		-v \
		--tb=short \
		--maxfail=5 \
		--timeout=300 \
		--durations=10

test-specific: ## Run endpoint-specific tests
	@echo "$(GREEN)Running endpoint-specific tests...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) -m pytest \
		test_api_fuzz.py::TestAPIFuzzing::test_users_endpoint_specific \
		test_api_fuzz.py::TestAPIFuzzing::test_products_endpoint_specific \
		test_api_fuzz.py::TestAPIFuzzing::test_orders_creation \
		-v \
		--tb=short \
		--maxfail=5 \
		--timeout=300

test-manual: ## Run manual/traditional tests
	@echo "$(GREEN)Running manual API tests...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) -m pytest \
		test_api_fuzz.py::TestAPIFuzzing::test_root_endpoint \
		test_api_fuzz.py::TestAPIFuzzing::test_health_endpoint \
		test_api_fuzz.py::TestAPIFuzzing::test_create_valid_user \
		test_api_fuzz.py::TestAPIFuzzing::test_create_valid_order \
		-v \
		--tb=short

test-performance: ## Run performance tests
	@echo "$(GREEN)Running performance tests...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) -m pytest test_api_fuzz.py::TestAPIFuzzing::test_api_response_times \
		-v \
		--tb=short \
		--maxfail=3 \
		--timeout=300

test-with-server: server-bg test-basic server-stop ## Start server, run basic tests, stop server

test-all-with-server: server-bg test-all server-stop ## Start server, run all tests, stop server

# Security Scans
security: bandit pip-audit ## Run all security scans

bandit: ## Run bandit security scan
	@echo "$(GREEN)Running bandit security scan...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	bandit -r . -f json -o $(REPORTS_DIR)/bandit-report.json -x .venv,venv,.git || true
	@echo "$(BLUE)Bandit text report:$(NC)"
	bandit -r . -x .venv,venv,.git --severity-level medium || true

pip-audit: ## Run pip-audit dependency vulnerability scan
	@echo "$(GREEN)Running pip-audit vulnerability scan...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	pip-audit --format=json --output=$(REPORTS_DIR)/pip-audit-report.json || true
	@echo "$(BLUE)Vulnerability report:$(NC)"
	pip-audit --format=columns || true

safety: ## Run safety dependency scan (alternative to pip-audit)
	@echo "$(GREEN)Running safety dependency scan...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	safety check --json --output $(REPORTS_DIR)/safety-report.json || true
	safety check || true

# Code Quality
lint: ## Run code linting
	@echo "$(GREEN)Running code linting...$(NC)"
	@if command -v ruff > /dev/null; then \
		ruff check . || true; \
	else \
		echo "$(YELLOW)ruff not installed, skipping lint$(NC)"; \
	fi

format: ## Format code
	@echo "$(GREEN)Formatting code...$(NC)"
	@if command -v black > /dev/null; then \
		black . --line-length 100; \
	else \
		echo "$(YELLOW)black not installed, skipping format$(NC)"; \
	fi
	@if command -v isort > /dev/null; then \
		isort . --profile black; \
	else \
		echo "$(YELLOW)isort not installed, skipping import sorting$(NC)"; \
	fi

# Reports
reports: ## Generate comprehensive test and security reports
	@echo "$(GREEN)Generating comprehensive reports...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	
	@echo "$(BLUE)Running tests with coverage and HTML report...$(NC)"
	$(PYTHON) -m pytest test_api_fuzz.py::TestAPIFuzzing::test_api_fuzzing_basic \
		--html=$(REPORTS_DIR)/pytest-report.html \
		--json-report --json-report-file=$(REPORTS_DIR)/pytest-results.json \
		--cov=. --cov-report=html:$(REPORTS_DIR)/coverage \
		--cov-report=json:$(REPORTS_DIR)/coverage.json \
		-v || true
	
	@echo "$(BLUE)Running security scans...$(NC)"
	@$(MAKE) security
	
	@echo "$(BLUE)Generating PR output...$(NC)"
	$(PYTHON) generate_pr_output.py summary $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json || true
	$(PYTHON) generate_pr_output.py comment $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json || true
	
	@echo "$(GREEN)✓ Reports generated in $(REPORTS_DIR)/$(NC)"
	@echo "$(BLUE)Available reports:$(NC)"
	@ls -la $(REPORTS_DIR)/ 2>/dev/null || true

test-all: test-basic test-comprehensive test-specific test-manual test-performance security ## Run all tests and security scans

# CI/CD Commands
ci-test: ## Run tests suitable for CI/CD
	@echo "$(GREEN)Running CI tests...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) -m pytest test_api_fuzz.py::TestAPIFuzzing::test_api_fuzzing_basic \
		--json-report --json-report-file=$(REPORTS_DIR)/pytest-results.json \
		--timeout=600 \
		--maxfail=10 \
		--tb=short \
		-v

ci-security: ## Run security scans for CI/CD
	@echo "$(GREEN)Running CI security scans...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	@$(MAKE) bandit
	@$(MAKE) pip-audit

ci-reports: ## Generate CI reports
	@echo "$(GREEN)Generating CI reports...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	@$(MAKE) ci-test || true
	@$(MAKE) ci-security || true
	$(PYTHON) generate_pr_output.py summary $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json || true

# Development helpers
clean: ## Clean up generated files and reports
	@echo "$(GREEN)Cleaning up...$(NC)"
	rm -rf $(REPORTS_DIR)/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf __pycache__/
	rm -rf *.pyc
	rm -rf .ruff_cache/
	rm -f $(SERVER_PID_FILE)
	rm -f pr-comment.md
	@echo "$(GREEN)✓ Cleanup completed$(NC)"

debug: ## Show debug information
	@echo "$(BLUE)Debug Information$(NC)"
	@echo "=================="
	@echo "Python: $(PYTHON)"
	@echo "Pip: $(PIP)"
	@echo "Working directory: $(PWD)"
	@echo "Reports directory: $(REPORTS_DIR)"
	@echo "Server PID file: $(SERVER_PID_FILE)"
	@echo "API URL: $(API_URL)"
	@echo ""
	@echo "$(BLUE)Environment:$(NC)"
	@env | grep -E "(PYTHON|PIP|PATH)" | head -5
	@echo ""
	@echo "$(BLUE)Files:$(NC)"
	@ls -la *.py 2>/dev/null || echo "No Python files found"

# Quick start for new developers
quickstart: dev-install verify-setup ## Quick setup for new developers
	@echo ""
	@echo "$(GREEN)✓ Quick start completed!$(NC)"
	@echo ""
	@echo "$(BLUE)Next steps:$(NC)"
	@echo "1. Start the server: $(YELLOW)make server-bg$(NC)"
	@echo "2. Run basic tests: $(YELLOW)make test-basic$(NC)"
	@echo "3. Run all tests: $(YELLOW)make test-all$(NC)"
	@echo "4. Generate reports: $(YELLOW)make reports$(NC)"
	@echo "5. Stop the server: $(YELLOW)make server-stop$(NC)"
	@echo ""
	@echo "$(BLUE)Or run everything at once:$(NC)"
	@echo "$(YELLOW)make test-all-with-server$(NC)"
