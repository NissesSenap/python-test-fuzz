# Simplified Makefile for Security and Quality Checks

.PHONY: help bandit pip-audit ruff zap-scan zap-baseline zap-start zap-stop zap-status verify-reports all clean
.DEFAULT_GOAL := help

# Variables
PYTHON := python
REPORTS_DIR := reports

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show available commands
	@echo "$(BLUE)Security and Quality Tools$(NC)"
	@echo "=========================="
	@echo ""
	@echo "$(GREEN)Available commands:$(NC)"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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

ruff: ## Run ruff code linting
	@echo "$(GREEN)Running ruff code linting...$(NC)"
	@if command -v ruff > /dev/null; then \
		ruff check . || true; \
	else \
		echo "$(YELLOW)ruff not installed, please install it first$(NC)"; \
		exit 1; \
	fi

zap-start: ## Start ZAP daemon for DAST scanning
	@echo "$(GREEN)Starting ZAP daemon...$(NC)"
	./zap-manage.sh start

zap-stop: ## Stop ZAP daemon
	@echo "$(GREEN)Stopping ZAP daemon...$(NC)"
	./zap-manage.sh stop

zap-status: ## Check ZAP daemon status
	@echo "$(GREEN)Checking ZAP status...$(NC)"
	./zap-manage.sh status

zap-scan: zap-start ## Run ZAP DAST scan against the API
	@echo "$(GREEN)Running ZAP DAST scan...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	@echo "$(BLUE)Starting FastAPI server for scanning...$(NC)"
	@$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8000 &
	@echo $$! > server.pid
	@echo "$(BLUE)Waiting for API to be ready...$(NC)"
	@timeout 30 bash -c 'until curl -f http://localhost:8000/health > /dev/null 2>&1; do sleep 1; done' || (echo "$(RED)API failed to start$(NC)" && exit 1)
	@echo "$(BLUE)Ensuring ZAP daemon is running...$(NC)"
	@./zap-manage.sh apiscan http://localhost:8000 || true
	@echo "$(BLUE)Stopping FastAPI server...$(NC)"
	@if [ -f server.pid ]; then kill $$(cat server.pid) || true; rm server.pid; fi
	@pkill -f "uvicorn main:app" || true
	@echo "$(GREEN)✓ ZAP DAST scan completed$(NC)"

zap-baseline: ## Run ZAP baseline scan (standalone container)
	@echo "$(GREEN)Running ZAP baseline scan...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	@echo "$(BLUE)Starting FastAPI server for scanning...$(NC)"
	@$(PYTHON) -m uvicorn main:app --host 0.0.0.0 --port 8000 &
	@echo $$! > server.pid
	@echo "$(BLUE)Waiting for API to be ready...$(NC)"
	@timeout 30 bash -c 'until curl -f http://localhost:8000/health > /dev/null 2>&1; do sleep 1; done' || (echo "$(RED)API failed to start$(NC)" && exit 1)
	@echo "$(BLUE)Running ZAP baseline scan...$(NC)"
	@if command -v docker > /dev/null; then \
		docker run -v $(PWD)/$(REPORTS_DIR):/zap/wrk/:rw -t zaproxy/zap-baseline:latest \
			zap-baseline.py -t http://host.docker.internal:8000 \
			-J zap-report.json \
			-r zap-report.html \
			-I || true; \
	else \
		echo "$(YELLOW)Docker not available for baseline scan$(NC)"; \
	fi
	@echo "$(BLUE)Stopping FastAPI server...$(NC)"
	@if [ -f server.pid ]; then kill $$(cat server.pid) || true; rm server.pid; fi
	@pkill -f "uvicorn main:app" || true
	@echo "$(GREEN)✓ ZAP baseline scan completed$(NC)"

verify-reports: ## Run generate_pr_output.py to verify report generation
	@echo "$(GREEN)Verifying report generation...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) generate_pr_output.py summary $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json $(REPORTS_DIR)/bandit-report.json $(REPORTS_DIR)/zap-report.json || true
	$(PYTHON) generate_pr_output.py comment $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json $(REPORTS_DIR)/bandit-report.json $(REPORTS_DIR)/zap-report.json || true
	@echo "$(GREEN)✓ Report verification completed$(NC)"

all: bandit pip-audit ruff zap-scan verify-reports ## Run all security scans, linting, and report verification

clean: ## Clean up generated reports
	@echo "$(GREEN)Cleaning up reports...$(NC)"
	rm -rf $(REPORTS_DIR)/
	rm -f pr-comment.md
	@echo "$(GREEN)✓ Cleanup completed$(NC)"
