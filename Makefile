# Simplified Makefile for Security and Quality Checks

.PHONY: help bandit pip-audit ruff verify-reports all clean
.DEFAULT_GOAL := help

# Variables
PYTHON := python
REPORTS_DIR := reports

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
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

verify-reports: ## Run generate_pr_output.py to verify report generation
	@echo "$(GREEN)Verifying report generation...$(NC)"
	@mkdir -p $(REPORTS_DIR)
	$(PYTHON) generate_pr_output.py summary $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json $(REPORTS_DIR)/bandit-report.json || true
	$(PYTHON) generate_pr_output.py comment $(REPORTS_DIR)/pytest-results.json $(REPORTS_DIR)/pip-audit-report.json $(REPORTS_DIR)/bandit-report.json || true
	@echo "$(GREEN)✓ Report verification completed$(NC)"

all: bandit pip-audit ruff verify-reports ## Run all security scans, linting, and report verification

clean: ## Clean up generated reports
	@echo "$(GREEN)Cleaning up reports...$(NC)"
	rm -rf $(REPORTS_DIR)/
	rm -f pr-comment.md
	@echo "$(GREEN)✓ Cleanup completed$(NC)"
