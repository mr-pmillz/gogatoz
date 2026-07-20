SHELL := /bin/bash

GO ?= go
PKGS := $(shell $(GO) list ./...)
TPARSE := $(shell command -v tparse 2>/dev/null)
GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null)
COVER_PROFILE := coverage.out
COVER_DIR := coverage

TEST_FLAGS ?= -covermode=atomic -coverprofile=coverage/coverage.out
RACE_FLAGS ?= -race -count=1
LINT_FLAGS ?= --config ./.golangci-lint.yml --timeout=10m -v

.DEFAULT_GOAL := help

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*##' Makefile | awk 'BEGIN {FS = ":.*## "}; {printf "  %-22s %s\n", $$1, $$2}'

lint: ## Run golangci-lint on the project
ifndef GOLANGCI_LINT
	@echo "golangci-lint not found. Install with: make tools" && exit 2
endif
	@$(GOLANGCI_LINT) run $(LINT_FLAGS)

test: ## Run unit tests (uses tparse if available)
ifdef TPARSE
	@set -o pipefail; $(GO) test $(TEST_FLAGS) -json ./... | $(TPARSE) -all
else
	@$(GO) test $(TEST_FLAGS) ./...
endif

test-race: ## Run tests with race detector (uses tparse if available)
ifdef TPARSE
	@set -o pipefail; $(GO) test $(RACE_FLAGS) -json ./... | $(TPARSE) -all
else
	@$(GO) test $(RACE_FLAGS) ./...
endif

cover: ## Run tests with coverage and show summary (uses tparse if available)
	@mkdir -p $(COVER_DIR)
ifdef TPARSE
	@set -o pipefail; $(GO) test -cover -coverprofile=${COVER_DIR}/$(COVER_PROFILE) -json ./... | $(TPARSE) -all
else
	@$(GO) test -cover -coverprofile=${COVER_DIR}/$(COVER_PROFILE) ./...
endif
	@$(GO) tool cover -func=${COVER_DIR}/$(COVER_PROFILE) | tail -n1

cover-html: cover ## Generate HTML coverage report in coverage/coverage.html
	@$(GO) tool cover -html=${COVER_DIR}/$(COVER_PROFILE) -o $(COVER_DIR)/coverage.html
	@echo "Open $(COVER_DIR)/coverage.html in your browser."

fmt: ## Format code with go fmt
	@$(GO) fmt ./...

vet: ## Run go vet
	@$(GO) vet ./...

tidy: ## Ensure go.mod/go.sum are tidy
	@$(GO) mod tidy

tools: ## Install developer tools (tparse, golangci-lint)
	@$(GO) install github.com/mfridman/tparse@latest
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

ci: fmt vet lint test ## Run a basic CI pipeline locally

bench: ## Run benchmarks
	@$(GO) test -bench=. -benchmem -run=^$$ ./pkg/pipeline/... ./pkg/analyze/... ./pkg/enumerate/...

test-e2e: ## Run E2E tests against live GitLab (accepts GITLAB_TOKEN, TEST_GITLAB_URL, TEST_RUNNER_TAG env vars)
	@TEST_API_PAT="$${TEST_API_PAT:-$$GITLAB_TOKEN}" TEST_GITLAB_URL="$${TEST_GITLAB_URL}" TEST_RUNNER_TAG="$${TEST_RUNNER_TAG}" $(GO) test -tags e2e -v -count=1 -timeout 300s ./e2e/...

.PHONY: help lint test test-race cover cover-html fmt vet tidy tools ci bench test-e2e


# Generate Cobra command reference into docs/cmd
.PHONY: docs-cmd
docs-cmd: ## Generate CLI command docs into docs/cmd
	@$(GO) run ./cmd/gen-docs

# Documentation site (Astro Starlight) — requires Node >= 18.20.8 (see docs/.nvmrc)
DOCS_NODE := $(shell . "$$HOME/.nvm/nvm.sh" 2>/dev/null && nvm which 24 2>/dev/null || which node)
.PHONY: docs-dev docs-build docs-preview
docs-dev: ## Start docs dev server
	@cd docs && PATH="$$(dirname $(DOCS_NODE)):$$PATH" npm run dev
docs-build: ## Build docs site
	@cd docs && PATH="$$(dirname $(DOCS_NODE)):$$PATH" npm run build
docs-preview: ## Preview built docs site
	@cd docs && PATH="$$(dirname $(DOCS_NODE)):$$PATH" npm run preview

