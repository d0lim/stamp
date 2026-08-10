GO           ?= go
GOLANGCI     ?= golangci-lint
GOVULNCHECK  ?= golang.org/x/vuln/cmd/govulncheck@latest
BUILD_TAGS   ?= m1deps
LDFLAGS      ?= -X main.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the stamp binary
	$(GO) build -ldflags "$(LDFLAGS)" -o stamp ./cmd/stamp

.PHONY: fmt
fmt: ## Rewrite files with gofmt
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any file needs gofmt
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "these files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet
	$(GO) vet -tags $(BUILD_TAGS) ./...

.PHONY: lint
lint: ## Run golangci-lint
	@command -v $(GOLANGCI) >/dev/null 2>&1 || { \
		echo "golangci-lint not found."; \
		echo "install: https://golangci-lint.run/welcome/install/"; \
		echo "it is a merge gate, so this is a failure rather than a skip."; \
		exit 1; \
	}
	$(GOLANGCI) run

.PHONY: test
test: ## Run the test suite with the race detector
	$(GO) test -race ./...

.PHONY: vulncheck
vulncheck: ## Scan dependencies for known vulnerabilities
	$(GO) run $(GOVULNCHECK) ./...

# `land` is the local stand-in for branch protection. This repository is a
# private free-plan repo, where required status checks are unavailable, so the
# merge gates in the plan's landing strategy are convention rather than
# enforcement. Running them from a pre-push hook is the one mechanism
# available before the repository goes public.
.PHONY: land
land: fmt-check vet lint test vulncheck ## Run every gate a PR must pass before it lands
	@echo "land: all gates passed"

.PHONY: hooks
hooks: ## Point git at the tracked hooks directory
	git config core.hooksPath .githooks
	@echo "hooks: core.hooksPath set to .githooks"

.PHONY: clean
clean: ## Remove build output
	rm -f stamp
	$(GO) clean -testcache
