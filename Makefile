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

NPM          ?= npm
CONSOLE_DIR  ?= console

.PHONY: build
build: ## Build the stamp binary
	$(GO) build -ldflags "$(LDFLAGS)" -o stamp ./cmd/stamp

# The console is a separate stack with a separate toolchain, and `build` does
# not depend on it on purpose: `//go:embed all:dist` matches a tracked
# placeholder, so a Go contributor with no Node installed still gets a working
# binary whose console role explains what is missing. `make build-all` is the
# one that produces the shipped artifact.
.PHONY: console
console: ## Build the console bundle into console/dist
	cd $(CONSOLE_DIR) && $(NPM) ci && $(NPM) run build

.PHONY: console-test
console-test: ## Typecheck the console, run its contract boundary check and its tests
	cd $(CONSOLE_DIR) && $(NPM) ci && $(NPM) test

.PHONY: console-e2e
console-e2e: ## Run the Playwright smoke suite (builder and approval round trips, axe with contrast)
	cd $(CONSOLE_DIR) && $(NPM) ci && $(NPM) run e2e:install && $(NPM) run e2e

.PHONY: console-contract
console-contract: ## Verify the exported public contract and the console's calls against it
	$(GO) test ./internal/api/ -run TestConsoleContract -count=1
	cd $(CONSOLE_DIR) && $(NPM) run check:contract

.PHONY: build-all
build-all: console build ## Build the console bundle and then the binary that embeds it

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

# The benchmark is not part of `land`. It needs a Docker daemon and minutes,
# it reports rather than gates, and its thresholds are per-runner — a developer
# machine's numbers say nothing about CI's and vice versa. Run it when you are
# asking a performance question, and read bench/out/report.md.
#
# `-run '^$$'` keeps the package's own unit tests out of the measured run;
# `-count` is how many times each scenario repeats, and the artifact's spread
# column comes from those repeats.
BENCH_REPEATS ?= 3
BENCH_TIMEOUT ?= 30m

.PHONY: bench
bench: ## Run the check path benchmark, writing bench/out
	cd bench && $(GO) test -run '^$$' -bench . -benchtime=1x \
		-count=$(BENCH_REPEATS) -timeout=$(BENCH_TIMEOUT) .

VERSION ?= 0.1.0

.PHONY: chart
chart: ## Render both Helm topologies into deploy/helm/snapshots
	deploy/helm/render.sh

.PHONY: chart-check
chart-check: ## Fail if the committed Helm snapshots are not what the chart renders
	deploy/helm/render.sh --check

.PHONY: contracts
contracts: ## Check that the three public contracts are documented with a semver version
	scripts/check-contract-versions.sh

.PHONY: release-dryrun
release-dryrun: ## Build the release artifacts locally, publishing nothing
	scripts/release-artifacts.sh --version $(VERSION) --unreleased

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
