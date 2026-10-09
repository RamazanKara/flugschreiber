VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE      ?= flugschreiber
CHART      ?= deploy/helm/flugschreiber
PKG        := github.com/RamazanKara/flugschreiber/internal/version

LDFLAGS := -s -w \
  -X $(PKG).Version=$(VERSION) \
  -X $(PKG).Commit=$(COMMIT) \
  -X $(PKG).Date=$(BUILD_DATE)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build both binaries into ./dist
	@mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/ ./cmd/flugschreiber ./cmd/proxyd

.PHONY: test
test: ## Run every test, with the race detector when cgo is enabled
	@if [ "$$(go env CGO_ENABLED)" = 1 ]; then \
	  go test -race -count=1 ./...; \
	else \
	  echo "CGO_ENABLED=0: running tests without the race detector"; \
	  go test -count=1 ./...; \
	fi

.PHONY: test-short
test-short: ## Run unit tests only, skipping the binary-building acceptance test
	go test -short -count=1 ./...

.PHONY: acceptance
acceptance: ## Run the five-minute demo as a test
	go test -count=1 -v -run TestQuickstartEndToEnd ./test/

.PHONY: overhead
overhead: ## Measure proxy overhead against the mock upstream
	go test -count=1 -v -run TestProxyOverheadStaysUnderBudget ./test/

.PHONY: golden
golden: ## Rewrite the documentation golden files
	go test ./internal/report -update
	@echo "Review the diff before committing: git diff internal/report/testdata"

.PHONY: cover
cover: ## Report test coverage per package
	go test -count=1 -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -20

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: fmt
fmt: ## Format the source
	gofmt -w ./cmd ./internal ./test

.PHONY: fmt-check
fmt-check: ## Check formatting without changing files
	@test -z "$$(gofmt -l ./cmd ./internal ./test)" || { gofmt -l ./cmd ./internal ./test; exit 1; }

.PHONY: staticcheck
staticcheck: ## Run staticcheck through golangci-lint
	golangci-lint run --enable-only staticcheck

.PHONY: vuln
vuln: ## Check for reachable known vulnerabilities
	govulncheck ./...

.PHONY: deps
deps: ## Enforce zero external Go dependencies
	@modules="$$(go list -m all)" && test "$$(printf '%s\n' "$$modules" | wc -l)" -eq 1

.PHONY: fuzz
fuzz: ## Run each parser fuzz target for 30 seconds
	@set -e; for pkg in config openai proxy evidence archive report pdf; do \
	  targets="$$(go test ./internal/$$pkg -list '^Fuzz')"; \
	  for target in $$(printf '%s\n' "$$targets" | awk '/^Fuzz/{print $$1}'); do \
	    go test ./internal/$$pkg -run '^$$' -fuzz "^$$target$$" -fuzztime=30s -parallel=2 -timeout=2m; \
	  done; \
	done

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: check
check: fmt-check deps vet lint staticcheck test vuln build ## Run the local release gate

.PHONY: helm
helm: ## Lint, render and schema check the Helm chart. Needs no cluster
	./deploy/helm/check.sh $(CHART)

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart only
	helm lint $(CHART) --set config.upstream=http://vllm.models.svc:8000

.PHONY: helm-template
helm-template: ## Render the chart with the production example values
	helm template flugschreiber $(CHART) \
	  -f deploy/examples/values/central-production.yaml \
	  --api-versions monitoring.coreos.com/v1

.PHONY: image
image: ## Build the container image
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: demo
demo: ## Run the recorded demo script against a local build
	./scripts/demo.sh

.PHONY: clean
clean: ## Remove build output and local demo state
	rm -rf dist coverage.out reports .demo
