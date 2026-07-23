VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE      ?= flugschreiber
PKG        := github.com/flugschreiber/flugschreiber/internal/version

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
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/flugschreiber ./cmd/flugschreiber
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/proxyd ./cmd/proxyd

.PHONY: test
test: ## Run every test with the race detector
	go test -race -count=1 ./...

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

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: check
check: fmt vet test ## Format, vet and test

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
