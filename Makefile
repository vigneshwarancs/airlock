BINARY  := airlock
PKG     := ./...
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.Version=$(VERSION)

.DEFAULT_GOAL := check

.PHONY: check
check: fmt-check vet test ## fmt, vet and test — run this before pushing

.PHONY: build
build: ## build the binary into ./bin
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/airlock

.PHONY: install
install: ## install the binary into GOPATH/bin
	go install -ldflags "$(LDFLAGS)" ./cmd/airlock

.PHONY: test
test: ## run the full test suite with the race detector
	go test -race -count=1 $(PKG)

.PHONY: test-short
test-short: ## run tests without the race detector
	go test $(PKG)

.PHONY: cover
cover: ## report per-package coverage
	go test -coverprofile=coverage.out $(PKG)
	go tool cover -func=coverage.out | tail -20

.PHONY: bench
bench: ## run benchmarks for the hot path
	go test -run '^$$' -bench . -benchmem ./internal/rewrite/ ./internal/detect/

.PHONY: vet
vet:
	go vet $(PKG)

.PHONY: fmt
fmt: ## format all Go files
	gofmt -w ./cmd ./internal

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l ./cmd ./internal); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: run
run: build ## start the gateway using ./airlock.yaml
	./bin/$(BINARY) run --policy airlock.yaml

.PHONY: demo
demo: build ## show what the policy would do to the sample text
	@[ -f airlock.yaml ] || ./bin/$(BINARY) init --out airlock.yaml
	@printf 'Refund Priya Raghavan (priya.r@acme.co), order AC-88412, card 4111 1111 1111 1111, uid 2345 6789 0124, emp EMP-004213.\n' \
		| ./bin/$(BINARY) scan --policy airlock.yaml

.PHONY: docker-build
docker-build: ## build the container image
	docker build -t $(BINARY):$(VERSION) .

.PHONY: docker-test
docker-test: ## run the test suite inside the build image
	docker build --target test .

.PHONY: clean
clean:
	rm -rf bin coverage.out

.PHONY: help
help: ## list targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
