BINARY_NAME=dnsfuck
MODULE=github.com/m5rcel-vibecodes/dnsfuck
VERSION ?= 1.0.0
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS=-ldflags "-s -w -X $(MODULE)/pkg/cli.Version=$(VERSION) -X $(MODULE)/pkg/cli.Commit=$(COMMIT) -X $(MODULE)/pkg/cli.BuildDate=$(BUILD_DATE)"

.PHONY: all build clean test test-race lint install cross-build help

all: lint test build

build:
	@echo "==> Building $(BINARY_NAME)..."
	@mkdir -p bin
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

install:
	@echo "==> Installing $(BINARY_NAME) to \$$GOPATH/bin..."
	CGO_ENABLED=0 go install $(LDFLAGS) ./cmd/$(BINARY_NAME)

test:
	@echo "==> Running tests..."
	go test -v ./...

test-race:
	@echo "==> Running tests with race detector..."
	go test -v -race ./...

lint:
	@echo "==> Running vet and format checks..."
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Unformatted files found. Run 'gofmt -w .'" && exit 1)

clean:
	@echo "==> Cleaning artifacts..."
	@rm -rf bin dist

cross-build: clean
	@echo "==> Building cross-platform release binaries..."
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64  ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64  ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/$(BINARY_NAME)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-arm64.exe ./cmd/$(BINARY_NAME)
	@echo "==> Binaries generated in dist/"

help:
	@echo "Available targets:"
	@echo "  build        Compile binary to bin/$(BINARY_NAME)"
	@echo "  install      Install binary to \$$GOPATH/bin"
	@echo "  test         Run unit tests"
	@echo "  test-race    Run unit tests with race detection"
	@echo "  lint         Run static analysis and formatting check"
	@echo "  cross-build  Build for Linux, macOS, and Windows (amd64/arm64)"
	@echo "  clean        Remove compiled binaries"
