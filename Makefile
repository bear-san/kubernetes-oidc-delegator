.PHONY: all build clean test lint fmt help run docker-build docker-push deploy

# Variables
BINARY_NAME=kubernetes-oidc-delegator
DOCKER_IMAGE=kubernetes-oidc-delegator
DOCKER_TAG=latest
GO=go
GOFLAGS=-v
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[0;33m
NC=\033[0m # No Color

all: lint test build ## Run lint, test, and build

build: ## Build the binary
	@echo "${GREEN}Building binary...${NC}"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build $(GOFLAGS) \
		-o $(BINARY_NAME) cmd/server/main.go
	@echo "${GREEN}Build complete: $(BINARY_NAME)${NC}"

clean: ## Remove build artifacts
	@echo "${YELLOW}Cleaning...${NC}"
	@rm -f $(BINARY_NAME)
	@rm -f $(BINARY_NAME)-*
	@rm -f coverage.out
	@echo "${GREEN}Clean complete${NC}"

test: ## Run tests
	@echo "${GREEN}Running tests...${NC}"
	$(GO) test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo "${GREEN}Tests complete${NC}"

test-coverage: test ## Run tests and show coverage
	@echo "${GREEN}Generating coverage report...${NC}"
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "${GREEN}Coverage report generated: coverage.html${NC}"

lint: ## Run golangci-lint
	@echo "${GREEN}Running linter...${NC}"
	@if ! which golangci-lint > /dev/null; then \
		echo "${YELLOW}Installing golangci-lint...${NC}"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v2.5.0; \
	fi
	golangci-lint run --timeout 5m ./...
	@echo "${GREEN}Lint complete${NC}"

fmt: ## Format code
	@echo "${GREEN}Formatting code...${NC}"
	$(GO) fmt ./...
	goimports -w -local github.com/bear-san/kubernetes-oidc-delegator .
	@echo "${GREEN}Format complete${NC}"

vet: ## Run go vet
	@echo "${GREEN}Running go vet...${NC}"
	$(GO) vet ./...
	@echo "${GREEN}Vet complete${NC}"

mod-tidy: ## Run go mod tidy
	@echo "${GREEN}Tidying modules...${NC}"
	$(GO) mod tidy
	@echo "${GREEN}Mod tidy complete${NC}"

mod-download: ## Download dependencies
	@echo "${GREEN}Downloading dependencies...${NC}"
	$(GO) mod download
	@echo "${GREEN}Dependencies downloaded${NC}"

run: ## Run the application locally
	@echo "${GREEN}Running application...${NC}"
	$(GO) run cmd/server/main.go --server-host http://localhost:8080 --port 8080

docker-build: ## Build Docker image
	@echo "${GREEN}Building Docker image...${NC}"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "${GREEN}Docker build complete: $(DOCKER_IMAGE):$(DOCKER_TAG)${NC}"

docker-run: docker-build ## Run Docker container
	@echo "${GREEN}Running Docker container...${NC}"
	docker run -p 8080:8080 \
		-e SERVER_HOST=http://localhost:8080 \
		$(DOCKER_IMAGE):$(DOCKER_TAG) \
		--server-host http://localhost:8080

docker-push: ## Push Docker image to registry
	@echo "${GREEN}Pushing Docker image...${NC}"
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "${GREEN}Docker push complete${NC}"

deploy: ## Deploy to Kubernetes
	@echo "${GREEN}Deploying to Kubernetes...${NC}"
	kubectl apply -f manifests/
	@echo "${GREEN}Deploy complete${NC}"

deploy-delete: ## Delete from Kubernetes
	@echo "${YELLOW}Deleting from Kubernetes...${NC}"
	kubectl delete -f manifests/
	@echo "${GREEN}Delete complete${NC}"

install-tools: ## Install development tools
	@echo "${GREEN}Installing development tools...${NC}"
	$(GO) install golang.org/x/tools/cmd/goimports@latest
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v2.5.0
	@echo "${GREEN}Tools installed${NC}"

# Development targets
dev-setup: install-tools mod-download ## Setup development environment
	@echo "${GREEN}Development environment ready${NC}"

ci: lint vet test build ## Run CI pipeline locally
	@echo "${GREEN}CI pipeline complete${NC}"

pre-commit: fmt lint test ## Run pre-commit checks
	@echo "${GREEN}Pre-commit checks complete${NC}"

# Multi-platform builds
build-all: ## Build for all platforms
	@echo "${GREEN}Building for all platforms...${NC}"
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			if [ "$$os" = "windows" ] && [ "$$arch" = "arm64" ]; then \
				continue; \
			fi; \
			echo "${YELLOW}Building for $$os/$$arch...${NC}"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build $(GOFLAGS) \
				-o $(BINARY_NAME)-$$os-$$arch cmd/server/main.go; \
		done; \
	done
	@echo "${GREEN}Multi-platform build complete${NC}"

help: ## Display this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${GREEN}%-20s${NC} %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build the binary"
	@echo "  make test           # Run tests"
	@echo "  make docker-build   # Build Docker image"
	@echo "  make deploy         # Deploy to Kubernetes"

.DEFAULT_GOAL := help