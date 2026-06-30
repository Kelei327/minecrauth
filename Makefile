# minecrauth Makefile
#
# Run `make` or `make help` to see every available target with a short description.
# Targets are grouped: development, quality, codegen, frontend assets, release.

# Binary and module settings.
BINARY      := minecrauth
PKG         := ./cmd/minecrauth
BIN_DIR     := bin

# Pinned versions of the tools and vendored frontend assets, kept here so the
# whole toolchain is reproducible without a separate lockfile.
# Tool versions are installed into ./bin by `make bootstrap`.
GOLANGCI_VERSION   := v2.12.2
GORELEASER_VERSION := v2.12.0
SYFT_VERSION       := v1.46.0
SWAG_VERSION  := v2.0.0-rc5
VUE_VERSION   := 3.5.39
VUE_URL       := https://unpkg.com/vue@$(VUE_VERSION)/dist/vue.global.prod.js
PIXELFONT_URL := https://cdn.jsdelivr.net/npm/@fontsource/press-start-2p/files/press-start-2p-latin-400-normal.woff2
VENDOR_DIR    := webui/static/vendor

# Docker image settings. Override on the command line, e.g.
#   make docker-build TAG=v1.2.3
#   make docker-buildx IMAGE=ghcr.io/you/minecrauth TAG=v1.2.3
IMAGE       ?= ghcr.io/achetronic/minecrauth
TAG         ?= dev
PLATFORMS   ?= linux/amd64,linux/arm64
# Architecture for the single-arch docker-build / docker-push targets (defaults to the host).
DOCKER_ARCH := $(shell go env GOARCH)

# Release settings, consumed by the `release` target (and the GitHub release workflow).
#   VERSION         when set, overrides the version/tag GoReleaser releases under
#                   (via GORELEASER_CURRENT_TAG). Lets a manual run from main publish
#                   to a chosen semver, e.g. `make release VERSION=v1.2.3`.
#   GORELEASER_ARGS extra flags appended to `goreleaser release`, e.g.
#                   `GORELEASER_ARGS=--skip=validate` for a manual, non-tagged run.
VERSION         ?=
GORELEASER_ARGS ?=
GORELEASER_ENV   = $(if $(VERSION),GORELEASER_CURRENT_TAG=$(VERSION),)

# Project-local tool binaries installed by `make bootstrap`. Using ./bin keeps the
# toolchain self-contained and pinned, matching the versions CI uses, without
# polluting the system PATH.
GOLANGCI   := $(BIN_DIR)/golangci-lint
GORELEASER := $(BIN_DIR)/goreleaser
SWAG       := $(BIN_DIR)/swag

.DEFAULT_GOAL := help

.PHONY: help bootstrap build run test test-race vet fmt fmt-check lint tidy check openapi vendor frontend docker docker-build docker-push docker-buildx release release-snapshot clean

help: ## Show this help.
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

build: ## Build the static, cgo-free binary into bin/ (embeds the Web UI).
	CGO_ENABLED=0 go build -buildvcs=false -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY) $(PKG)

bootstrap: ## Install pinned dev tools (golangci-lint, goreleaser, swag, syft) into ./bin.
	@mkdir -p $(BIN_DIR)
	GOBIN=$(CURDIR)/$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	GOBIN=$(CURDIR)/$(BIN_DIR) go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)
	GOBIN=$(CURDIR)/$(BIN_DIR) go install github.com/swaggo/swag/v2/cmd/swag@$(SWAG_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b $(CURDIR)/$(BIN_DIR) $(SYFT_VERSION)
	@echo "Installed pinned dev tools into $(BIN_DIR)/ (golangci-lint $(GOLANGCI_VERSION), goreleaser $(GORELEASER_VERSION), swag $(SWAG_VERSION), syft $(SYFT_VERSION))."

run: build ## Build and run the server locally with development defaults.
	./$(BIN_DIR)/$(BINARY) --config config.dev.yaml

test: ## Run the test suite (cgo-free).
	CGO_ENABLED=0 go test ./...

test-race: ## Run the test suite with the race detector (needs cgo for -race only).
	CGO_ENABLED=1 go test -race ./...

vet: ## Run go vet.
	go vet ./...

fmt: ## Format all Go files in place.
	gofmt -w .

fmt-check: ## Fail if any Go file is not gofmt-formatted.
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; \
	fi

lint: ## Run golangci-lint from ./bin (run `make bootstrap` first to install it).
	@test -x $(GOLANGCI) || { echo "$(GOLANGCI) not found; run 'make bootstrap'"; exit 1; }
	$(GOLANGCI) run ./...

tidy: ## Tidy go.mod and go.sum.
	go mod tidy

check: fmt-check vet test ## Run the checks CI runs (format, vet, test).

openapi: ## Generate the OpenAPI 3.1 spec from code annotations into internal/openapi.
	@test -x $(SWAG) || { echo "$(SWAG) not found; run 'make bootstrap'"; exit 1; }
	$(SWAG) init \
		--v3.1 \
		--generalInfo cmd/minecrauth/main.go \
		--output internal/openapi \
		--parseInternal

vendor: ## Re-download the vendored frontend assets (Vue runtime and the pixel font).
	mkdir -p $(VENDOR_DIR)
	curl -sSL $(VUE_URL) -o $(VENDOR_DIR)/vue.global.prod.js
	curl -sSL $(PIXELFONT_URL) -o $(VENDOR_DIR)/press-start-2p.woff2
	@echo "Vendored Vue $(VUE_VERSION) and the pixel font into $(VENDOR_DIR)"

frontend: ## Prepare the Web UI assets (ensures vendored deps exist; they are embedded at build time).
	@if [ ! -f $(VENDOR_DIR)/vue.global.prod.js ] || [ ! -f $(VENDOR_DIR)/press-start-2p.woff2 ]; then \
		echo "Vendored assets missing, fetching..."; $(MAKE) vendor; \
	else \
		echo "Vendored assets present. The Web UI is static (no build step) and is embedded by 'make build'."; \
	fi

docker: ## Build multi-arch images locally via GoReleaser (no publish). Requires goreleaser (make bootstrap) + docker buildx.
	@test -x $(GORELEASER) || { echo "$(GORELEASER) not found; run 'make bootstrap'"; exit 1; }
	PATH="$(CURDIR)/$(BIN_DIR):$$PATH" $(GORELEASER) release --snapshot --clean --skip=publish
	rm -rf dist/ linux/

docker-build: ## Build a single-arch image for the host arch and load it into local Docker (override IMAGE/TAG/DOCKER_ARCH).
	@mkdir -p linux/$(DOCKER_ARCH)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_ARCH) go build -buildvcs=false -ldflags="-s -w" -o linux/$(DOCKER_ARCH)/$(BINARY) $(PKG)
	docker buildx build --platform linux/$(DOCKER_ARCH) --load -t $(IMAGE):$(TAG) .
	rm -rf linux/
	@echo "Built and loaded $(IMAGE):$(TAG) (linux/$(DOCKER_ARCH))."

docker-push: ## Push the single-arch image (build it first with 'make docker-build'). Override IMAGE/TAG.
	docker push $(IMAGE):$(TAG)

docker-buildx: ## Build and push a multi-arch manifest via buildx (override IMAGE/TAG/PLATFORMS). Needs a docker-container buildx builder.
	@docker buildx inspect --bootstrap >/dev/null 2>&1 || { echo "no buildx builder; run 'docker buildx create --use' first"; exit 1; }
	@for arch in $$(echo "$(PLATFORMS)" | tr ',' ' ' | sed 's|linux/||g'); do \
		echo "building linux/$$arch binary..."; \
		mkdir -p linux/$$arch; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -buildvcs=false -ldflags="-s -w" -o linux/$$arch/$(BINARY) $(PKG) || exit 1; \
	done
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) --push .
	rm -rf linux/
	@echo "Built and pushed $(IMAGE):$(TAG) ($(PLATFORMS))."

release-snapshot: ## Build a local snapshot release (binaries + images, no publish, no tag).
	@test -x $(GORELEASER) || { echo "$(GORELEASER) not found; run 'make bootstrap'"; exit 1; }
	PATH="$(CURDIR)/$(BIN_DIR):$$PATH" $(GORELEASER) release --snapshot --clean --skip=publish
	rm -rf linux/

release: ## Publish a full release: binaries to the GitHub Release + multi-arch images to GHCR (GoReleaser). The release workflow calls this. Needs GITHUB_TOKEN, docker buildx and QEMU.
	@test -x $(GORELEASER) || { echo "$(GORELEASER) not found; run 'make bootstrap'"; exit 1; }
	PATH="$(CURDIR)/$(BIN_DIR):$$PATH" $(GORELEASER_ENV) $(GORELEASER) release --clean $(GORELEASER_ARGS)
	rm -rf linux/

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR)/ dist/ linux/
