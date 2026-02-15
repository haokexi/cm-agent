.PHONY: help test build clean \
	build-linux-amd64 build-linux-arm64 \
	release-linux-amd64 release-linux-arm64 release \
	github-release

APP := cm-agent
DIST_DIR := dist

# Use /tmp by default to avoid macOS sandbox permission issues on ~/Library/Caches/go-build.
GOCACHE ?= /tmp/go-build-cache
GO ?= go

CGO_ENABLED ?= 0

LDFLAGS := -s -w

help:
	@echo "Targets:"
	@echo "  make test                 Run unit tests"
	@echo "  make build                Build host binary -> ./$(APP)"
	@echo "  make build-linux-amd64     Build Linux amd64 -> $(DIST_DIR)/$(APP)-linux-amd64"
	@echo "  make build-linux-arm64     Build Linux arm64 -> $(DIST_DIR)/$(APP)-linux-arm64"
	@echo "  make release               Build + tar.gz + sha256 for linux amd64/arm64"
	@echo "  make clean                Remove $(DIST_DIR)/"

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

test:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) test ./...

build:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(APP) .

build-linux-amd64: | $(DIST_DIR)
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-linux-amd64 .

build-linux-arm64: | $(DIST_DIR)
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 \
		$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP)-linux-arm64 .

release-linux-amd64: build-linux-amd64
	cp -f config.example.yaml $(DIST_DIR)/config.example.yaml
	tar -C $(DIST_DIR) -czf $(DIST_DIR)/$(APP)-linux-amd64.tgz $(APP)-linux-amd64 config.example.yaml
	# Write checksum with a basename (no dist/ prefix) so `sha256sum -c` works after downloading elsewhere.
	cd $(DIST_DIR) && shasum -a 256 $(APP)-linux-amd64.tgz > $(APP)-linux-amd64.tgz.sha256

release-linux-arm64: build-linux-arm64
	cp -f config.example.yaml $(DIST_DIR)/config.example.yaml
	tar -C $(DIST_DIR) -czf $(DIST_DIR)/$(APP)-linux-arm64.tgz $(APP)-linux-arm64 config.example.yaml
	# Write checksum with a basename (no dist/ prefix) so `sha256sum -c` works after downloading elsewhere.
	cd $(DIST_DIR) && shasum -a 256 $(APP)-linux-arm64.tgz > $(APP)-linux-arm64.tgz.sha256

release: release-linux-amd64 release-linux-arm64
	@echo "Release artifacts in $(DIST_DIR)/"

github-release:
	@./scripts/github_release.sh "$(TAG)"

clean:
	rm -rf $(DIST_DIR)
