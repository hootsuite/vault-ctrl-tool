CURRENTOS := $(shell go env GOOS)
CURRENTARCH := $(shell go env GOARCH)
VERSION := dev

.DEFAULT_GOAL := build

help: ## List targets & descriptions
	@grep --no-filename -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

build: clean test darwin-binary linux-binary copy-binary ## Build all the binaries

clean: ## Delete the destination directory.
	rm -rf ./bin

test: mocks ## Run unit tests
	go test -v ./...

darwin-binary: mocks ## Build a macOS binary
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X main.buildVersion=$(VERSION)" -o bin/vault-ctrl-tool.darwin.amd64 .

linux-binary: mocks ## Build a Linux (amd64) binary
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.buildVersion=$(VERSION)" -o bin/vault-ctrl-tool.linux.amd64 .

# Useful when doing development
copy-binary:
	cp bin/vault-ctrl-tool.$(CURRENTOS).$(CURRENTARCH) vault-ctrl-tool

deps: ## Ensure dependencies are present and prune orphaned
	go mod download
	go mod tidy

vaultclient/mocks/vaultclient.go: vaultclient/vaultclient.go
	mockgen -source=$< -destination=$@

mocks: vaultclient/mocks/vaultclient.go

.PHONY: help mocks deps copy-binary linux-binary darwin-binary test clean build
