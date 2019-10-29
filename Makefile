CURRENTOS := $(shell go env GOOS)
CURRENTARCH := $(shell go env GOARCH)
VERSION := dev

export GOFLAGS=-mod=vendor
unexport GOPATH

build: clean test darwin-binary linux-binary copy-binary

clean: ## Delete the destination directory.
	rm -rf ./bin

test:
	go test -v ./...

darwin-binary:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.buildVersion=$(VERSION)" -o bin/vault-ctrl-tool.darwin.amd64 .

linux-binary:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.buildVersion=$(VERSION)" -o bin/vault-ctrl-tool.linux.amd64 .

# Useful when doing development
copy-binary:
	cp bin/vault-ctrl-tool.$(CURRENTOS).$(CURRENTARCH) vault-ctrl-tool

vendor:
	go mod vendor

