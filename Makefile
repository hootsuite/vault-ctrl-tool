CURRENTOS := $(shell go env GOOS)
CURRENTARCH := $(shell go env GOARCH)

export GOFLAGS=-mod=vendor
unexport GOPATH

build: clean test darwin-binary linux-binary copy-binary

clean: ## Delete the target and bin directories.
	rm -rf ./target ./bin

test:
	go test -v ./...

darwin-binary:
	GOOS=darwin GOARCH=amd64 go build -o bin/vault-ctrl-tool.darwin.amd64 cmd/*.go

linux-binary:
	GOOS=linux GOARCH=amd64 go build -o bin/vault-ctrl-tool.linux.amd64 cmd/*.go

# Useful when doing development
copy-binary:
	cp bin/vault-ctrl-tool.$(CURRENTOS).$(CURRENTARCH) vault-ctrl-tool

vendor:
	go mod vendor
