VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/BastionPHP/Bastion/internal/cli.Version=$(VERSION)

.PHONY: build test integration site site-serve demo lint clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bastion ./cmd/bastion

test:
	go vet ./...
	go test -race ./...
	cd site && npm test

# Needs Docker and root/sudo (container filesystems are read via /proc/<pid>/root).
integration:
	go test -tags integration -count=1 -v -timeout 30m ./integration/

site: build
	cd site && BASTION_BIN=$(CURDIR)/bastion node build.mjs

site-serve: build
	cd site && BASTION_BIN=$(CURDIR)/bastion node build.mjs --serve

# Re-record the terminal demos and sample report used by the site and README.
demo: build
	sudo BIN=./bastion scripts/demo/record.sh

lint:
	test -z "$$(gofmt -l .)" || (gofmt -l . && false)
	go vet ./...

clean:
	rm -rf bastion dist site/dist
