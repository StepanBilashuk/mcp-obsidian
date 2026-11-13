.PHONY: test build dist clean

LDFLAGS := -s -w

test:
	go test -race ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o vaultmcp .

dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vaultmcp-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/vaultmcp-linux-arm64 .

clean:
	rm -rf dist vaultmcp
