APP     := opentalon
MODULE  := github.com/vesaa/opentalon
VERSION := v0.1.0
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"
DIST    := dist

.PHONY: all build tidy ui clean linux windows arm64 darwin

all: tidy linux windows arm64

## build: compile for the current OS/ARCH
build:
	go build $(LDFLAGS) -o $(APP) .

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## linux: cross-compile for Linux amd64
linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(APP)-linux-amd64 .

## windows: cross-compile for Windows amd64
windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(APP)-windows-amd64.exe .

## arm64: cross-compile for Linux arm64 (Alpine / Raspberry Pi)
arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(APP)-linux-arm64 .

## darwin: cross-compile for macOS amd64
darwin:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(APP)-darwin-amd64 .

## ui: (future) build the Vue frontend into web/dist
ui:
	@echo "→ cd web && npm install && npm run build"
	@echo "  Then re-run: make build"

## clean: remove build artifacts
clean:
	rm -rf $(DIST) $(APP) $(APP).exe

## run-server: quick local server for development
run-server: build
	./$(APP) server

## run-agent: quick local agent (joins localhost)
run-agent: build
	./$(APP) agent --join 127.0.0.1
