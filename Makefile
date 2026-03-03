APP     := opentalon
MODULE  := github.com/vesaa/opentalon
VERSION := v0.1.0
LDFLAGS := -ldflags="-s -w -X main.version=$(VERSION)"
DIST    := dist

.PHONY: all build tidy ui clean distdir linux windows arm64 armv7 alpine darwin darwin-arm64

all: tidy linux windows arm64 armv7 alpine darwin darwin-arm64

distdir:
	mkdir -p $(DIST)

## build: compile for the current OS/ARCH
build:
	go build $(LDFLAGS) -o $(APP) .

## tidy: sync go.mod / go.sum
tidy:
	go mod tidy

## linux: cross-compile for Linux amd64 (universal static build)
linux: distdir
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -tags netgo,osusergo -o $(DIST)/$(APP)-linux-amd64 .

## windows: cross-compile for Windows amd64
windows: distdir
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(APP)-windows-amd64.exe .

## arm64: cross-compile for Linux arm64 (Alpine / Raspberry Pi)
arm64: distdir
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(APP)-linux-arm64 .

## armv7: cross-compile for Linux armv7 (32-bit)
armv7: distdir
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o $(DIST)/$(APP)-linux-armv7 .

## alpine: legacy alias for linux universal build (kept for backward compatibility)
alpine: linux
	cp $(DIST)/$(APP)-linux-amd64 $(DIST)/$(APP)-linux-amd64-alpine

## darwin: cross-compile for macOS amd64
darwin: distdir
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(APP)-darwin-amd64 .

## darwin-arm64: cross-compile for macOS arm64 (Apple Silicon)
darwin-arm64: distdir
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(APP)-darwin-arm64 .

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
