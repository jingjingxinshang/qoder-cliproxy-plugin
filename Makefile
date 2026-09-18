PLUGIN_ID := qoder
OUT := dist

# The host derives a plugin's id from its FILE NAME, not from anything the plugin
# reports: plugins/qoder.so is the plugin "qoder", and plugins/qoder-linux-amd64.so
# would silently become the unrelated plugin "qoder-linux-amd64" with no config.
# So the arch-suffixed files below are for archiving; when installing, copy one
# to <cpa>/plugins/qoder.so.
#
# There is no version here on purpose: the version strings live in main.go
# (pluginVer — what the panel shows) and registry.json (what the store installs).
# Keep those two in step and tag the same number; this file only builds artifacts.

.PHONY: fmt test build build-local package clean

fmt:
	gofmt -w main.go

test:
	go test ./...

# The linux targets need a matching C toolchain. Building them from macOS fails
# inside runtime/cgo, because the compiler picks up the macOS SDK headers for a
# Linux target (clearenv, setresgid are not declared there). Build them on a Linux
# host, or let .github/workflows/release.yml do it: it installs
# gcc-aarch64-linux-gnu and gcc-x86-64-linux-gnu and names the artifact qoder.so.
build: fmt
	mkdir -p $(OUT)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -o $(OUT)/$(PLUGIN_ID)-linux-amd64.so .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -buildmode=c-shared -o $(OUT)/$(PLUGIN_ID)-linux-arm64.so .
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -o $(OUT)/$(PLUGIN_ID)-darwin-amd64.dylib .
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -buildmode=c-shared -o $(OUT)/$(PLUGIN_ID)-darwin-arm64.dylib .

build-local: fmt
	mkdir -p $(OUT)
	go build -buildmode=c-shared -o $(OUT)/$(PLUGIN_ID)-local.dylib .

# package stages the Linux binary under the name the host turns into the plugin
# id: copy $(OUT)/install/$(PLUGIN_ID).so to <cpa>/plugins/ and the plugin is
# "qoder", which is the key its configuration lives under.
package: build
	mkdir -p $(OUT)/install
	cp $(OUT)/$(PLUGIN_ID)-linux-amd64.so $(OUT)/install/$(PLUGIN_ID).so
	@echo "install with: cp $(OUT)/install/$(PLUGIN_ID).so <cpa>/plugins/$(PLUGIN_ID).so"

clean:
	rm -rf $(OUT)
