package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoder"
	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoderwasm"
)

// The signing module prepends /algo to the path it is given. Writing that prefix
// into a path here therefore asks for /algo/algo/..., which the gateway answers
// with 404 and an empty result — a failure that looks exactly like a rejected
// signature from the outside, because discovery has no error channel. This
// happened once; the assertion is here so it cannot happen silently again.
func TestSignedPathsCarryOneAlgoPrefix(t *testing.T) {
	wasmPath := signingWasmPath()
	if wasmPath == "" {
		t.Skip("qoder auth wasm not available (set QODER_AUTH_WASM)")
	}
	raw, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("read %s: %v", wasmPath, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	module, err := qoderwasm.Load(ctx, raw)
	if err != nil {
		t.Fatalf("load signing wasm: %v", err)
	}
	defer func() { _ = module.Close(ctx) }()

	region := qoder.RegionFor("cn")
	credential := &qoderAuth{
		Token: "test-token", UID: "1", MachineID: strings.Repeat("a", 96),
		EncryptUserInfo: "field", Key: "key", Region: region.ID,
	}
	prepared, err := signRequest(ctx, credential, func(s *signer) (qoderwasm.Prepared, error) {
		return s.context.PrepareRequest(region.InferHost, modelListPath, "GET", "auth", "", "")
	})
	if err != nil {
		t.Fatalf("sign model list: %v", err)
	}
	if count := strings.Count(prepared.URL, "/algo/"); count != 1 {
		t.Fatalf("signed url has %d /algo/ prefixes, want exactly 1: %s", count, prepared.URL)
	}
	if !strings.Contains(prepared.URL, modelListPath) {
		t.Fatalf("signed url %q does not carry the requested path %q", prepared.URL, modelListPath)
	}
	t.Logf("signed model list url: %s", prepared.URL)
}

// signingWasmPath mirrors the lookup the qoderwasm tests use, so this test runs
// wherever that one does and skips otherwise.
func signingWasmPath() string {
	if fromEnv := os.Getenv("QODER_AUTH_WASM"); fromEnv != "" {
		return fromEnv
	}
	for _, candidate := range []string{
		filepath.Join("qoderwasm", "testdata", "qoder_auth_wasm_bg.wasm"),
		"/tmp/qoder/wasm/qoder_auth_wasm_bg.wasm",
	} {
		if info, err := os.Stat(candidate); err == nil && info.Size() > 0 {
			return candidate
		}
	}
	return ""
}
