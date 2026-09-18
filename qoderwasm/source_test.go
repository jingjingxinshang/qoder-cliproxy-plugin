package qoderwasm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// headerBytes is the smallest thing the scanner accepts as a wasm module: the
// magic, the version, and enough padding to land inside the auth window.
func headerBytes(size int) []byte {
	out := make([]byte, size)
	copy(out, []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00})
	return out
}

// bundleWith embeds blobs the way the CLI does: base64 inside the JavaScript.
func bundleWith(blobs ...[]byte) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("var x=\"/bundle/qodercli.js\";var parts=[")
	for index, blob := range blobs {
		if index > 0 {
			buffer.WriteString(",")
		}
		buffer.WriteString("\"" + base64.StdEncoding.EncodeToString(blob) + "\"")
	}
	buffer.WriteString("];export default {parts};")
	return buffer.Bytes()
}

func tarGzWith(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tarWriter.Write(content); err != nil {
		t.Fatalf("write tar body: %v", err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buffer.Bytes()
}

// Only blobs inside the size window are candidates: the bundle ships several
// modules and picking the wrong one is the failure mode this guards.
func TestScanWasmBlobsFiltersBySize(t *testing.T) {
	tooSmall := headerBytes(54 << 10)
	inWindow := headerBytes(298 << 10)
	tooBig := headerBytes(1 << 20)

	found := scanWasmBlobs(bundleWith(tooSmall, inWindow, tooBig))

	if len(found) != 1 {
		t.Fatalf("got %d candidates, want 1", len(found))
	}
	if len(found[0]) != len(inWindow) {
		t.Fatalf("candidate is %d bytes, want %d", len(found[0]), len(inWindow))
	}
}

// A blob whose base64 is interrupted by JavaScript syntax must not derail the
// scan; the real bundle concatenates dozens of these.
func TestScanWasmBlobsSurvivesNeighbouringText(t *testing.T) {
	found := scanWasmBlobs(bundleWith(headerBytes(256<<10), []byte("noise"), headerBytes(300<<10)))

	if len(found) != 2 {
		t.Fatalf("got %d candidates, want 2", len(found))
	}
}

func TestExtractAuthWasmRejectsTarballWithoutBundle(t *testing.T) {
	archive := tarGzWith(t, "package/readme.md", []byte("nothing to see"))

	if _, err := ExtractAuthWasm(context.Background(), archive); err == nil {
		t.Fatal("expected an error for a tarball without a bundle")
	}
}

// The integrity string is the only thing standing between a network response and
// bytes that get executed as a signing oracle, so a mismatch must be fatal.
func TestDownloadRejectsIntegrityMismatch(t *testing.T) {
	payload := []byte("tarball-bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	digest := sha512.Sum512(payload)
	good := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])

	manager := &Manager{Package: "@qoder-ai/qodercli", Client: server.Client()}
	if _, err := manager.download(context.Background(), server.URL, good); err != nil {
		t.Fatalf("matching integrity was rejected: %v", err)
	}

	wrong := "sha512-" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 64))
	if _, err := manager.download(context.Background(), server.URL, wrong); err == nil {
		t.Fatal("integrity mismatch was accepted")
	}
	if _, err := manager.download(context.Background(), server.URL, "md5-abc"); err == nil {
		t.Fatal("an unexpected integrity algorithm was accepted")
	}
}

// An override is the operator's explicit choice; it must be read from disk
// without touching the registry.
func TestResolvePrefersOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vendored.wasm")
	if err := os.WriteFile(path, realAuthWasm(t), 0o644); err != nil {
		t.Fatalf("write override: %v", err)
	}

	manager := &Manager{
		Package:  "@qoder-ai/qodercli",
		CacheDir: dir,
		Override: path,
		Client:   failingClient(t), // any registry call would fail the test
	}
	resolved, err := manager.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Origin != "override" {
		t.Fatalf("origin = %q, want override", resolved.Origin)
	}
	if !bytes.Equal(resolved.Bytes, realAuthWasm(t)) {
		t.Fatal("override bytes were not used verbatim")
	}
}

// A cached module is used without a network call, which keeps ordinary starts
// offline-safe when the registry is unreachable.
func TestResolveUsesCacheWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	wasmBytes := realAuthWasm(t)
	versionDir := filepath.Join(dir, cacheDirName, "1.1.55")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, wasmFileName), wasmBytes, 0o644); err != nil {
		t.Fatalf("write cached wasm: %v", err)
	}
	record, err := json.Marshal(Meta{Version: "1.1.55", Bytes: len(wasmBytes)})
	if err != nil {
		t.Fatalf("marshal meta: %v", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, metaFileName), record, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}

	manager := &Manager{Package: "@qoder-ai/qodercli", CacheDir: dir, Client: failingClient(t)}
	resolved, err := manager.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Origin != "cache" || resolved.Version != "1.1.55" {
		t.Fatalf("resolved = %+v, want the cached 1.1.55 module", resolved)
	}
}

// refreshing must replace the cache with the freshly extracted module.
func TestRefreshStoresDownloadedModule(t *testing.T) {
	dir := t.TempDir()
	wasmBytes := realAuthWasm(t)
	archive := tarGzWith(t, "package/bundle/qodercli.js", bundleWith(wasmBytes))

	digest := sha512.Sum512(archive)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])

	// The metadata has to point at the test server, whose URL only exists after
	// it is started, so the handler closes over a variable filled in below.
	var tarballURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/@qoder-ai%2Fqodercli/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":    "@qoder-ai/qodercli",
			"version": "9.9.9",
			"dist":    map[string]string{"tarball": tarballURL, "integrity": integrity},
		})
	})
	mux.HandleFunc("/tarball.tgz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	tarballURL = server.URL + "/tarball.tgz"

	manager := &Manager{
		Package:  "@qoder-ai/qodercli",
		CacheDir: dir,
		Registry: server.URL,
		Client:   server.Client(),
	}
	resolved, err := manager.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if resolved.Origin != "download" || resolved.Version != "9.9.9" {
		t.Fatalf("resolved = %+v", resolved)
	}
	if !bytes.Equal(resolved.Bytes, wasmBytes) {
		t.Fatal("downloaded module does not match the bundle contents")
	}
	stored, err := os.ReadFile(filepath.Join(dir, cacheDirName, "9.9.9", wasmFileName))
	if err != nil {
		t.Fatalf("read cached module: %v", err)
	}
	if !bytes.Equal(stored, wasmBytes) {
		t.Fatal("cached module does not match the bundle contents")
	}
}

// failingClient returns a client whose transport fails the test if used: it
// proves a code path performs no network I/O.
func failingClient(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected network call to %s", request.URL)
		return nil, nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// realAuthWasm returns the real module for tests that need one that satisfies
// ValidateAuthWasm, skipping when the machine has never fetched it.
func realAuthWasm(t *testing.T) []byte {
	t.Helper()
	path := authWasmPath()
	if path == "" {
		t.Skip("qoder auth wasm not available (set QODER_AUTH_WASM or add testdata/qoder_auth_wasm_bg.wasm)")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return bytes
}
