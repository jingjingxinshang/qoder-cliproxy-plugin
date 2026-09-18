package qoderwasm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The auth module is not shipped in this repository. It is a third-party binary
// that changes when Qoder rotates its signing keys, so it is fetched from the
// official CLI package the way the CLI itself carries it: base64 inside the
// bundled JavaScript.
const (
	// wasmMagic is the base64 prefix of the wasm header ("\0asm").
	wasmMagic = "AGFzbQ"

	// The bundle carries several modules (54KB, 72KB, 205KB and 1.4MB in CLI
	// 1.1.55); the auth module is the ~298KB one. This window only narrows the
	// candidates — the real identification is that the bytes instantiate and
	// export the signing API.
	minAuthWasmSize = 200 << 10
	maxAuthWasmSize = 400 << 10

	defaultRegistry = "https://registry.npmjs.org"

	// integrityAlgorithm is the only one npm publishes for these tarballs.
	integrityAlgorithm = "sha512"

	cacheDirName = "qoder-auth-wasm"
	wasmFileName = "qoder_auth_wasm_bg.wasm"
	metaFileName = "meta.json"
)

// requiredExports are the entry points this package calls. A blob that does not
// export all of them is not the auth module.
var requiredExports = []string{
	"credential_storage_decrypt",
	"credential_storage_encrypt",
	"decrypt_server_response",
	"generate_runtime_auth_fields",
	"qodercontext_new",
	"qodercontext_prepareRequest",
	"qodercontext_prepareInferRequest",
	"requestresult_body",
	"requestresult_headers",
	"requestresult_url",
}

// PackageMeta is the slice of npm registry metadata needed to download a release.
type PackageMeta struct {
	Name      string
	Version   string
	Tarball   string
	Integrity string
}

// Wasm is a resolved auth module.
type Wasm struct {
	Bytes   []byte
	Path    string
	Version string
	// Origin records where the bytes came from: "override", "cache" or
	// "download". Operators debugging signature failures want this.
	Origin string
}

// Meta is the cache bookkeeping written next to a cached module.
type Meta struct {
	Version      string `json:"version"`
	Package      string `json:"package"`
	Tarball      string `json:"tarball"`
	Integrity    string `json:"integrity"`
	SHA256       string `json:"sha256"`
	Bytes        int    `json:"bytes"`
	DownloadedAt string `json:"downloadedAt"`
}

// Manager resolves the auth module for one CLI package.
//
// Resolution order is override, then cache, then download. Cached bytes win over
// a fresh download so a normal start costs no network call; call Refresh when
// the server rejects a signature, which is the signal that the key pool rotated.
type Manager struct {
	// Package is the npm package for the region, e.g. "@qoder-ai/qodercli".
	Package string
	// CacheDir is where downloaded modules are kept. Defaults to the user cache
	// directory when empty.
	CacheDir string
	// Registry overrides the npm registry base URL.
	Registry string
	// Client is the HTTP client used for downloads.
	Client *http.Client
	// Override disables downloading entirely and uses this file. An operator who
	// vendored the module must not have it silently replaced.
	Override string
}

func (m *Manager) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (m *Manager) registry() string {
	if m.Registry != "" {
		return m.Registry
	}
	return defaultRegistry
}

func (m *Manager) cacheRoot() (string, error) {
	if m.CacheDir != "" {
		return filepath.Join(m.CacheDir, cacheDirName), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache directory: %w", err)
	}
	return filepath.Join(base, cacheDirName), nil
}

// Resolve returns the module to use, downloading it only when nothing is cached.
func (m *Manager) Resolve(ctx context.Context) (Wasm, error) {
	if m.Override != "" {
		bytes, err := os.ReadFile(m.Override)
		if err != nil {
			return Wasm{}, fmt.Errorf("read qoder auth wasm override %s: %w", m.Override, err)
		}
		if !ValidateAuthWasm(ctx, bytes) {
			return Wasm{}, fmt.Errorf("qoder auth wasm override %s does not export the signing API", m.Override)
		}
		return Wasm{Bytes: bytes, Path: m.Override, Version: cachedVersion(m.Override), Origin: "override"}, nil
	}
	if cached, ok := m.loadCached(); ok {
		if ValidateAuthWasm(ctx, cached.Bytes) {
			return cached, nil
		}
		// A cached module that lost its API is worse than a download: fall
		// through and replace it.
	}
	return m.Refresh(ctx)
}

// Refresh downloads the latest published CLI package and caches its auth module,
// replacing whatever was cached. It is the recovery path for HTTP 403
// `{"code":"101","message":"Signature invalid"}`.
func (m *Manager) Refresh(ctx context.Context) (Wasm, error) {
	meta, err := m.LatestPackage(ctx)
	if err != nil {
		return Wasm{}, err
	}
	tarball, err := m.download(ctx, meta.Tarball, meta.Integrity)
	if err != nil {
		return Wasm{}, err
	}
	wasmBytes, err := ExtractAuthWasm(ctx, tarball)
	if err != nil {
		return Wasm{}, fmt.Errorf("extract auth wasm from %s@%s: %w", meta.Name, meta.Version, err)
	}
	written, err := m.store(meta, wasmBytes)
	if err != nil {
		return Wasm{}, err
	}
	return written, nil
}

// LatestPackage reads the `latest` document of the package from the registry.
func (m *Manager) LatestPackage(ctx context.Context) (PackageMeta, error) {
	if m.Package == "" {
		return PackageMeta{}, errors.New("no npm package configured for this qoder region")
	}
	url := fmt.Sprintf("%s/%s/latest", m.registry(), strings.ReplaceAll(m.Package, "/", "%2F"))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PackageMeta{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := m.client().Do(request)
	if err != nil {
		return PackageMeta{}, fmt.Errorf("fetch npm metadata for %s: %w", m.Package, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return PackageMeta{}, fmt.Errorf("npm metadata for %s answered HTTP %d", m.Package, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return PackageMeta{}, err
	}
	var payload struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return PackageMeta{}, fmt.Errorf("npm metadata for %s is not JSON: %w", m.Package, err)
	}
	if payload.Version == "" || payload.Dist.Tarball == "" || payload.Dist.Integrity == "" {
		return PackageMeta{}, fmt.Errorf("npm metadata for %s is missing version, tarball or integrity", m.Package)
	}
	name := payload.Name
	if name == "" {
		name = m.Package
	}
	return PackageMeta{
		Name:      name,
		Version:   payload.Version,
		Tarball:   payload.Dist.Tarball,
		Integrity: payload.Dist.Integrity,
	}, nil
}

// download fetches a tarball and verifies it against the registry's published
// integrity before anything is extracted from it.
func (m *Manager) download(ctx context.Context, tarballURL, integrity string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := m.client().Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", tarballURL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s answered HTTP %d", tarballURL, response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tarballURL, err)
	}
	if err := verifyIntegrity(body, integrity); err != nil {
		return nil, err
	}
	return body, nil
}

// verifyIntegrity checks the tarball against an npm `sha512-<base64>` string.
func verifyIntegrity(body []byte, integrity string) error {
	algorithm, encoded, found := strings.Cut(integrity, "-")
	if !found {
		return fmt.Errorf("unexpected integrity format %q", integrity)
	}
	if algorithm != integrityAlgorithm {
		return fmt.Errorf("unsupported integrity algorithm %q", algorithm)
	}
	digest := sha512.Sum512(body)
	got := base64.StdEncoding.EncodeToString(digest[:])
	if got != encoded {
		return fmt.Errorf("tarball integrity mismatch: registry published %s, downloaded bytes hash to %s", encoded, got)
	}
	return nil
}

// store writes the module and its bookkeeping into the cache.
func (m *Manager) store(meta PackageMeta, wasmBytes []byte) (Wasm, error) {
	root, err := m.cacheRoot()
	if err != nil {
		return Wasm{}, err
	}
	dir := filepath.Join(root, meta.Version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Wasm{}, fmt.Errorf("create wasm cache %s: %w", dir, err)
	}
	path := filepath.Join(dir, wasmFileName)
	if err := os.WriteFile(path, wasmBytes, 0o644); err != nil {
		return Wasm{}, fmt.Errorf("write %s: %w", path, err)
	}
	digest := sha256.Sum256(wasmBytes)
	record := Meta{
		Version:      meta.Version,
		Package:      meta.Name,
		Tarball:      meta.Tarball,
		Integrity:    meta.Integrity,
		SHA256:       hex.EncodeToString(digest[:]),
		Bytes:        len(wasmBytes),
		DownloadedAt: time.Now().UTC().Format(time.RFC3339),
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return Wasm{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, metaFileName), append(encoded, '\n'), 0o644); err != nil {
		return Wasm{}, fmt.Errorf("write cache metadata: %w", err)
	}
	return Wasm{Bytes: wasmBytes, Path: path, Version: meta.Version, Origin: "download"}, nil
}

// loadCached returns the most recently written cached module, if any.
func (m *Manager) loadCached() (Wasm, bool) {
	root, err := m.cacheRoot()
	if err != nil {
		return Wasm{}, false
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Wasm{}, false
	}
	type candidate struct {
		version string
		modTime time.Time
	}
	var newest candidate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if newest.version == "" || info.ModTime().After(newest.modTime) {
			newest = candidate{version: entry.Name(), modTime: info.ModTime()}
		}
	}
	if newest.version == "" {
		return Wasm{}, false
	}
	path := filepath.Join(root, newest.version, wasmFileName)
	bytes, err := os.ReadFile(path)
	if err != nil || len(bytes) == 0 {
		return Wasm{}, false
	}
	return Wasm{Bytes: bytes, Path: path, Version: newest.version, Origin: "cache"}, true
}

// cachedVersion reads the version recorded next to an override file, falling
// back to "override" when there is none.
func cachedVersion(path string) string {
	encoded, err := os.ReadFile(filepath.Join(filepath.Dir(path), metaFileName))
	if err != nil {
		return "override"
	}
	var record Meta
	if json.Unmarshal(encoded, &record) != nil || record.Version == "" {
		return "override"
	}
	return record.Version
}

// ExtractAuthWasm pulls the auth module out of a CLI tarball.
//
// The bundle ships several wasm blobs, so candidates are identified by both the
// size window and the signing API they export; a blob that fails to instantiate
// is simply not the one.
func ExtractAuthWasm(ctx context.Context, tarGz []byte) ([]byte, error) {
	bundles, err := readBundleScripts(tarGz)
	if err != nil {
		return nil, err
	}
	if len(bundles) == 0 {
		return nil, errors.New("tarball contains no bundle JavaScript")
	}
	var sizes []int
	for _, bundle := range bundles {
		for _, candidate := range scanWasmBlobs(bundle) {
			sizes = append(sizes, len(candidate))
			if ValidateAuthWasm(ctx, candidate) {
				return candidate, nil
			}
		}
	}
	if len(sizes) == 0 {
		return nil, fmt.Errorf("no wasm blob found in the bundle (looked for a %s blob between %d and %d bytes)",
			wasmMagic, minAuthWasmSize, maxAuthWasmSize)
	}
	return nil, fmt.Errorf("found %d wasm blobs (%v) but none exports the qoder signing API", len(sizes), sizes)
}

// readBundleScripts returns the contents of the bundled JavaScript files.
func readBundleScripts(tarGz []byte) ([][]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return nil, fmt.Errorf("tarball is not gzip: %w", err)
	}
	defer gzipReader.Close()

	var bundles [][]byte
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tarball: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := header.Name
		if !strings.HasSuffix(name, ".js") || !strings.Contains(name, "/bundle/") {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(tarReader, 256<<20))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		bundles = append(bundles, content)
	}
	return bundles, nil
}

// scanWasmBlobs returns the base64-embedded wasm modules inside a bundle.
//
// The scan is index-based rather than regex-based on purpose: the bundle is
// tens of megabytes and a regex over it is a good way to run out of stack.
func scanWasmBlobs(bundle []byte) [][]byte {
	var out [][]byte
	position := 0
	for {
		index := bytes.Index(bundle[position:], []byte(wasmMagic))
		if index < 0 {
			return out
		}
		start := position + index
		end := start
		for end < len(bundle) && isBase64Byte(bundle[end]) {
			end++
		}
		encoded := bundle[start:end]
		position = end
		if len(encoded) < 200 {
			continue
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
		written, err := base64.StdEncoding.Decode(decoded, encoded)
		if err != nil {
			continue
		}
		decoded = decoded[:written]
		if len(decoded) < minAuthWasmSize || len(decoded) > maxAuthWasmSize {
			continue
		}
		if !bytes.HasPrefix(decoded, []byte{0x00, 0x61, 0x73, 0x6d}) {
			continue
		}
		out = append(out, decoded)
	}
}

func isBase64Byte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=':
		return true
	default:
		return false
	}
}

// ValidateAuthWasm reports whether the bytes are the Qoder auth module, by
// instantiating them and asking for the entry points this package calls.
//
// Instantiation is the cheap, honest test: a different module in the same size
// range fails to resolve these imports and never gets this far.
func ValidateAuthWasm(ctx context.Context, wasm []byte) bool {
	if len(wasm) < 8 || !bytes.HasPrefix(wasm, []byte{0x00, 0x61, 0x73, 0x6d}) {
		return false
	}
	module, err := Load(ctx, wasm)
	if err != nil {
		return false
	}
	defer func() { _ = module.Close(ctx) }()
	for _, name := range requiredExports {
		if module.mod.ExportedFunction(name) == nil {
			return false
		}
	}
	return true
}
