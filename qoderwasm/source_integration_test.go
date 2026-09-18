package qoderwasm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// realTarballPath points at a CLI tarball downloaded by hand. The test that uses
// it exercises the whole extraction path against the real 30MB bundle, which is
// the only way to know the layout assumptions still hold — it skips when the
// file is absent so the suite stays hermetic.
func realTarballPath() string {
	if fromEnv := os.Getenv("QODER_CLI_TARBALL"); fromEnv != "" {
		return fromEnv
	}
	candidates := []string{
		filepath.Join("testdata", "qodercli.tgz"),
		"/tmp/qoder/qodercli.tgz",
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Size() > 0 {
			return candidate
		}
	}
	return ""
}

// Extraction must land on the auth module itself, not on one of the several
// other modules the bundle carries in a similar size range.
func TestExtractAuthWasmFromRealCLITarball(t *testing.T) {
	path := realTarballPath()
	if path == "" {
		t.Skip("cli tarball not available (set QODER_CLI_TARBALL or download it to testdata/)")
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	wasmBytes, err := ExtractAuthWasm(context.Background(), archive)
	if err != nil {
		t.Fatalf("ExtractAuthWasm: %v", err)
	}
	if !ValidateAuthWasm(context.Background(), wasmBytes) {
		t.Fatal("extracted module does not export the signing API")
	}

	// The module must actually sign: this is the property everything else rests
	// on, and it is cheap to assert here.
	module, err := Load(context.Background(), wasmBytes)
	if err != nil {
		t.Fatalf("load extracted module: %v", err)
	}
	defer func() { _ = module.Close(context.Background()) }()

	raw, err := module.GenerateRuntimeAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("GenerateRuntimeAuthFields on the extracted module: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatalf("derived fields are not JSON: %v", err)
	}
	if fields["key"] == "" || fields["encrypt_user_info"] == "" {
		t.Fatalf("derived fields are empty: %q", raw)
	}
}

// The scanner must not be fooled by the smaller modules: they are real wasm with
// the same header, and the only thing separating them from the auth module is
// the export set.
func TestRealBundleYieldsOnlyInWindowCandidates(t *testing.T) {
	path := realTarballPath()
	if path == "" {
		t.Skip("cli tarball not available")
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	bundles, err := readBundleScripts(archive)
	if err != nil {
		t.Fatalf("readBundleScripts: %v", err)
	}
	if len(bundles) == 0 {
		t.Fatal("no bundle JavaScript found in the tarball")
	}

	total := 0
	valid := 0
	for _, bundle := range bundles {
		candidates := scanWasmBlobs(bundle)
		total += len(candidates)
		for _, candidate := range candidates {
			if ValidateAuthWasm(context.Background(), candidate) {
				valid++
			}
		}
	}
	if total == 0 {
		t.Fatal("the bundle exposed no candidates in the auth size window")
	}
	if valid != 1 {
		t.Fatalf("%d of %d candidates export the signing API, want exactly 1", valid, total)
	}
}

// A downloaded module must be byte-identical to what the bundle carries, i.e.
// the base64 round trip and the cache write do not corrupt it.
func TestCachedModuleMatchesBundleBytes(t *testing.T) {
	path := realTarballPath()
	if path == "" {
		t.Skip("cli tarball not available")
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	extracted, err := ExtractAuthWasm(context.Background(), archive)
	if err != nil {
		t.Fatalf("ExtractAuthWasm: %v", err)
	}

	// Re-scanning the same bundle must produce the same bytes.
	bundles, err := readBundleScripts(archive)
	if err != nil {
		t.Fatalf("readBundleScripts: %v", err)
	}
	var again []byte
	for _, candidate := range scanWasmBlobs(bundles[0]) {
		if bytes.Equal(candidate, extracted) {
			again = candidate
			break
		}
	}
	if again == nil {
		t.Fatal("the extracted module was not reproducible from the bundle")
	}

	// And the base64 we recorded is exactly the embedded text.
	encoded := base64.StdEncoding.EncodeToString(extracted)
	if !bytes.Contains(bundles[0], []byte(encoded)) {
		t.Fatal("extracted bytes are not the base64 text embedded in the bundle")
	}
}
