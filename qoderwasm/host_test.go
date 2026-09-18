package qoderwasm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The auth wasm is a third-party artifact and is not committed. Tests that need
// it look in testdata first and then at the path the CLI extraction script
// writes; when neither exists they skip instead of failing, so `go test ./...`
// stays green on a machine that has never signed in to Qoder.
func authWasmPath() string {
	if fromEnv := os.Getenv("QODER_AUTH_WASM"); fromEnv != "" {
		return fromEnv
	}
	candidates := []string{
		filepath.Join("testdata", "qoder_auth_wasm_bg.wasm"),
		"/tmp/qoder/wasm/qoder_auth_wasm_bg.wasm",
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Size() > 0 {
			return candidate
		}
	}
	return ""
}

var (
	sharedOnce sync.Once
	sharedMod  *Module
	sharedErr  error
)

func testModule(t *testing.T) *Module {
	t.Helper()
	path := authWasmPath()
	if path == "" {
		t.Skip("qoder auth wasm not available (set QODER_AUTH_WASM or add testdata/qoder_auth_wasm_bg.wasm)")
	}
	sharedOnce.Do(func() {
		wasm, err := os.ReadFile(path)
		if err != nil {
			sharedErr = err
			return
		}
		sharedMod, sharedErr = Load(context.Background(), wasm)
	})
	if sharedErr != nil {
		t.Fatalf("load auth wasm: %v", sharedErr)
	}
	if sharedMod == nil {
		t.Skip("qoder auth wasm not available")
	}
	return sharedMod
}

const sampleUserInfo = `{"uid":"9000000001","name":"tester","security_oauth_token":"oauth-token",` +
	`"access_token":"oauth-token","refresh_token":"refresh-token","expire_time":1893456000,` +
	`"refresh_token_expire_time":1924992000,"login_method":"browser","login_timestamp":1700000000,` +
	`"organization_id":"org-1","organization_tags":"tags","data_policy_agreed":true,` +
	`"encrypt_user_info":"","key":""}`

// The signed request path depends on this call: without the two derived fields
// the infer host answers HTTP 403 "Signature invalid".
func TestGenerateRuntimeAuthFields(t *testing.T) {
	mod := testModule(t)

	raw, err := mod.GenerateRuntimeAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("GenerateRuntimeAuthFields: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		t.Fatalf("result is not JSON (%q): %v", raw, err)
	}
	for _, key := range []string{"encrypt_user_info", "key"} {
		value, ok := fields[key].(string)
		if !ok || value == "" {
			t.Fatalf("field %q is missing or empty in %q", key, raw)
		}
	}
}

// The derived fields carry a random salt, so they change on every call. That is
// exactly why they must be persisted with the credential instead of re-derived
// per request: the signing context and the stored credential have to agree, and
// a value that changes under the server's feet would invalidate it.
func TestGenerateRuntimeAuthFieldsVariesPerCall(t *testing.T) {
	mod := testModule(t)

	first, err := mod.GenerateRuntimeAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := mod.GenerateRuntimeAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if first == second {
		t.Fatal("two derivations returned identical fields; the salt looks constant")
	}
	// Both must still be usable, non-empty payloads.
	for _, raw := range []string{first, second} {
		var fields map[string]any
		if err := json.Unmarshal([]byte(raw), &fields); err != nil {
			t.Fatalf("result is not JSON (%q): %v", raw, err)
		}
		for _, key := range []string{"encrypt_user_info", "key"} {
			value, ok := fields[key].(string)
			if !ok || value == "" {
				t.Fatalf("field %q is missing or empty in %q", key, raw)
			}
		}
	}
}

func TestCredentialStorageRoundTrip(t *testing.T) {
	mod := testModule(t)

	const key = "0123456789abcdef" // the CLI uses machine_id[:16]
	cipher, err := mod.CredentialStorageEncrypt(sampleUserInfo, key)
	if err != nil {
		t.Fatalf("CredentialStorageEncrypt: %v", err)
	}
	if cipher == "" || cipher == sampleUserInfo {
		t.Fatalf("encrypt returned %q", cipher)
	}
	plain, err := mod.CredentialStorageDecrypt(cipher, key)
	if err != nil {
		t.Fatalf("CredentialStorageDecrypt: %v", err)
	}
	if plain != sampleUserInfo {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", plain, sampleUserInfo)
	}
}

// A wrong key must not silently return garbage that the caller would then treat
// as a credential.
func TestCredentialStorageDecryptRejectsWrongKey(t *testing.T) {
	mod := testModule(t)

	cipher, err := mod.CredentialStorageEncrypt(sampleUserInfo, "0123456789abcdef")
	if err != nil {
		t.Fatalf("CredentialStorageEncrypt: %v", err)
	}
	if plain, err := mod.CredentialStorageDecrypt(cipher, "ffffffffffffffff"); err == nil && plain == sampleUserInfo {
		t.Fatal("decrypt with the wrong key returned the plaintext")
	}
}

// An unreadable envelope must surface as an error rather than an empty string.
func TestDecryptServerResponseRejectsGarbage(t *testing.T) {
	mod := testModule(t)

	if _, err := mod.DecryptServerResponse("not-an-envelope"); err == nil {
		t.Fatal("DecryptServerResponse accepted garbage")
	}
}
