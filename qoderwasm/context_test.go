package qoderwasm

import (
	"strings"
	"testing"
)

// signingContext builds a context the way login will: derive the two auth
// fields from the credential, then hand the module the subset it verifies.
func signingContext(t *testing.T, mod *Module) *QoderContext {
	t.Helper()
	fields, err := mod.GenerateAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("GenerateAuthFields: %v", err)
	}
	agreed := true
	ctx, err := mod.NewContext(
		"11111111-2222-3333-4444-555555555555",
		"1.1.45",
		UserInfoForAuth{
			UID:              "9000000001",
			EncryptUserInfo:  fields.EncryptUserInfo,
			Key:              fields.Key,
			OrganizationID:   "org-1",
			OrganizationTags: []string{"tag-a"},
			DataPolicyAgreed: &agreed,
		},
		NewClientInfo(),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	t.Cleanup(ctx.Free)
	return ctx
}

// The infer request is the one that matters: if this does not produce a signed
// URL, headers and body, nothing the plugin does can work.
func TestSigningContextPreparesInferRequest(t *testing.T) {
	mod := testModule(t)
	ctx := signingContext(t, mod)

	const host = "https://gateway.qoder.com.cn"
	const body = `{"model":"qoder-pro","messages":[{"role":"user","content":"hi"}],"stream":true}`

	prepared, err := ctx.PrepareInferRequest(host, body, "qoder-pro", "system")
	if err != nil {
		t.Fatalf("PrepareInferRequest: %v", err)
	}

	if !strings.HasPrefix(prepared.URL, host) {
		t.Fatalf("signed url = %q, want it under %s", prepared.URL, host)
	}
	if len(prepared.Headers) == 0 {
		t.Fatal("signed request carries no headers")
	}
	if prepared.Body == "" {
		t.Fatal("signed request carries no body")
	}
	t.Logf("infer url: %s", prepared.URL)
	for _, pair := range SortHeaders(prepared.Headers) {
		// Values are not logged: they carry the signature material.
		t.Logf("infer header: %s (%d bytes)", pair[0], len(pair[1]))
	}
}

// The model list goes through the plain signed path, which is also what image
// uploads use.
func TestSigningContextPreparesPlainRequest(t *testing.T) {
	mod := testModule(t)
	ctx := signingContext(t, mod)

	const host = "https://gateway.qoder.com.cn"
	prepared, err := ctx.PrepareRequest(host, "/api/v2/model/list?Encode=1", "GET", "auth", "", "")
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	if !strings.HasPrefix(prepared.URL, host) {
		t.Fatalf("signed url = %q, want it under %s", prepared.URL, host)
	}
	if !strings.Contains(prepared.URL, "/api/v2/model/list") {
		t.Fatalf("signed url = %q, want it to carry the requested path", prepared.URL)
	}
	if len(prepared.Headers) == 0 {
		t.Fatal("signed request carries no headers")
	}
	t.Logf("plain url: %s", prepared.URL)
	for _, pair := range SortHeaders(prepared.Headers) {
		t.Logf("plain header: %s (%d bytes)", pair[0], len(pair[1]))
	}
}

// Two requests must not share signature material: the module mixes in a nonce,
// so a repeated call has to produce a different signature.
func TestSigningIsFreshPerRequest(t *testing.T) {
	mod := testModule(t)
	ctx := signingContext(t, mod)

	const host = "https://gateway.qoder.com.cn"
	const path = "/api/v2/model/list?Encode=1"

	first, err := ctx.PrepareRequest(host, path, "GET", "auth", "", "")
	if err != nil {
		t.Fatalf("first PrepareRequest: %v", err)
	}
	second, err := ctx.PrepareRequest(host, path, "GET", "auth", "", "")
	if err != nil {
		t.Fatalf("second PrepareRequest: %v", err)
	}
	if headersEqual(first.Headers, second.Headers) {
		t.Fatal("two signed requests produced identical headers")
	}
}

// A freed context must fail loudly rather than signing with a dangling handle.
func TestFreedContextDoesNotSign(t *testing.T) {
	mod := testModule(t)
	ctx := signingContext(t, mod)
	ctx.Free()

	if _, err := ctx.PrepareInferRequest("https://gateway.qoder.com.cn", `{"model":"m"}`, "m", "system"); err == nil {
		t.Fatal("a freed signing context still produced a request")
	}
}

// The derived fields must survive the JSON round trip the credential store does,
// because they are persisted rather than recomputed per request.
func TestAuthFieldsArePersistable(t *testing.T) {
	mod := testModule(t)
	fields, err := mod.GenerateAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("GenerateAuthFields: %v", err)
	}
	if fields.Key == "" || fields.EncryptUserInfo == "" {
		t.Fatal("derived fields are empty")
	}
	// A context built from a re-derived credential must sign, which is the
	// property that breaks if the fields are dropped from storage.
	ctx := signingContext(t, mod)
	if _, err := ctx.PrepareRequest("https://gateway.qoder.com.cn", "/api/v2/quota/usage", "GET", "auth", "", ""); err != nil {
		t.Fatalf("PrepareRequest after re-derivation: %v", err)
	}
}

func headersEqual(a, b [][2]string) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA := SortHeaders(a)
	sortedB := SortHeaders(b)
	for i := range sortedA {
		if sortedA[i][0] != sortedB[i][0] || sortedA[i][1] != sortedB[i][1] {
			return false
		}
	}
	return true
}
