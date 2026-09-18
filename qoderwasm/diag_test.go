package qoderwasm

import (
	"context"
	"os"
	"testing"
)

// Diagnostic: which part of building a signing context does the module accept?
// Each case gets its own instance because a trap leaves module state undefined.
func TestDiagContextVariants(t *testing.T) {
	if os.Getenv("QODER_DIAG") == "" {
		t.Skip("set QODER_DIAG=1 to run the signing diagnostics")
	}
	path := authWasmPath()
	if path == "" {
		t.Skip("auth wasm unavailable")
	}
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wasm: %v", err)
	}

	agreed := true
	cases := []struct {
		name     string
		userInfo UserInfoForAuth
	}{
		{"subset+tags", UserInfoForAuth{UID: "9000000001", OrganizationID: "org-1", OrganizationTags: []string{"tag-a"}, DataPolicyAgreed: &agreed}},
		{"subset-no-tags", UserInfoForAuth{UID: "9000000001", OrganizationID: "org-1", DataPolicyAgreed: &agreed}},
		{"subset-no-org", UserInfoForAuth{UID: "9000000001", DataPolicyAgreed: &agreed}},
		{"uid-only", UserInfoForAuth{UID: "9000000001"}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mod, err := Load(context.Background(), wasmBytes)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			defer func() { _ = mod.Close(context.Background()) }()

			fields, err := mod.GenerateAuthFields(sampleUserInfo)
			if err != nil {
				t.Fatalf("fields: %v", err)
			}
			user := testCase.userInfo
			user.EncryptUserInfo = fields.EncryptUserInfo
			user.Key = fields.Key

			ctx, err := mod.NewContext("11111111-2222-3333-4444-555555555555", "1.1.45", user, NewClientInfo())
			if err != nil {
				t.Logf("NewContext FAILED: %v", err)
				return
			}
			t.Logf("NewContext ok, handle=%d", ctx.handle)

			prepared, err := ctx.PrepareRequest("https://gateway.qoder.com.cn", "/api/v2/model/list?Encode=1", "GET", "auth", "", "")
			if err != nil {
				t.Logf("PrepareRequest FAILED: %v", err)
				return
			}
			t.Logf("PrepareRequest ok: url=%s headers=%d", prepared.URL, len(prepared.Headers))

			infer, err := ctx.PrepareInferRequest("https://gateway.qoder.com.cn", `{"model":"qoder-pro","stream":true}`, "qoder-pro", "system")
			if err != nil {
				t.Logf("PrepareInferRequest FAILED: %v", err)
				return
			}
			t.Logf("PrepareInferRequest ok: url=%s headers=%d body=%d", infer.URL, len(infer.Headers), len(infer.Body))
		})
	}
}
