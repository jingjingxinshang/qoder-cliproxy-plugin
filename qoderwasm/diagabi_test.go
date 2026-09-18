package qoderwasm

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Diagnostic for the prepare* trap: dump the raw ABI result area and, with debug
// info enabled, ask wazero where the trap happened. Gated behind QODER_DIAG
// because it exists to be read, not to assert.
func TestDiagRawABI(t *testing.T) {
	if os.Getenv("QODER_DIAG") == "" {
		t.Skip("set QODER_DIAG=1 to run the ABI diagnostics")
	}
	path := authWasmPath()
	if path == "" {
		t.Skip("auth wasm unavailable")
	}
	wasmBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wasm: %v", err)
	}
	mod, err := Load(context.Background(), wasmBytes, WithDebugInfo())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = mod.Close(context.Background()) }()

	fields, err := mod.GenerateAuthFields(sampleUserInfo)
	if err != nil {
		t.Fatalf("fields: %v", err)
	}
	agreed := true
	userInfo := UserInfoForAuth{
		UID:              "9000000001",
		EncryptUserInfo:  fields.EncryptUserInfo,
		Key:              fields.Key,
		OrganizationID:   "org-1",
		OrganizationTags: []string{"tag-a"},
		DataPolicyAgreed: &agreed,
	}

	// 1. What does the constructor actually write, word by word?
	area, err := mod.stackPush()
	if err != nil {
		t.Fatalf("stackPush: %v", err)
	}
	args := []string{
		"11111111-2222-3333-4444-555555555555",
		"1.1.45",
		mustJSON(t, userInfo),
		mustJSON(t, NewClientInfo()),
	}
	var params []uint64
	params = append(params, u64(area))
	for _, arg := range args {
		ptr, length, err := mod.pushString(arg)
		if err != nil {
			t.Fatalf("pushString: %v", err)
		}
		defer mod.free(ptr, length, 1)
		params = append(params, u64(ptr), u64(length))
	}
	t.Logf("stack area returned by add_to_stack_pointer: %d", area)
	if _, errCall := mod.call("qodercontext_new", params...); errCall != nil {
		t.Fatalf("qodercontext_new: %v", errCall)
	}
	raw, err := mod.read(area, 32)
	if err != nil {
		t.Fatalf("read area: %v", err)
	}
	t.Logf("constructor result words: +0=%d +4=%d +8=%d +12=%d",
		mod.readI32(area), mod.readI32(area+4), mod.readI32(area+8), mod.readI32(area+12))
	t.Logf("constructor result bytes: %v", raw[:16])
	handle := mod.readI32(area)
	mod.stackPop()

	// Is the handle plausible? A wasm resource pointer should point inside the
	// module's memory.
	size := mod.mod.Memory().Size()
	t.Logf("handle=%d memory size=%d (handle inside memory: %v)", handle, size, uint32(handle) < size)

	// 2. Now the call that traps, with function names available.
	prepareArgs := []string{
		"https://gateway.qoder.com.cn",
		"/api/v2/model/list?Encode=1",
		"GET",
		"auth",
		"",
		"",
	}
	area2, err := mod.stackPush()
	if err != nil {
		t.Fatalf("stackPush: %v", err)
	}
	params2 := []uint64{u64(area2), u64(handle)}
	for _, arg := range prepareArgs {
		if arg == "" {
			params2 = append(params2, 0, 0)
			continue
		}
		ptr, length, err := mod.pushString(arg)
		if err != nil {
			t.Fatalf("pushString: %v", err)
		}
		defer mod.free(ptr, length, 1)
		params2 = append(params2, u64(ptr), u64(length))
	}
	t.Logf("prepareRequest param count: %d", len(params2))
	if _, errCall := mod.call("qodercontext_prepareRequest", params2...); errCall != nil {
		t.Logf("prepareRequest error: %v", errCall)
		if runtimeErr, ok := errCall.(interface{ Error() string }); ok {
			t.Logf("prepareRequest error (string): %s", runtimeErr.Error())
		}
		return
	}
	t.Logf("prepareRequest succeeded: +0=%d +4=%d +8=%d", mod.readI32(area2), mod.readI32(area2+4), mod.readI32(area2+8))
	result := mod.readI32(area2)
	mod.stackPop()

	// 3. Walk the RequestResult accessors one at a time. Each is logged BEFORE it
	// is called, so the last line printed identifies whichever one traps.
	step := func(name string) {
		t.Logf("--- calling %s (handle=%d)", name, result)
	}
	step("requestresult_url")
	if area3, err := mod.stackPush(); err == nil {
		if _, errCall := mod.call("requestresult_url", u64(area3), u64(result)); errCall != nil {
			t.Logf("requestresult_url FAILED: %v", errCall)
			return
		}
		t.Logf("requestresult_url ok: ptr=%d len=%d", mod.readI32(area3), mod.readI32(area3+4))
		mod.free(mod.readI32(area3), mod.readI32(area3+4), 1)
		mod.stackPop()
	}
	step("requestresult_headerCount")
	if counts, errCall := mod.call("requestresult_headerCount", u64(result)); errCall != nil {
		t.Logf("requestresult_headerCount FAILED: %v", errCall)
		return
	} else {
		t.Logf("requestresult_headerCount ok: %v", counts)
	}
	step("requestresult_headers")
	if slots, errCall := mod.call("requestresult_headers", u64(result)); errCall != nil {
		t.Logf("requestresult_headers FAILED: %v", errCall)
		return
	} else {
		t.Logf("requestresult_headers ok: slots=%v", slots)
	}
	step("requestresult_body")
	if area4, err := mod.stackPush(); err == nil {
		if _, errCall := mod.call("requestresult_body", u64(area4), u64(result)); errCall != nil {
			t.Logf("requestresult_body FAILED: %v", errCall)
			return
		}
		t.Logf("requestresult_body ok: ptr=%d len=%d", mod.readI32(area4), mod.readI32(area4+4))
		mod.stackPop()
	}
	step("__wbg_requestresult_free")
	if _, errCall := mod.call("__wbg_requestresult_free", u64(result), 1); errCall != nil {
		t.Logf("free FAILED: %v", errCall)
		return
	}
	t.Logf("all RequestResult accessors ok")
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}
