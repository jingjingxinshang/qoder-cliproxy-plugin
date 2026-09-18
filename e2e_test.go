package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoder"
	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoderwasm"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestE2ESignedTraffic walks the whole signed path against the live service,
// using the same helpers the plugin uses. It exists because exactly one thing in
// the plugin is unverified: the shape of the infer request body. Everything else
// — the device login, the signature, the response decoding — can be settled here
// in one run, with the only human step being the one approval the device flow
// needs by design.
//
//	QODER_E2E=1 QODER_E2E_REGION=cn go test . -run TestE2ESignedTraffic -v -timeout 15m
//
// It is skipped unless QODER_E2E is set, so the normal suite stays offline.
func TestE2ESignedTraffic(t *testing.T) {
	if os.Getenv("QODER_E2E") == "" {
		t.Skip("set QODER_E2E=1 to run the live end-to-end check")
	}
	region := qoder.RegionFor(envOr("QODER_E2E_REGION", "cn"))
	t.Logf("region %s: openapi=%s infer=%s", region.ID, region.OpenapiHost, region.InferHost)

	// ── 1. the device login ─────────────────────────────────────────────────
	login := &qoder.Login{Region: region}
	session, err := login.Start()
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	t.Logf("========================================================")
	t.Logf("APPROVE THIS URL IN YOUR BROWSER: %s", session.AuthURL)
	t.Logf("========================================================")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	token, err := login.Poll(ctx, session, 5*time.Minute)
	if err != nil {
		t.Fatalf("login poll: %v", err)
	}
	t.Logf("token acquired: id=%s user=%s expires_in=%d", token.ID, token.UserName, token.ExpiresIn)

	auth := qoderAuth{
		Token:        token.Token,
		RefreshToken: token.RefreshToken,
		UID:          firstNonEmpty(token.UserID, token.ID),
		UserName:     token.UserName,
		MachineID:    session.MachineID,
		Region:       region.ID,
	}
	if token.ExpiresIn > 0 {
		auth.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).UnixMilli()
	}
	enrich(ctx, &auth, region)
	t.Logf("identity: uid=%s user=%s org=%s tags=%v", auth.UID, auth.UserName, auth.OrgID, auth.OrgTags)
	if auth.UID == "" {
		t.Errorf("no uid: the signing context needs one")
	}

	// ── 2. the signed model list ────────────────────────────────────────────
	// This is the step that proves the signature is accepted by the server, so
	// its failure mode is reported in full rather than summarised.
	models, raw := e2eDiscoverModels(t, &auth)
	if len(models) == 0 {
		t.Fatalf("no models discovered; raw response was:\n%s", truncateForLog(raw, 1200))
	}
	for i, model := range models {
		if i < 12 {
			t.Logf("model: %s  (%s)", model.ID, model.DisplayName)
		}
	}
	t.Logf("discovered %d models", len(models))

	// ── 3. the signed chat request ──────────────────────────────────────────
	// The payload shape is the open question. The server's answer decides it: an
	// accepted request returns a stream we can decrypt, and a rejected one
	// names the field it wanted. Both outcomes are printed verbatim.
	target := firstNonEmpty(os.Getenv("QODER_E2E_MODEL"), models[0].ID)
	module, errModule := activeModuleFor(regionOf(auth))
	if errModule != nil {
		t.Fatalf("load signing module: %v", errModule)
	}
	e2eChat(t, &auth, target, module)
}

// e2eDiscoverModels signs and sends the model list, returning the parsed models
// and the raw body either way.
func e2eDiscoverModels(t *testing.T, auth *qoderAuth) ([]pluginapi.ModelInfo, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	module, errModule := activeModuleFor(regionOf(*auth))
	if errModule != nil {
		t.Fatalf("load signing module: %v", errModule)
	}

	signed, err := signRequest(ctx, auth, func(s *signer) (qoderwasm.Prepared, error) {
		return s.context.PrepareRequest(regionOf(*auth).InferHost, modelListPath, "GET", "auth", "", "")
	})
	if err != nil {
		t.Fatalf("sign model list: %v", err)
	}
	t.Logf("signed model list url: %s", signed.URL)
	t.Logf("signature headers: %d", len(signed.Headers))
	for _, pair := range signed.Headers {
		t.Logf("  %s: %s", pair[0], truncateForLog(pair[1], 60))
	}

	status, payload, err := call(signed.URL, "GET", signed.Headers, nil)
	if err != nil {
		t.Fatalf("model list request: %v", err)
	}
	t.Logf("model list status=%d bytes=%d", status, len(payload))
	if status >= 400 {
		t.Logf("model list body: %s", truncateForLog(string(payload), 1200))
		return nil, string(payload)
	}
	models := parseModels(payload, module)
	if len(models) == 0 {
		models = fallbackModels(payload)
	}
	return models, string(payload)
}

// e2eChat signs an infer request and reports exactly what came back, including
// the decrypted form so the response decoder is exercised too.
func e2eChat(t *testing.T, auth *qoderAuth, model string, module *qoderwasm.Module) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	// The two shapes worth trying: the chat-completions payload the host hands
	// the executor, and the same payload with the stream flag the CLI sets.
	payload := fmt.Sprintf(`{"model":%q,"stream":true,"messages":[{"role":"user","content":"say ok"}]}`, model)
	t.Logf("infer body attempt: %s", payload)

	signed, err := signRequest(ctx, auth, func(s *signer) (qoderwasm.Prepared, error) {
		return s.context.PrepareInferRequest(regionOf(*auth).InferHost, payload, model, "")
	})
	if err != nil {
		t.Fatalf("sign infer: %v", err)
	}
	t.Logf("signed infer url: %s", signed.URL)
	if signed.Body != "" {
		t.Logf("signed infer body (%d bytes): %s", len(signed.Body), truncateForLog(signed.Body, 600))
	}

	status, body, err := call(signed.URL, "POST", signed.Headers, []byte(signed.Body))
	if err != nil {
		t.Fatalf("infer request: %v", err)
	}
	t.Logf("infer status=%d bytes=%d", status, len(body))
	t.Logf("infer raw response: %s", truncateForLog(string(body), 1500))

	if status >= 400 {
		t.Errorf("infer rejected with %d — the body shape is what needs fixing", status)
		return
	}
	for i, chunk := range splitSSE(body, module) {
		if i < 6 {
			t.Logf("chunk %d: %s", i, truncateForLog(string(chunk.Payload), 300))
		}
	}
}

// fallbackModels reads any id-shaped field out of an unexpected response, so an
// unrecognised envelope still yields something to try chatting with.
func fallbackModels(payload []byte) []pluginapi.ModelInfo {
	var loose struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(payload, &loose)
	out := []pluginapi.ModelInfo{}
	for _, candidate := range []json.RawMessage{payload, loose.Data} {
		var entries []map[string]any
		if len(candidate) == 0 || json.Unmarshal(candidate, &entries) != nil {
			continue
		}
		for _, entry := range entries {
			id := firstNonEmpty(stringField(entry, "id"), stringField(entry, "model"), stringField(entry, "name"))
			if id != "" {
				out = append(out, pluginapi.ModelInfo{ID: id, DisplayName: id})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func truncateForLog(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}
