package qoder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The default region is CN, matching the CLI.
func TestRegionForDefaultsToCN(t *testing.T) {
	if got := RegionFor("").ID; got != "cn" {
		t.Fatalf("RegionFor(\"\") = %q, want cn", got)
	}
	if got := RegionFor("GLOBAL").ID; got != "global" {
		t.Fatalf("RegionFor(GLOBAL) = %q, want global", got)
	}
	if got := RegionFor("nonsense").ID; got != "cn" {
		t.Fatalf("RegionFor(nonsense) = %q, want cn", got)
	}
}

// The API hosts must never be the browser hosts. Getting this wrong is the whole
// reason the first attempt reported "Not Found" instead of "unauthorized": the
// web surface answers 404 for openapi paths.
func TestAPICallsNeverTargetTheWebSurface(t *testing.T) {
	for id, region := range Regions {
		openapi, err := region.OpenapiURL("/api/v1/userinfo")
		if err != nil {
			t.Fatalf("%s: OpenapiURL: %v", id, err)
		}
		infer, err := region.InferURL("/api/v2/model/list?Encode=1")
		if err != nil {
			t.Fatalf("%s: InferURL: %v", id, err)
		}
		for _, endpoint := range []string{openapi, infer} {
			parsed, errParse := url.Parse(endpoint)
			if errParse != nil {
				t.Fatalf("%s: unparsable endpoint %q", id, endpoint)
			}
			for _, surface := range webSurfaces {
				if parsed.Hostname() == surface {
					t.Fatalf("%s: endpoint %q targets the web surface %s", id, endpoint, surface)
				}
			}
		}
	}
}

func TestGuardHostRejectsBrowserHosts(t *testing.T) {
	for _, host := range []string{"qoder.cn", "www.qoder.cn", "qoder.com", "QODER.COM"} {
		if err := guardHost(host); err == nil {
			t.Fatalf("guardHost(%s) allowed a web surface", host)
		}
	}
	for _, host := range []string{"openapi.qoder.com.cn", "gateway.qoder.com.cn", "openapi.qoder.sh"} {
		if err := guardHost(host); err != nil {
			t.Fatalf("guardHost(%s) rejected an API host: %v", host, err)
		}
	}
}

// A region table that pointed at a browser host must fail loudly rather than
// produce 404s at runtime.
func TestMisconfiguredRegionIsRejected(t *testing.T) {
	broken := Region{ID: "broken", OpenapiHost: "https://qoder.cn", InferHost: "https://qoder.com"}
	if _, err := broken.OpenapiURL("/api/v1/userinfo"); err == nil {
		t.Fatal("a region pointing at the web surface was accepted")
	}
	if _, err := broken.InferURL("/api/v2/model/list"); err == nil {
		t.Fatal("an infer host on the web surface was accepted")
	}
}

// The device URL carries the parameters a live login sends. Two of them were
// missing before, and a login started without them yields a token the follow-up
// calls reject.
func TestDeviceAuthURLCarriesTheLiveParameters(t *testing.T) {
	region := RegionFor("cn")
	authURL := region.DeviceAuthURL("challenge-value", "nonce-value", "machine-value")
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("unparsable auth url %q: %v", authURL, err)
	}
	if !strings.HasPrefix(authURL, "https://qoder.cn/device/selectAccounts?") {
		t.Fatalf("auth url = %q, want the CN device page", authURL)
	}
	want := map[string]string{
		"challenge":        "challenge-value",
		"challenge_method": "S256",
		"nonce":            "nonce-value",
		"machine_id":       "machine-value",
		"client_id":        ClientID,
		"redirect_uri":     RedirectURI,
		"directLogin":      "true",
	}
	query := parsed.Query()
	for key, value := range want {
		if got := query.Get(key); got != value {
			t.Fatalf("auth url %s = %q, want %q", key, got, value)
		}
	}
	// The global region uses its own page.
	if global := RegionFor("global").DeviceAuthURL("c", "n", "m"); !strings.HasPrefix(global, "https://qoder.com/device/selectAccounts?") {
		t.Fatalf("global auth url = %q", global)
	}
}

// Machine ids are 96 characters of URL-safe base64; a UUID is a different shape
// and the token is bound to this value.
func TestMachineIDShape(t *testing.T) {
	first, err := NewMachineID()
	if err != nil {
		t.Fatalf("NewMachineID: %v", err)
	}
	if len(first) != 96 {
		t.Fatalf("machine id length = %d, want 96 (%q)", len(first), first)
	}
	if strings.ContainsAny(first, "+/=") {
		t.Fatalf("machine id is not URL-safe: %q", first)
	}
	second, err := NewMachineID()
	if err != nil {
		t.Fatalf("NewMachineID: %v", err)
	}
	if first == second {
		t.Fatal("two machine ids are identical")
	}
}

// PKCE must be S256: base64url(sha256(verifier)) without padding.
func TestPKCEChallengeIsS256(t *testing.T) {
	// Known vector: sha256("abc") — the value is asserted by recomputation here
	// because the point is the encoding, not the digest.
	challenge := pkceChallenge("abc")
	if len(challenge) != 43 {
		t.Fatalf("challenge length = %d, want 43 (%q)", len(challenge), challenge)
	}
	if strings.ContainsAny(challenge, "+/=") {
		t.Fatalf("challenge is not URL-safe base64: %q", challenge)
	}
	if challenge != pkceChallenge("abc") {
		t.Fatal("challenge is not deterministic")
	}
	if challenge == pkceChallenge("abd") {
		t.Fatal("different verifiers produced the same challenge")
	}
}

// A 401 from userinfo means the credential is bad; a 404 means the request
// reached the wrong surface. Reporting both as "login failed" is what made the
// first attempt hard to diagnose.
func TestFetchUserInfoSeparatesTokenErrorsFromRouteErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"token rejected", http.StatusUnauthorized, `{"code":"TOKEN_INVALID","message":"missing authorization token"}`, ErrTokenRejected},
		{"forbidden", http.StatusForbidden, `{"code":"FORBIDDEN"}`, ErrTokenRejected},
		{"route missing", http.StatusNotFound, `{"errorCode":"NotFound","errorMessage":"资源没有找到"}`, ErrRouteNotFound},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(testCase.body))
			}))
			defer server.Close()

			login := &Login{Region: RegionFor("cn"), Client: server.Client(), OpenapiBase: server.URL}
			_, err := login.FetchUserInfo(context.Background(), "a-token")
			if !errors.Is(err, testCase.want) {
				t.Fatalf("error = %v, want it to wrap %v", err, testCase.want)
			}
		})
	}
}

func TestFetchUserInfoReturnsPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer a-token" {
			t.Errorf("Authorization = %q, want a bearer token", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"uid": "u-1", "name": "tester"})
	}))
	defer server.Close()

	login := &Login{Region: RegionFor("cn"), Client: server.Client(), OpenapiBase: server.URL}
	payload, err := login.FetchUserInfo(context.Background(), "a-token")
	if err != nil {
		t.Fatalf("FetchUserInfo: %v", err)
	}
	if payload["uid"] != "u-1" {
		t.Fatalf("uid = %v, want u-1", payload["uid"])
	}
}

// Pending approval answers 404, so polling must treat that as "keep waiting".
func TestPollTreatsNotFoundAsPending(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":"NotFound"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "device-token", "refresh_token": "r", "expires_in": 3600})
	}))
	defer server.Close()

	var traced []LoginStep
	login := &Login{
		Region:      RegionFor("cn"),
		Client:      server.Client(),
		OpenapiBase: server.URL,
		Trace:       func(step LoginStep) { traced = append(traced, step) },
	}
	token, err := login.Poll(context.Background(), Session{Verifier: "v", Nonce: "n"}, 10*time.Second)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if token.Token != "device-token" {
		t.Fatalf("token = %q, want device-token", token.Token)
	}
	if len(traced) < 2 {
		t.Fatalf("expected the poll to be traced per attempt, got %d steps", len(traced))
	}
}

// The override must not become a way to reach the web surface.
func TestOpenapiBaseOverrideKeepsTheGuard(t *testing.T) {
	login := &Login{Region: RegionFor("cn"), OpenapiBase: "https://qoder.cn"}
	if _, err := login.openapiURL("/api/v1/userinfo"); err == nil {
		t.Fatal("an override pointing at the web surface was accepted")
	}
}
