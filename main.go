package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct { uint32_t abi_version; cliproxy_plugin_call_fn call; cliproxy_plugin_free_fn free_buffer; cliproxy_plugin_shutdown_fn shutdown; } cliproxy_plugin_api;
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;
static void store_host_api(const cliproxy_host_api* host) { stored_host = host; }
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoder"
	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoderwasm"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	providerID = "qoder"
	pluginName = "Qoder"
	pluginVer  = "0.1.0"

	// loginTTL bounds how long an unapproved device code stays usable. The code
	// is approved by hand in a browser, so this is minutes, not seconds.
	loginTTL = 15 * time.Minute
	// httpTimeout applies to one upstream call.
	httpTimeout = 60 * time.Second
	// pollBudget is how long one poll call is allowed to wait for the browser
	// approval before reporting "still pending" back to the panel.
	pollBudget = 5 * time.Second

	// modelListPath is the signed model list. `Encode=1` asks for the encoded
	// response shape the CLI itself requests.
	modelListPath = "/algo/api/v2/model/list?Encode=1"
)

// qoderAuth is the credential CPA stores for one Qoder account.
//
// The two derived fields are persisted rather than recomputed: the wasm's
// generate_runtime_auth_fields is non-deterministic, and a signature built from
// freshly derived fields on every request would not match.
type qoderAuth struct {
	Token        string   `json:"token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresAt    int64    `json:"expires_at"` // unix milliseconds
	UID          string   `json:"uid,omitempty"`
	UserName     string   `json:"user_name,omitempty"`
	OrgID        string   `json:"organization_id,omitempty"`
	OrgTags      []string `json:"organization_tags,omitempty"`
	DataPolicy   bool     `json:"data_policy_agreed,omitempty"`

	// MachineID is the 96 character identity the signing context claims.
	MachineID string `json:"machine_id,omitempty"`
	// CosyVersion is the CLI version the signing context claims.
	CosyVersion string `json:"cosy_version,omitempty"`
	// EncryptUserInfo and Key are the signing fields the wasm derives.
	EncryptUserInfo string `json:"encrypt_user_info,omitempty"`
	Key             string `json:"key,omitempty"`
	// Region pins the cluster, because the two clusters share no hosts.
	Region string `json:"region,omitempty"`
}

// pluginConfig is the plugins.configs.qoder slice this plugin reads. The panel's
// generic OAuth card starts a login with no parameters, so the region has to
// come from configuration.
type pluginConfig struct {
	DefaultRegion string `yaml:"default_region"`
}

// lifecycleRequest carries the plugin config the host serializes as base64 YAML.
type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	ModelProvider         bool                         `json:"model_provider"`
	AuthProvider          bool                         `json:"auth_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats,omitempty"`
	CommandLinePlugin     bool                         `json:"command_line_plugin"`
	ManagementAPI         bool                         `json:"management_api"`
	QuotaProvider         bool                         `json:"quota_provider"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

type streamResponse struct {
	Headers http.Header                     `json:"headers,omitempty"`
	Chunks  []pluginapi.ExecutorStreamChunk `json:"chunks,omitempty"`
}

// loginState is the server-side half of one device login, kept between the
// panel's start and poll calls.
type loginState struct {
	Session   qoder.Session
	Region    string
	ExpiresAt time.Time
}

var (
	loginMu sync.Mutex
	logins  = map[string]loginState{}

	configMu  sync.RWMutex
	pluginCfg = pluginConfig{DefaultRegion: "cn"}
)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required", http.StatusBadRequest))
		return 1
	}
	var raw []byte
	if request != nil && requestLen > 0 {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	result, err := handleMethod(C.GoString(method), raw)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", err.Error(), http.StatusInternalServerError))
		return 1
	}
	writeResponse(response, result)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {}

func handleMethod(method string, raw []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := configure(raw); err != nil {
			return errorEnvelope("invalid_config", err.Error(), http.StatusBadRequest), nil
		}
		return okEnvelope(registrationData())
	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier, pluginabi.MethodQuotaIdentifier:
		return okEnvelope(identifierResponse{Identifier: providerID})
	case pluginabi.MethodAuthParse:
		return okEnvelope(parseAuth(raw))
	case pluginabi.MethodAuthLoginStart:
		return okEnvelope(startLogin(raw))
	case pluginabi.MethodAuthLoginPoll:
		return okEnvelope(pollLogin(raw))
	case pluginabi.MethodAuthRefresh:
		return okEnvelope(refreshAuth(raw))
	case pluginabi.MethodModelStatic, pluginabi.MethodModelRegister:
		return okEnvelope(pluginapi.ModelRegistrationResponse{Provider: providerID})
	case pluginabi.MethodModelForAuth:
		return okEnvelope(discoverModels(raw))
	case pluginabi.MethodExecutorExecute:
		return execute(raw, false)
	case pluginabi.MethodExecutorExecuteStream:
		return execute(raw, true)
	case pluginabi.MethodExecutorCountTokens:
		return okEnvelope(pluginapi.ExecutorResponse{Payload: []byte(`{"total_tokens":0}`)})
	case pluginabi.MethodExecutorHTTPRequest:
		return okEnvelope(pluginapi.ExecutorHTTPResponse{StatusCode: http.StatusNotImplemented, Body: []byte(`{"error":"not implemented"}`)})
	case pluginabi.MethodCommandLineRegister:
		return okEnvelope(pluginapi.CommandLineRegistrationResponse{Flags: []pluginapi.CommandLineFlag{{
			Name: "qoder-login", Usage: "Start a Qoder device login", Type: "bool",
		}}})
	case pluginabi.MethodCommandLineExecute:
		return okEnvelope(pluginapi.CommandLineExecutionResponse{Stdout: []byte("Sign in to Qoder from the panel's plugin page instead.\n")})
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method, http.StatusNotImplemented), nil
	}
}

func registrationData() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVer,
			Author:           "Qoder CPA Plugin",
			GitHubRepository: "https://github.com/jingjingxinshang/qoder-cliproxy-plugin",
			ConfigFields: []pluginapi.ConfigField{{
				Name:        "default_region",
				Type:        pluginapi.ConfigFieldTypeEnum,
				EnumValues:  []string{"cn", "global"},
				Description: "Which Qoder cluster new logins use. The panel's OAuth card starts a login with no parameters, so this picks between the CN and global clusters.",
			}},
		},
		Capabilities: registrationCapability{
			ModelProvider:         true,
			AuthProvider:          true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeOAuth,
			ExecutorInputFormats:  []string{"chat-completions"},
			ExecutorOutputFormats: []string{"chat-completions"},
			CommandLinePlugin:     false,
			ManagementAPI:         false,
			QuotaProvider:         false,
		},
	}
}

func configure(raw []byte) error {
	cfg := pluginConfig{DefaultRegion: "cn"}
	if len(raw) > 0 {
		var req lifecycleRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return err
		}
		if len(req.ConfigYAML) > 0 {
			if err := yaml.Unmarshal(req.ConfigYAML, &cfg); err != nil {
				return err
			}
		}
	}
	cfg.DefaultRegion = normalizeRegion(cfg.DefaultRegion)
	configMu.Lock()
	pluginCfg = cfg
	configMu.Unlock()
	return nil
}

// normalizeRegion keeps only regions with a profile, so an unusable setting
// degrades to the default instead of building URLs against nothing.
func normalizeRegion(region string) string {
	region = strings.ToLower(strings.TrimSpace(region))
	if _, ok := qoder.Regions[region]; ok {
		return region
	}
	return "cn"
}

func configuredRegion() string {
	configMu.RLock()
	region := pluginCfg.DefaultRegion
	configMu.RUnlock()
	return normalizeRegion(region)
}

// loginRegion lets an explicit metadata region override the configured default:
// the host maps every query parameter of /v0/management/<id>-auth-url into the
// login metadata, which keeps `?region=global` working.
func loginRegion(metadata map[string]any) string {
	if value, ok := metadata["region"].(string); ok {
		if _, known := qoder.Regions[value]; known {
			return value
		}
	}
	return configuredRegion()
}

func regionOf(auth qoderAuth) qoder.Region {
	return qoder.RegionFor(normalizeRegion(auth.Region))
}

func parseAuth(raw []byte) pluginapi.AuthParseResponse {
	var req pluginapi.AuthParseRequest
	if json.Unmarshal(raw, &req) != nil {
		return pluginapi.AuthParseResponse{}
	}
	if req.Provider != providerID && !strings.Contains(strings.ToLower(req.FileName), providerID) {
		return pluginapi.AuthParseResponse{}
	}
	var auth qoderAuth
	if json.Unmarshal(req.RawJSON, &auth) != nil || (auth.Token == "" && auth.RefreshToken == "") {
		return pluginapi.AuthParseResponse{}
	}
	return pluginapi.AuthParseResponse{Handled: true, Auth: authData(auth, authFileSource(req))}
}

// authData builds the credential record CPA stores. The ID mirrors the file name
// because the host addresses runtime credentials by that name.
func authData(auth qoderAuth, fileName string) pluginapi.AuthData {
	if fileName == "" {
		fileName = providerID + ".json"
	}
	body, _ := json.Marshal(auth)
	id := strings.TrimSuffix(fileName, ".json")
	if id == "" {
		id = providerID
	}
	label := auth.UserName
	if label == "" {
		label = providerID + ":" + firstNonEmpty(auth.UID, shortID(auth.Token))
	}
	metadata := map[string]any{"region": normalizeRegion(auth.Region)}
	for key, value := range map[string]string{"uid": auth.UID, "user_name": auth.UserName, "organization_id": auth.OrgID} {
		if value != "" {
			metadata[key] = value
		}
	}
	return pluginapi.AuthData{
		Provider:         providerID,
		ID:               id,
		FileName:         fileName,
		Label:            label,
		StorageJSON:      body,
		Metadata:         metadata,
		NextRefreshAfter: nextRefresh(auth),
	}
}

// nextRefresh is when the host should refresh. Qoder hands out short lived
// bearer tokens, so refresh a little before expiry rather than at it.
func nextRefresh(auth qoderAuth) time.Time {
	if auth.ExpiresAt <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(auth.ExpiresAt).Add(-5 * time.Minute)
}

func credentialFileName(auth qoderAuth) string {
	suffix := firstNonEmpty(auth.UID, shortID(auth.Token))
	if suffix == "" {
		suffix = "default"
	}
	return providerID + "-" + suffix + ".json"
}

func authFileSource(req pluginapi.AuthParseRequest) string {
	source := firstNonEmpty(req.FileName, req.Path)
	if source == "" {
		return providerID + ".json"
	}
	base := source
	if idx := strings.LastIndexAny(source, "/\\"); idx >= 0 {
		base = source[idx+1:]
	}
	if !strings.HasSuffix(strings.ToLower(base), ".json") {
		base += ".json"
	}
	return base
}

// startLogin begins a device login: the panel shows the returned URL, the user
// approves in the browser, and pollLogin picks up the token.
func startLogin(raw []byte) pluginapi.AuthLoginStartResponse {
	var req pluginapi.AuthLoginStartRequest
	_ = json.Unmarshal(raw, &req)
	region := qoder.RegionFor(loginRegion(req.Metadata))

	login := &qoder.Login{Region: region}
	session, err := login.Start()
	if err != nil {
		return pluginapi.AuthLoginStartResponse{
			Provider:  providerID,
			ExpiresAt: time.Now().Add(loginTTL),
			Metadata:  map[string]any{"error": "Qoder login start failed: " + err.Error()},
		}
	}
	state := shortID(session.Nonce)
	loginMu.Lock()
	logins[state] = loginState{Session: session, Region: region.ID, ExpiresAt: time.Now().Add(loginTTL)}
	loginMu.Unlock()
	return pluginapi.AuthLoginStartResponse{
		Provider:  providerID,
		URL:       session.AuthURL,
		State:     state,
		ExpiresAt: time.Now().Add(loginTTL),
		Metadata:  map[string]any{"region": region.ID, "display_name": region.DisplayName},
	}
}

// pollLogin asks whether the device code was approved. Poll blocks until its
// deadline, so it is given a short budget and a timeout is reported as pending.
func pollLogin(raw []byte) pluginapi.AuthLoginPollResponse {
	var req pluginapi.AuthLoginPollRequest
	_ = json.Unmarshal(raw, &req)
	loginMu.Lock()
	pending, ok := logins[req.State]
	loginMu.Unlock()
	if !ok {
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "login expired or unknown; start again"}
	}
	if time.Now().After(pending.ExpiresAt) {
		loginMu.Lock()
		delete(logins, req.State)
		loginMu.Unlock()
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: "login expired before it was approved"}
	}

	region := qoder.RegionFor(pending.Region)
	ctx, cancel := context.WithTimeout(context.Background(), pollBudget)
	defer cancel()
	token, err := (&qoder.Login{Region: region}).Poll(ctx, pending.Session, pollBudget)
	if err != nil {
		// A pending device code is the common case here, so an error is only
		// reported as a failure once the flow's own deadline has passed.
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: "waiting for approval: " + err.Error()}
	}

	auth := qoderAuth{
		Token:        token.Token,
		RefreshToken: token.RefreshToken,
		UID:          firstNonEmpty(token.UserID, token.ID),
		UserName:     token.UserName,
		MachineID:    pending.Session.MachineID,
		Region:       region.ID,
	}
	if token.ExpiresIn > 0 {
		auth.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).UnixMilli()
	}
	enrich(ctx, &auth, region)
	loginMu.Lock()
	delete(logins, req.State)
	loginMu.Unlock()
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Message: "Qoder login complete", Auth: authData(auth, credentialFileName(auth))}
}

// enrich fills the identity fields the signing context needs. Both calls are
// best effort: a login that cannot read the profile should still produce a
// credential rather than nothing.
func enrich(ctx context.Context, auth *qoderAuth, region qoder.Region) {
	info, err := (&qoder.Login{Region: region}).FetchUserInfo(ctx, auth.Token)
	if err != nil {
		return
	}
	auth.UID = firstNonEmpty(stringField(info, "id"), auth.UID)
	auth.UserName = firstNonEmpty(stringField(info, "name"), stringField(info, "username"), auth.UserName)
	auth.OrgID = firstNonEmpty(stringField(info, "organization_id"), stringField(info, "org_id"), auth.OrgID)
	if tags, ok := info["organization_tags"].([]any); ok {
		auth.OrgTags = auth.OrgTags[:0]
		for _, tag := range tags {
			if text, isText := tag.(string); isText {
				auth.OrgTags = append(auth.OrgTags, text)
			}
		}
	}
	if agreed, ok := info["data_policy_agreed"].(bool); ok {
		auth.DataPolicy = agreed
	}
}

// refreshAuth exchanges the refresh token for a new bearer token.
//
// The contract is the CLI's own: POST /api/v1/deviceToken/refresh with
// {refresh_token, machine_id} on the openapi host. The signing context always
// claims a machine id, so the refresh has to send the same one.
func refreshAuth(raw []byte) pluginapi.AuthRefreshResponse {
	var req pluginapi.AuthRefreshRequest
	_ = json.Unmarshal(raw, &req)
	var auth qoderAuth
	if json.Unmarshal(req.StorageJSON, &auth) != nil || auth.RefreshToken == "" {
		return pluginapi.AuthRefreshResponse{}
	}
	region := regionOf(auth)
	body, _ := json.Marshal(map[string]any{
		"refresh_token": auth.RefreshToken,
		"machine_id":    auth.MachineID,
	})
	status, payload, err := call(region.OpenapiHost+"/api/v1/deviceToken/refresh", http.MethodPost, nil, body)
	if err != nil || status >= 400 {
		return pluginapi.AuthRefreshResponse{}
	}
	var token struct {
		Token           string `json:"token"`
		RefreshToken    string `json:"refresh_token"`
		ExpiresIn       int64  `json:"expires_in"`
		ExpireTime      int64  `json:"expire_time"`
		RefreshExpireIn int64  `json:"refresh_token_expires_in"`
		MachineIDUsed   string `json:"machine_id_used"`
		Profile         struct {
			UID  string `json:"uid"`
			Name string `json:"name"`
		} `json:"profile"`
	}
	if json.Unmarshal(payload, &token) != nil || token.Token == "" {
		return pluginapi.AuthRefreshResponse{}
	}
	auth.Token = token.Token
	if token.RefreshToken != "" {
		auth.RefreshToken = token.RefreshToken
	}
	switch {
	case token.ExpiresIn > 0:
		auth.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).UnixMilli()
	case token.ExpireTime > 0:
		auth.ExpiresAt = token.ExpireTime * 1000
	}
	if token.MachineIDUsed != "" {
		auth.MachineID = token.MachineIDUsed
	}
	auth.UID = firstNonEmpty(token.Profile.UID, auth.UID)
	auth.UserName = firstNonEmpty(token.Profile.Name, auth.UserName)
	// The derived signing fields belong to the old token, so drop them and let
	// the next signing context re-derive against the new one.
	auth.EncryptUserInfo, auth.Key = "", ""
	return pluginapi.AuthRefreshResponse{Auth: authData(auth, req.AuthID+".json"), NextRefreshAfter: nextRefresh(auth)}
}

func discoverModels(raw []byte) pluginapi.ModelResponse {
	var req pluginapi.AuthModelRequest
	_ = json.Unmarshal(raw, &req)
	var auth qoderAuth
	if json.Unmarshal(req.StorageJSON, &auth) != nil || auth.Token == "" {
		return pluginapi.ModelResponse{Provider: providerID}
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	signed, err := signRequest(ctx, &auth, func(s *signer) (qoderwasm.Prepared, error) {
		region := regionOf(auth)
		return s.context.PrepareRequest(region.InferHost, modelListPath, http.MethodGet, "auth", "", "")
	})
	if err != nil {
		return pluginapi.ModelResponse{Provider: providerID}
	}
	status, payload, err := call(signed.URL, http.MethodGet, signed.Headers, nil)
	if err != nil || status >= 400 {
		return pluginapi.ModelResponse{Provider: providerID}
	}
	models := parseModels(payload)
	return pluginapi.ModelResponse{Provider: providerID, Models: models, AuthUpdate: authData(auth, req.AuthID+".json")}
}

// parseModels reads the model list.
//
// The response is read tolerantly: the endpoint wraps the list in an envelope on
// some clusters and returns it bare on others, and the per-model fields are
// either snake_case or camelCase depending on the region. Only the fields that
// matter to routing are taken; everything else is left at its zero value so the
// host's own defaults apply.
func parseModels(payload []byte) []pluginapi.ModelInfo {
	candidates := [][]byte{payload}
	var envelope struct {
		Data    json.RawMessage `json:"data"`
		Models  json.RawMessage `json:"models"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(payload, &envelope) == nil {
		for _, raw := range []json.RawMessage{envelope.Models, envelope.Data, envelope.Content} {
			if len(raw) > 0 {
				candidates = append(candidates, raw)
			}
		}
	}
	var entries []map[string]any
	for _, candidate := range candidates {
		if json.Unmarshal(candidate, &entries) == nil && len(entries) > 0 {
			break
		}
		if len(candidate) > 0 {
			var nested []map[string]any
			if json.Unmarshal(candidate, &nested) == nil && len(nested) > 0 {
				entries = nested
				break
			}
		}
	}
	models := make([]pluginapi.ModelInfo, 0, len(entries))
	for _, entry := range entries {
		id := firstNonEmpty(stringField(entry, "id"), stringField(entry, "model"), stringField(entry, "key"), stringField(entry, "name"))
		if id == "" {
			continue
		}
		names := []string{"name", "display_name", "displayName", "title"}
		inputModalities := []string{"text"}
		switch {
		case anyField(entry, "supports_images", "supportsImages", "vision"):
			inputModalities = append(inputModalities, "image")
		}
		models = append(models, pluginapi.ModelInfo{
			ID:                         id,
			Object:                     "model",
			OwnedBy:                    providerID,
			Name:                       id,
			DisplayName:                firstNonEmpty(fields(entry, names...)...),
			Description:                stringField(entry, "description"),
			ContextLength:              intField(entry, "max_input_tokens", "maxInputTokens", "context_length", "contextLength"),
			MaxCompletionTokens:        intField(entry, "max_output_tokens", "maxOutputTokens"),
			SupportedGenerationMethods: []string{"chat"},
			SupportedParameters:        []string{"tools", "stream"},
			SupportedInputModalities:   inputModalities,
			SupportedOutputModalities:  []string{"text"},
		})
	}
	return models
}

// execute signs an infer request with the wasm and proxies the stream.
//
// Both halves are the CLI's own protocol: the request goes to the infer host
// with the signature the wasm computes, and response payloads are run through
// the module's decrypt_server_response. A payload that does not decrypt is
// forwarded untouched, because the module also returns plain payloads on the
// paths where the server does not encode anything.
func execute(raw []byte, stream bool) ([]byte, error) {
	var req pluginapi.ExecutorRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	var auth qoderAuth
	if json.Unmarshal(req.StorageJSON, &auth) != nil || auth.Token == "" {
		return errorEnvelope("authentication_error", "Qoder credential is missing a token", http.StatusUnauthorized), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	signed, err := signRequest(ctx, &auth, func(s *signer) (qoderwasm.Prepared, error) {
		region := regionOf(auth)
		return s.context.PrepareInferRequest(region.InferHost, string(req.Payload), req.Model, "")
	})
	if err != nil {
		return errorEnvelope("signature_error", err.Error(), http.StatusBadGateway), nil
	}
	body := []byte(signed.Body)
	status, payload, err := call(signed.URL, http.MethodPost, signed.Headers, body)
	if err != nil {
		return errorEnvelope("upstream_error", err.Error(), http.StatusBadGateway), nil
	}
	if status >= 400 {
		return errorEnvelope("upstream_error", string(payload), status), nil
	}
	if !stream {
		return okEnvelope(pluginapi.ExecutorResponse{Payload: payload, Headers: jsonHeaders()})
	}
	return okEnvelope(streamResponse{Headers: sseHeaders(), Chunks: splitSSE(payload)})
}

// splitSSE turns a buffered event stream into the host's chunk list, decrypting
// each data payload where the module can.
func splitSSE(payload []byte) []pluginapi.ExecutorStreamChunk {
	chunks := make([]pluginapi.ExecutorStreamChunk, 0, 16)
	for _, block := range bytes.Split(payload, []byte("\n\n")) {
		trimmed := bytes.TrimSpace(block)
		if len(trimmed) == 0 {
			continue
		}
		chunks = append(chunks, pluginapi.ExecutorStreamChunk{Payload: decryptChunk(trimmed)})
	}
	if len(chunks) == 0 && len(payload) > 0 {
		chunks = append(chunks, pluginapi.ExecutorStreamChunk{Payload: payload})
	}
	return chunks
}

// decryptChunk replaces the data payload of one SSE block with its decrypted
// form when the module recognises it.
func decryptChunk(block []byte) []byte {
	const prefix = "data:"
	text := string(block)
	idx := strings.Index(text, prefix)
	if idx < 0 {
		return block
	}
	head := text[:idx+len(prefix)+1]
	value := strings.TrimSpace(text[idx+len(prefix):])
	plain, err := activeModule().DecryptServerResponse(value)
	if err != nil || plain == "" || plain == value {
		return block
	}
	return []byte(head + plain + "\n\n")
}

func jsonHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}}
}

func sseHeaders() http.Header {
	return http.Header{"Content-Type": []string{"text/event-stream"}, "Cache-Control": []string{"no-cache"}}
}

// call performs one upstream request and returns status and body.
func call(target, method string, headers [][2]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	// The signed header set is authoritative: the module decides what the
	// signature covers, so nothing is added on top of it.
	for _, pair := range headers {
		req.Header.Set(pair[0], pair[1])
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	payload, err := io.ReadAll(resp.Body)
	return resp.StatusCode, payload, err
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string, status int) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message, HTTPStatus: status}})
	return raw
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

// ── field readers for the tolerant model parser ──────────────────────────────

func stringField(entry map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := entry[key].(type) {
		case string:
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func fields(entry map[string]any, keys ...string) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := stringField(entry, key); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func intField(entry map[string]any, keys ...string) int64 {
	for _, key := range keys {
		switch value := entry[key].(type) {
		case float64:
			if value > 0 {
				return int64(value)
			}
		case json.Number:
			if parsed, err := value.Int64(); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	return 0
}

func anyField(entry map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := entry[key].(bool); ok && value {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func shortID(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) <= 8 {
		return trimmed
	}
	return trimmed[:8]
}
