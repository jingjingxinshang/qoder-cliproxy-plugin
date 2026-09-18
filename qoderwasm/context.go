package qoderwasm

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// QoderContext is a signing context. One is created per request: it carries the
// machine id, CLI version and the auth-derived fields the server verifies, and
// the module mutates internal state (nonces, timestamps) as it signs.
type QoderContext struct {
	module *Module
	handle int32
}

// Prepared is a signed request the caller can send as-is.
type Prepared struct {
	URL     string
	Headers [][2]string
	Body    string
}

// Header looks a header up by name, case-insensitively.
func (p Prepared) Header(name string) (string, bool) {
	for _, pair := range p.Headers {
		if equalFold(pair[0], name) {
			return pair[1], true
		}
	}
	return "", false
}

// AuthFields are the two values the module derives from the user info.
type AuthFields struct {
	// EncryptUserInfo and Key must both be present in the signing context, or
	// the infer host answers HTTP 403 "Signature invalid".
	EncryptUserInfo string
	Key             string
}

// UserInfoForAuth is the subset of the stored credential the signing context
// needs, mirroring what the CLI hands the module.
type UserInfoForAuth struct {
	UID             string `json:"uid"`
	EncryptUserInfo string `json:"encrypt_user_info,omitempty"`
	Key             string `json:"key,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	// OrganizationTags is forwarded verbatim because the module validates its
	// shape itself: it wants a sequence, and real credentials have been seen
	// carrying it as one. Modelling it as a string here was rejected by the
	// module with "invalid type: string, expected a sequence".
	OrganizationTags any   `json:"organization_tags,omitempty"`
	DataPolicyAgreed *bool `json:"data_policy_agreed,omitempty"`
}

// ClientInfo identifies the client to the server. These four values are the
// CLI's defaults; any other combination is rejected as an invalid signature.
type ClientInfo struct {
	ClientType      string `json:"client_type"`
	BusinessProduct string `json:"business_product"`
	BusinessType    string `json:"business_type"`
	Scene           string `json:"scene"`
}

// NewClientInfo returns the client identity the CLI presents.
func NewClientInfo() ClientInfo {
	return ClientInfo{ClientType: "5", BusinessProduct: "cli", BusinessType: "agent", Scene: "assistant"}
}

// GenerateAuthFields derives the two signing fields from a full credential.
func (m *Module) GenerateAuthFields(credentialJSON string) (AuthFields, error) {
	raw, err := m.GenerateRuntimeAuthFields(credentialJSON)
	if err != nil {
		return AuthFields{}, err
	}
	var payload struct {
		EncryptUserInfo string `json:"encrypt_user_info"`
		Key             string `json:"key"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return AuthFields{}, fmt.Errorf("qoder derived auth fields are not JSON: %w", err)
	}
	if payload.EncryptUserInfo == "" || payload.Key == "" {
		return AuthFields{}, errors.New("qoder derived auth fields are empty")
	}
	return AuthFields{EncryptUserInfo: payload.EncryptUserInfo, Key: payload.Key}, nil
}

// NewContext builds a signing context.
func (m *Module) NewContext(machineID, cosyVersion string, userInfo UserInfoForAuth, clientInfo ClientInfo) (*QoderContext, error) {
	userJSON, err := json.Marshal(userInfo)
	if err != nil {
		return nil, fmt.Errorf("encode signing user info: %w", err)
	}
	clientJSON, err := json.Marshal(clientInfo)
	if err != nil {
		return nil, fmt.Errorf("encode signing client info: %w", err)
	}
	handle, err := m.callResourceFunction("qodercontext_new",
		machineID, cosyVersion, string(userJSON), string(clientJSON))
	if err != nil {
		return nil, err
	}
	return &QoderContext{module: m, handle: handle}, nil
}

// PrepareRequest signs a plain request (model list, uploads).
func (c *QoderContext) PrepareRequest(endpoint, path, method, authMode, body, headersJSON string) (Prepared, error) {
	if c == nil || c.module == nil {
		return Prepared{}, errors.New("qoder signing context is nil")
	}
	handle, err := c.module.callResourceMethod("qodercontext_prepareRequest", c.handle,
		endpoint, path, method, authMode, body, headersJSON)
	if err != nil {
		return Prepared{}, err
	}
	return c.module.readPrepared(handle)
}

// PrepareInferRequest signs an infer (chat) request, which also encodes the body.
func (c *QoderContext) PrepareInferRequest(endpoint, bodyJSON, modelKey, modelSource string) (Prepared, error) {
	if c == nil || c.module == nil {
		return Prepared{}, errors.New("qoder signing context is nil")
	}
	handle, err := c.module.callResourceMethod("qodercontext_prepareInferRequest", c.handle,
		endpoint, bodyJSON, modelKey, modelSource)
	if err != nil {
		return Prepared{}, err
	}
	return c.module.readPrepared(handle)
}

// RefreshAuthFields re-derives the auth fields inside an existing context.
func (c *QoderContext) RefreshAuthFields(credentialJSON string) error {
	if c == nil || c.module == nil {
		return errors.New("qoder signing context is nil")
	}
	area, err := c.module.stackPush()
	if err != nil {
		return err
	}
	defer c.module.stackPop()

	ptr, length, err := c.module.pushString(credentialJSON)
	if err != nil {
		return err
	}
	// Not freed: the module takes ownership of its String parameters.

	if _, errCall := c.module.call("qodercontext_refreshAuthFields", u64(area), u64(c.handle), u64(ptr), u64(length)); errCall != nil {
		return errCall
	}
	// This export reports only an error flag, at area+4.
	if flag := c.module.readI32(area + 4); flag != 0 {
		return jsThrow{message: c.module.errorMessage(c.module.readI32(area))}
	}
	return nil
}

// Free releases the context. The module keeps signing state inside the handle,
// so a context must not be reused after it is freed.
func (c *QoderContext) Free() {
	if c == nil || c.module == nil || c.handle == 0 {
		return
	}
	c.module.freeResource("__wbg_qodercontext_free", c.handle)
	c.handle = 0
}

// ── plumbing for the resource-returning exports ──────────────────────────────

// callResourceFunction invokes an export that returns a resource handle and has
// no receiver. `qodercontext_new` is a free function; only the methods take a
// handle, and passing one where the module expects a string pointer is a
// mismatch the module reports as "expected N params".
func (m *Module) callResourceFunction(name string, args ...string) (int32, error) {
	return m.callResourceArgs(name, 0, args)
}

// callResourceMethod invokes a resource-returning export that takes a receiver.
func (m *Module) callResourceMethod(name string, this int32, args ...string) (int32, error) {
	return m.callResourceArgs(name, this, args)
}

// callResourceArgs invokes an export that returns a resource handle. Empty
// strings are passed as null, exactly as the glue does with `Iq(x) ? 0 : ...`,
// because several of these arguments are optional. A zero receiver means "no
// receiver", which is how the constructor is called.
//
// The argument buffers are deliberately not freed: wasm-bindgen generates
// `String` parameters, so the module takes ownership of them and drops them
// itself. The generated glue's `finally` block restores the stack pointer and
// nothing else. Freeing them here hands the module's allocator a pointer it
// already owns, which corrupts the heap quietly and only shows up later, as an
// out-of-bounds trap inside the next export that allocates. That double free is
// what made prepareRequest look like it could not sign at all.
func (m *Module) callResourceArgs(name string, this int32, args []string) (int32, error) {
	area, err := m.stackPush()
	if err != nil {
		return 0, err
	}
	defer m.stackPop()

	params := []uint64{u64(area)}
	if this != 0 {
		params = append(params, u64(this))
	}
	for _, arg := range args {
		if arg == "" {
			params = append(params, 0, 0)
			continue
		}
		ptr, length, errPush := m.pushString(arg)
		if errPush != nil {
			return 0, errPush
		}
		params = append(params, u64(ptr), u64(length))
	}

	if _, errCall := m.call(name, params...); errCall != nil {
		return 0, errCall
	}
	return m.readResourceResult(area)
}

// readResourceResult decodes the 12-byte area the resource exports write into:
// handle, error value (a heap slot), error flag.
func (m *Module) readResourceResult(area int32) (int32, error) {
	handle := m.readI32(area)
	errValue := m.readI32(area + 4)
	errFlag := m.readI32(area + 8)
	if errFlag != 0 {
		return 0, jsThrow{message: m.errorMessage(errValue)}
	}
	return handle, nil
}

// errorMessage turns a parked JavaScript error into a Go error message.
func (m *Module) errorMessage(slot int32) string {
	switch value := m.take(slot).(type) {
	case jsError:
		return value.message
	case jsString:
		return string(value)
	default:
		return "qoder signing failed"
	}
}

func (m *Module) freeResource(name string, handle int32) {
	_, _ = m.call(name, u64(handle), 1)
}

// readPrepared reads a RequestResult and releases it.
func (m *Module) readPrepared(handle int32) (Prepared, error) {
	defer m.freeResource("__wbg_requestresult_free", handle)

	url, err := m.readResultString("requestresult_url", handle)
	if err != nil {
		return Prepared{}, err
	}
	body, err := m.readResultString("requestresult_body", handle)
	if err != nil {
		return Prepared{}, err
	}
	headers, err := m.readResultHeaders(handle)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{URL: url, Headers: headers, Body: body}, nil
}

// readResultString reads one of the RequestResult string getters, which write
// (pointer, length) into the stack area and hand ownership to the caller.
func (m *Module) readResultString(name string, handle int32) (string, error) {
	area, err := m.stackPush()
	if err != nil {
		return "", err
	}
	defer m.stackPop()

	if _, errCall := m.call(name, u64(area), u64(handle)); errCall != nil {
		return "", errCall
	}
	ptr := m.readI32(area)
	length := m.readI32(area + 4)
	if ptr == 0 || length == 0 {
		return "", nil
	}
	value, errRead := m.readString(ptr, length)
	m.free(ptr, length, 1)
	if errRead != nil {
		return "", errRead
	}
	return value, nil
}

// readResultHeaders reads the header Map. The header count export is not used:
// the Map is the authoritative list, and reading it directly keeps the ordering
// the module produced.
func (m *Module) readResultHeaders(handle int32) ([][2]string, error) {
	results, err := m.call("requestresult_headers", u64(handle))
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("requestresult_headers returned nothing")
	}
	// The slot was allocated by the module through the object heap; taking it
	// mirrors the glue's `Gb(slot)`.
	value := m.take(int32(uint32(results[0])))
	headers := value.(jsMap)
	return headers.pairs(), nil
}

// pairs flattens a JavaScript Map into key/value pairs in insertion order.
func (m jsMap) pairs() [][2]string {
	out := make([][2]string, 0, len(m.keys))
	for _, key := range m.keys {
		value, ok := m.values[key]
		if !ok {
			continue
		}
		out = append(out, [2]string{key, stringify(value)})
	}
	return out
}

func stringify(value any) string {
	switch v := value.(type) {
	case jsString:
		return string(v)
	case jsNumber:
		return trimFloat(float64(v))
	case jsBool:
		if v {
			return "true"
		}
		return "false"
	case nil, jsUndefined, jsNullT:
		return ""
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(encoded)
	}
}

// trimFloat renders numbers the way a header value would appear.
func trimFloat(value float64) string {
	if value == float64(int64(value)) {
		return fmt.Sprintf("%d", int64(value))
	}
	return fmt.Sprintf("%g", value)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// SortHeaders orders header names, for stable diagnostics.
func SortHeaders(pairs [][2]string) [][2]string {
	out := append([][2]string(nil), pairs...)
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}
