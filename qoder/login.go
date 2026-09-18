package qoder

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MachineIDBytes is the entropy behind a machine id.
//
// Live machine ids look like `P1gAQol-efotCxvcE7pVMMdMHnBKoD6phQAEkYuQS7LSfdrpUKn…`,
// i.e. 96 characters of URL-safe base64 — about 72 bytes. The first
// implementation generated a 36-character UUID instead, which is a different
// shape entirely; the device login binds its token to this value, so the shape
// matters.
const MachineIDBytes = 72

// LoginStep is one hop of the device flow, reported so a failure names itself
// instead of surfacing as a bare "login failed".
type LoginStep struct {
	Method string
	URL    string
	Status int
	Detail string
}

// Tracer receives each hop. Plugin code logs these; tests assert on them.
type Tracer func(step LoginStep)

// Login drives the device-code flow for one region.
type Login struct {
	Region Region
	Client *http.Client
	Trace  Tracer
	// OpenapiBase overrides the region's openapi host. Tests point it at a stub
	// server; operators can point it at a proxy. The web-surface guard still
	// applies, so an override cannot quietly send API calls to the browser host.
	OpenapiBase string
}

// openapiURL resolves a path against the override when set, the region
// otherwise.
func (l *Login) openapiURL(path string) (string, error) {
	if l.OpenapiBase == "" {
		return l.Region.OpenapiURL(path)
	}
	parsed, err := url.Parse(l.OpenapiBase)
	if err != nil {
		return "", fmt.Errorf("openapi base %q is unparsable: %w", l.OpenapiBase, err)
	}
	if errGuard := guardHost(parsed.Hostname()); errGuard != nil {
		return "", errGuard
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(l.OpenapiBase, "/") + path, nil
}

func (l *Login) client() *http.Client {
	if l.Client != nil {
		return l.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (l *Login) trace(step LoginStep) {
	if l.Trace != nil {
		l.Trace(step)
	}
}

// Session is a started device login waiting for the user to approve it.
type Session struct {
	Verifier  string
	Nonce     string
	MachineID string
	AuthURL   string
}

// Start begins a device login. The caller shows AuthURL to the user.
func (l *Login) Start() (Session, error) {
	verifier, err := randomURLSafe(64)
	if err != nil {
		return Session{}, err
	}
	challenge := pkceChallenge(verifier)
	nonce, err := randomHex(32)
	if err != nil {
		return Session{}, err
	}
	machineID, err := NewMachineID()
	if err != nil {
		return Session{}, err
	}
	return Session{
		Verifier:  verifier,
		Nonce:     nonce,
		MachineID: machineID,
		AuthURL:   l.Region.DeviceAuthURL(challenge, nonce, machineID),
	}, nil
}

// Poll waits for the user to approve the login and returns the device token.
//
// The endpoint answers 404 while the approval is still pending, which is why a
// not-found here is "keep waiting" and never an error.
func (l *Login) Poll(ctx context.Context, session Session, deadline time.Duration) (DeviceToken, error) {
	endpoint, err := l.openapiURL("/api/v1/deviceToken/poll")
	if err != nil {
		return DeviceToken{}, err
	}
	query := url.Values{}
	query.Set("nonce", session.Nonce)
	query.Set("verifier", session.Verifier)
	query.Set("challenge_method", "S256")
	endpoint += "?" + query.Encode()

	stop := time.Now().Add(deadline)
	for {
		if errContext := ctx.Err(); errContext != nil {
			return DeviceToken{}, errContext
		}
		if time.Now().After(stop) {
			return DeviceToken{}, fmt.Errorf("qoder device login timed out after %s", deadline)
		}

		status, body, errCall := l.get(ctx, endpoint, "")
		if errCall != nil {
			return DeviceToken{}, errCall
		}
		l.trace(LoginStep{Method: http.MethodGet, URL: endpoint, Status: status})
		switch status {
		case http.StatusNotFound:
			// Still pending.
		case http.StatusOK:
			var token DeviceToken
			if errUnmarshal := json.Unmarshal(body, &token); errUnmarshal != nil {
				return DeviceToken{}, fmt.Errorf("device token response is not JSON: %w", errUnmarshal)
			}
			if token.Token == "" {
				return DeviceToken{}, fmt.Errorf("device token response carried no token: %s", truncate(body, 200))
			}
			return token, nil
		default:
			return DeviceToken{}, fmt.Errorf("deviceToken/poll answered HTTP %d: %s", status, truncate(body, 200))
		}
		if errSleep := sleepCtx(ctx, time.Second); errSleep != nil {
			return DeviceToken{}, errSleep
		}
	}
}

// DeviceToken is the login result.
type DeviceToken struct {
	ID               string `json:"id"`
	Token            string `json:"token"`
	UserID           string `json:"user_id"`
	UserName         string `json:"user_name"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int64  `json:"expires_in"`
	ExpiresAt        string `json:"expires_at"`
	RefreshExpiresIn int64  `json:"refresh_token_expires_in"`
}

// FetchUserInfo enriches a credential with the account fields the signing
// context needs.
//
// The openapi host answers 401 `TOKEN_INVALID` when the bearer is missing or
// bad, and the web host answers 404 `NotFound` for this path at all — so the two
// are told apart here and reported separately.
func (l *Login) FetchUserInfo(ctx context.Context, bearer string) (map[string]any, error) {
	endpoint, err := l.openapiURL("/api/v1/userinfo")
	if err != nil {
		return nil, err
	}
	status, body, errCall := l.get(ctx, endpoint, bearer)
	if errCall != nil {
		return nil, errCall
	}
	l.trace(LoginStep{Method: http.MethodGet, URL: endpoint, Status: status})
	switch {
	case status == http.StatusOK:
		var payload map[string]any
		if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
			return nil, fmt.Errorf("userinfo is not JSON: %w", errUnmarshal)
		}
		return payload, nil
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return nil, fmt.Errorf("%w: userinfo answered HTTP %d (%s)", ErrTokenRejected, status, truncate(body, 160))
	case status == http.StatusNotFound:
		// Reaching a 404 here means the request landed on the web surface or the
		// route moved; either way it is not a token problem and must not be
		// reported as one.
		return nil, fmt.Errorf("%w: userinfo answered HTTP 404 at %s (%s)", ErrRouteNotFound, endpoint, truncate(body, 160))
	default:
		return nil, fmt.Errorf("userinfo answered HTTP %d: %s", status, truncate(body, 160))
	}
}

// ErrTokenRejected means the credential is not accepted (401/403).
var ErrTokenRejected = fmt.Errorf("qoder rejected the credential")

// ErrRouteNotFound means the request reached a host that does not serve the
// path — a wiring bug, not a credential problem.
var ErrRouteNotFound = fmt.Errorf("qoder route not found")

func (l *Login) get(ctx context.Context, endpoint, bearer string) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Accept", "application/json, text/plain, */*")
	request.Header.Set("User-Agent", "qoder/"+l.Region.DefaultCosyVersion)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := l.client().Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("call %s: %w", endpoint, err)
	}
	defer response.Body.Close()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if errRead != nil {
		return response.StatusCode, nil, errRead
	}
	return response.StatusCode, body, nil
}

// NewMachineID produces a machine id of the shape the client uses: URL-safe
// base64 over 72 random bytes, 96 characters.
func NewMachineID() (string, error) {
	return randomURLSafe(MachineIDBytes)
}

// pkceChallenge derives the S256 challenge from a verifier.
func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// randomURLSafe returns n bytes of entropy as URL-safe base64 without padding.
func randomURLSafe(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("gather entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func randomHex(n int) (string, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("gather entropy: %w", err)
	}
	return fmt.Sprintf("%x", buffer), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func truncate(value []byte, limit int) string {
	text := strings.TrimSpace(string(value))
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "…"
}
