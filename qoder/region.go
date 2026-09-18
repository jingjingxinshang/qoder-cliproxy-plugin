// Package qoder implements the parts of the Qoder client the CPA plugin needs:
// region endpoints, the device-code login, and the two request families.
package qoder

import (
	"fmt"
	"net/url"
	"strings"
)

// Region describes one Qoder cluster.
//
// The two clusters have separate hosts, separate credential stores and separate
// client versions. Verified against the CLI bundle and live endpoints:
//
//   - the openapi host answers Bearer-authenticated calls and names itself in
//     its errors ("missing authorization token"), so a 401 there means the
//     request reached the right service;
//   - the web host (qoder.cn / qoder.com) is a different surface entirely: it
//     authenticates with a browser session cookie and answers 404
//     `{"errorCode":"NotFound"}` for paths that only exist on openapi.
//
// Sending an API call to the web host is therefore silent and confusing: http
// and not-found instead of unauthorized. The guards below exist to make that
// mistake impossible rather than merely unlikely.
type Region struct {
	ID          string
	DisplayName string
	// DevicePage is where a user approves a device login.
	DevicePage string
	// OpenapiHost serves Bearer-authenticated JSON (userinfo, plan, quota).
	OpenapiHost string
	// InferHost serves the signed model list and chat stream.
	InferHost string
	// AuthDir is the CLI's credential directory, used only for diagnostics.
	AuthDir string
	// NpmPackage is the official CLI package the signing wasm comes from.
	NpmPackage string
	// DefaultCosyVersion is the fallback client version when the current one
	// cannot be read from the published package metadata.
	DefaultCosyVersion string
}

// Regions is the canonical table. Hosts are pinned deliberately: the CLI
// resolves them dynamically (HTTPDNS, elected endpoints), and a wrong fallback
// silently lands on the web surface.
var Regions = map[string]Region{
	"cn": {
		ID:                 "cn",
		DisplayName:        "Qoder CN",
		DevicePage:         "https://qoder.cn",
		OpenapiHost:        "https://openapi.qoder.com.cn",
		InferHost:          "https://gateway.qoder.com.cn",
		AuthDir:            "~/.qoder-cn",
		NpmPackage:         "@qodercn-ai/qoderclicn",
		DefaultCosyVersion: "1.1.45",
	},
	"global": {
		ID:                 "global",
		DisplayName:        "Qoder",
		DevicePage:         "https://qoder.com",
		OpenapiHost:        "https://openapi.qoder.sh",
		InferHost:          "https://center.qoder.sh",
		AuthDir:            "~/.qoder",
		NpmPackage:         "@qoder-ai/qodercli",
		DefaultCosyVersion: "1.1.45",
	},
}

// webSurfaces are the browser hosts. Nothing in this package may call them: they
// answer 404 for openapi paths, which reads like a broken token instead of a
// broken route.
var webSurfaces = []string{"qoder.cn", "www.qoder.cn", "qoder.com", "www.qoder.com"}

// RegionFor resolves a region id, defaulting to CN the way the CLI does.
func RegionFor(id string) Region {
	normalized := strings.ToLower(strings.TrimSpace(id))
	if region, ok := Regions[normalized]; ok {
		return region
	}
	return Regions["cn"]
}

// OpenapiURL builds a URL on the openapi host, refusing anything that would land
// on a web surface.
func (r Region) OpenapiURL(path string) (string, error) {
	host, err := url.Parse(r.OpenapiHost)
	if err != nil {
		return "", fmt.Errorf("region %s has an unparsable openapi host %q: %w", r.ID, r.OpenapiHost, err)
	}
	if errHost := guardHost(host.Hostname()); errHost != nil {
		return "", errHost
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(r.OpenapiHost, "/") + path, nil
}

// InferURL is OpenapiURL for the signed infer host.
func (r Region) InferURL(path string) (string, error) {
	host, err := url.Parse(r.InferHost)
	if err != nil {
		return "", fmt.Errorf("region %s has an unparsable infer host %q: %w", r.ID, r.InferHost, err)
	}
	if errHost := guardHost(host.Hostname()); errHost != nil {
		return "", errHost
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(r.InferHost, "/") + path, nil
}

// guardHost rejects the browser hosts.
func guardHost(hostname string) error {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	for _, surface := range webSurfaces {
		if hostname == surface {
			return fmt.Errorf("refusing to call the web surface %s: it answers 404 for openapi paths and would look like an expired token", hostname)
		}
	}
	return nil
}

// DeviceAuthURL builds the URL the user opens to approve a device login.
//
// DeviceAuthURL is the URL the user approves a device login on.
//
// The parameter set is exactly the CLI's own, read out of the shipped bundle:
//
//	new URLSearchParams({challenge, challenge_method: "S256", nonce,
//	  machine_id, client_id: ktc})
//	`${base}/device/selectAccounts?${params}`
//
// redirect_uri and directLogin do NOT belong here. Adding them makes the server
// answer OAuthRedirectURIInvalid, because it validates redirect_uri against the
// client's registered list and this flow has none: redirect_uri belongs to the
// IDE's browser authorization-code flow, which posts to /authorize with
// response_type and code_challenge. Conflating the two flows is what broke this
// once already. machine_token is also part of the CLI's set, but only when a
// machine token exists; it is omitted here for the same reason the CLI omits it.
func (r Region) DeviceAuthURL(challenge, nonce, machineID string) string {
	query := url.Values{}
	query.Set("challenge", challenge)
	query.Set("challenge_method", "S256")
	query.Set("nonce", nonce)
	query.Set("machine_id", machineID)
	query.Set("client_id", ClientID)
	return strings.TrimRight(r.DevicePage, "/") + "/device/selectAccounts?" + query.Encode()
}

const (
	// ClientID is the public client the CLI's device flow uses. The bundle keeps
	// it obfuscated (`ktc`, base64 then XOR with a fixed key) and decodes to this
	// value, which is the default the flow selects over the alternative Rtc
	// client id (e93fe488-5778-4c35-a6fc-0f54ed7b3139).
	ClientID = "e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb"
	// RedirectURI belongs to the IDE's browser authorization-code flow (the deep
	// link it registers). The device flow must NOT send it: see DeviceAuthURL.
	RedirectURI = "qoder://aicoding.aicoding-agent/login-success"
)
