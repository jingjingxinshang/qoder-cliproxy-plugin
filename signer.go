package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoder"
	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoderwasm"
)

// The signing wasm is a shared artefact: one module instance serves every
// credential of a cluster, and each request gets its own signing context because
// a context carries the state (nonces, timestamps) that makes one signature
// distinct from the next. Loading is done once per cluster and cached; a context
// is cheap.
//
// The cache is keyed by the cluster's npm package rather than being a single
// sync.Once, because Manager.Resolve cannot load anything without being told
// which package to fetch, and the two clusters publish different ones. Asking for
// a module without a package fails with "no npm package configured for this
// qoder region", which is silent on the plugin's side because discovery only
// reports an empty model list.
var (
	moduleMu sync.Mutex
	modules  = map[string]*qoderwasm.Module{}
	failures = map[string]error{}
)

// activeModuleFor returns the signing module for a cluster, downloading and
// verifying the wasm on first use. It is deliberately lazy: a plugin that is
// installed but has never signed in must still register.
func activeModuleFor(region qoder.Region) (*qoderwasm.Module, error) {
	moduleMu.Lock()
	defer moduleMu.Unlock()
	if module, ok := modules[region.NpmPackage]; ok {
		return module, nil
	}
	if failure, ok := failures[region.NpmPackage]; ok {
		return nil, failure
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	manager := &qoderwasm.Manager{Package: region.NpmPackage}
	wasm, err := manager.Resolve(ctx)
	if err != nil {
		failure := fmt.Errorf("resolve qoder signing wasm for %s: %w", region.ID, err)
		failures[region.NpmPackage] = failure
		return nil, failure
	}
	module, err := qoderwasm.Load(ctx, wasm.Bytes)
	if err != nil {
		failure := fmt.Errorf("load qoder signing wasm for %s: %w", region.ID, err)
		failures[region.NpmPackage] = failure
		return nil, failure
	}
	modules[region.NpmPackage] = module
	return module, nil
}

// signer is one credential's signing context.
type signer struct {
	module  *qoderwasm.Module
	context *qoderwasm.QoderContext
	region  qoder.Region
}

// signRequest builds a signing context for one credential, derives the signing
// fields if the credential does not carry them yet, and hands the context to the
// caller. The context is freed on return: signing state must not be reused
// across requests, or two requests would share a nonce.
//
// A credential that had no derived fields is updated in place, and the caller is
// expected to persist it — see the AuthUpdate in model discovery.
func signRequest(ctx context.Context, auth *qoderAuth, prepare func(*signer) (qoderwasm.Prepared, error)) (qoderwasm.Prepared, error) {
	region := regionOf(*auth)
	module, err := activeModuleFor(region)
	if err != nil {
		return qoderwasm.Prepared{}, err
	}

	if auth.EncryptUserInfo == "" || auth.Key == "" {
		fields, err := module.GenerateAuthFields(credentialJSON(*auth))
		if err != nil {
			return qoderwasm.Prepared{}, fmt.Errorf("derive qoder signing fields: %w", err)
		}
		auth.EncryptUserInfo, auth.Key = fields.EncryptUserInfo, fields.Key
	}
	if auth.MachineID == "" {
		machineID, err := qoder.NewMachineID()
		if err != nil {
			return qoderwasm.Prepared{}, fmt.Errorf("generate qoder machine id: %w", err)
		}
		auth.MachineID = machineID
	}
	if auth.CosyVersion == "" {
		auth.CosyVersion = region.DefaultCosyVersion
	}
	if auth.Region == "" {
		auth.Region = region.ID
	}

	context, err := module.NewContext(auth.MachineID, auth.CosyVersion, userInfoForAuth(*auth), qoderwasm.NewClientInfo())
	if err != nil {
		return qoderwasm.Prepared{}, fmt.Errorf("build qoder signing context: %w", err)
	}
	defer context.Free()
	return prepare(&signer{module: module, context: context, region: region})
}

// userInfoForAuth is the subset of the credential the signing context verifies.
func userInfoForAuth(auth qoderAuth) qoderwasm.UserInfoForAuth {
	info := qoderwasm.UserInfoForAuth{
		UID:             auth.UID,
		EncryptUserInfo: auth.EncryptUserInfo,
		Key:             auth.Key,
		OrganizationID:  auth.OrgID,
	}
	if len(auth.OrgTags) > 0 {
		info.OrganizationTags = auth.OrgTags
	}
	if auth.DataPolicy {
		agreed := true
		info.DataPolicyAgreed = &agreed
	}
	return info
}

// credentialJSON renders the credential in the shape the module expects for
// generate_runtime_auth_fields. It is the CLI's own stored credential object,
// not the plugin's internal record: the field names here are the ones the module
// reads, so they are spelled exactly as the CLI writes them.
func credentialJSON(auth qoderAuth) string {
	expireSeconds := auth.ExpiresAt / 1000
	payload := map[string]any{
		"uid":                  auth.UID,
		"name":                 auth.UserName,
		"security_oauth_token": auth.Token,
		"access_token":         auth.Token,
		"refresh_token":        auth.RefreshToken,
		"expire_time":          expireSeconds,
		"login_method":         "browser",
		"organization_id":      auth.OrgID,
		"encrypt_user_info":    auth.EncryptUserInfo,
		"key":                  auth.Key,
		"data_policy_agreed":   auth.DataPolicy,
	}
	if len(auth.OrgTags) > 0 {
		payload["organization_tags"] = auth.OrgTags
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(raw)
}
