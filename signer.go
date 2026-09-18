package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoder"
	"github.com/jingjingxinshang/qoder-cliproxy-plugin/qoderwasm"
)

// The signing wasm is a shared artefact: one module instance serves every
// credential, and each request gets its own signing context because a context
// carries the state (nonces, timestamps) that makes one signature distinct from
// the next. Loading is done once and cached; a context is cheap.
var (
	moduleOnce sync.Once
	moduleVal  *qoderwasm.Module
	moduleErr  error
)

// activeModule returns the loaded signing module, downloading and verifying the
// wasm on first use. It is deliberately lazy: a plugin that is installed but has
// never signed in must still register.
func activeModule() *qoderwasm.Module {
	moduleOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		manager := &qoderwasm.Manager{}
		wasm, err := manager.Resolve(ctx)
		if err != nil {
			moduleErr = fmt.Errorf("resolve qoder signing wasm: %w", err)
			return
		}
		module, err := qoderwasm.Load(ctx, wasm.Bytes)
		if err != nil {
			moduleErr = fmt.Errorf("load qoder signing wasm: %w", err)
			return
		}
		moduleVal = module
	})
	return moduleVal
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
	module := activeModule()
	if module == nil {
		if moduleErr != nil {
			return qoderwasm.Prepared{}, moduleErr
		}
		return qoderwasm.Prepared{}, errors.New("qoder signing module is unavailable")
	}
	region := regionOf(*auth)

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
