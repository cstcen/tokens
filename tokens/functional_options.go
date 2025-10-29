package tokens

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

// IssueOption mutates parameters for issuing and storing tokens.
type IssueOption func(*IssueAndStoreParams)

// WithKeys sets signing and encryption keys and algorithms.
func WithKeys(signKid string, signPriv *ecdsa.PrivateKey, encKid string, encPubKey interface{}, algs KeyAlgs) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.SignKid = signKid
		p.In.SignPriv = signPriv
		p.In.EncKid = encKid
		p.In.EncPubKey = encPubKey
		p.In.Algs = algs
	}
}

// WithSubject sets subject/uid. If sub is empty, it will default to uid during validation.
func WithSubject(uid, sub string) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.UID = uid
		p.In.Sub = sub
	}
}

// WithAudience sets issuer and audience.
func WithAudience(iss, aud string) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.Iss = iss
		p.In.Aud = aud
	}
}

// WithClient sets client id.
func WithClient(clientID string) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.ClientID = clientID
	}
}

// WithDevice sets device id.
func WithDevice(deviceID string) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.DeviceID = deviceID
	}
}

// WithScope sets scopes (replaces existing slice).
func WithScope(scopes ...string) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.Scope = append([]string(nil), scopes...)
	}
}

// WithTTL sets access and refresh TTLs.
func WithTTL(accessTTL, refreshTTL time.Duration) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.In.AccessTTL = accessTTL
		p.In.RefreshTTL = refreshTTL
	}
}

// WithPolicy sets the device session policy.
func WithPolicy(policy DevicePolicy) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.Opts.Policy = policy
	}
}

// WithSameDeviceHandler sets the legacy-form custom handler.
func WithSameDeviceHandler(h SameDeviceHandler) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.Opts.Handler = h
	}
}

// WithSameDeviceHandlerFunc sets the preferred context-based handler.
func WithSameDeviceHandlerFunc(h SameDeviceHandlerFunc) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.Opts.HandlerFunc = h
	}
}

// WithResultSink allows callers to retrieve detailed same-device handling outcomes.
func WithResultSink(res *IssueResult) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.Opts.ResultSink = res
	}
}

// WithDeviceIndex provides a DeviceIndexStore for same-device policy enforcement.
func WithDeviceIndex(dstore DeviceIndexStore) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.DStore = dstore
	}
}

// Issue is the functional-options entrypoint to issue and persist tokens.
// Required: store, keys (WithKeys), iss/aud (WithAudience), uid (WithSubject), TTLs (WithTTL).
// Optional: sub (defaults to uid), device/client/scope/policy/handlers/device index.
func Issue(ctx context.Context, store TokenStore, opts ...IssueOption) (
	accessJWE, refreshJWE string,
	accessClaims AccessCustomClaims,
	refreshClaims RefreshCustomClaims,
	err error,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	params := IssueAndStoreParams{
		Ctx:   ctx,
		Store: store,
		In:    IssueInputs{},
		Opts:  IssueOptions{Policy: DevicePolicyAllowSameDevice},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&params)
		}
	}
	// Validation
	if params.Store == nil {
		err = errors.New("store is required")
		return
	}
	if params.In.SignPriv == nil || params.In.SignKid == "" || params.In.EncKid == "" || params.In.EncPubKey == nil {
		err = errors.New("sign/encrypt keys are required: WithKeys")
		return
	}
	if params.In.Algs.SignAlg == "" || params.In.Algs.ContentEncryption == "" || params.In.Algs.KeyMgmtAlg == "" {
		err = errors.New("algs are required in WithKeys")
		return
	}
	if params.In.Iss == "" || params.In.Aud == "" {
		err = errors.New("issuer and audience are required: WithAudience")
		return
	}
	if params.In.UID == "" {
		err = errors.New("uid is required: WithSubject")
		return
	}
	if params.In.Sub == "" {
		params.In.Sub = params.In.UID
	}
	if params.In.AccessTTL <= 0 || params.In.RefreshTTL <= 0 {
		err = errors.New("positive TTLs are required: WithTTL")
		return
	}
	return IssueAndStore(params)
}
