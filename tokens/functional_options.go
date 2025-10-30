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

// WithPolicy removed: use WithDeviceAllowMultiUser/WithForceReplace/WithForceLogoutOtherDevices.

// WithForceReplace allows replacing the same user's existing session on this device
func WithForceReplace(force bool) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.Opts.ForceReplace = force
	}
}

// WithForceReplace enforces single session per user across devices when true:
// 登录不同设备时，若该用户已在其它设备登录，则是否允许顶号（强制下线其它设备的会话）。
// 注意：同用户在同设备再次登录默认会顶号，不需要此开关。

// WithDeviceAllowMultiUser controls whether a single device can be used by multiple users concurrently.
// When true (default), multiple users can log in on the same device.
// When false, the device is exclusive: if occupied, new logins are rejected unless it's the same user and you also set WithForceReplace(true).
func WithDeviceAllowMultiUser(allow bool) IssueOption {
	return func(p *IssueAndStoreParams) {
		p.Opts.DeviceAllowMultiUser = allow
		p.Opts.DeviceAllowMultiUserSet = true
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
// Optional: sub (defaults to uid), device/client/scope/allow-multi-user/force replace/device index.
func Issue(ctx context.Context, store TokenStore, opts ...IssueOption) (res IssueResult) {
	if ctx == nil {
		ctx = context.Background()
	}
	params := IssueAndStoreParams{Ctx: ctx, Store: store, In: IssueInputs{}}
	for _, opt := range opts {
		if opt != nil {
			opt(&params)
		}
	}
	// Validation
	if params.Store == nil {
		res.Err = errors.New("store is required")
		return
	}
	if params.In.SignPriv == nil || params.In.SignKid == "" || params.In.EncKid == "" || params.In.EncPubKey == nil {
		res.Err = errors.New("sign/encrypt keys are required: WithKeys")
		return
	}
	if params.In.Algs.SignAlg == "" || params.In.Algs.ContentEncryption == "" || params.In.Algs.KeyMgmtAlg == "" {
		res.Err = errors.New("algs are required in WithKeys")
		return
	}
	if params.In.Iss == "" || params.In.Aud == "" {
		res.Err = errors.New("issuer and audience are required: WithAudience")
		return
	}
	if params.In.UID == "" {
		res.Err = errors.New("uid is required: WithSubject")
		return
	}
	if params.In.Sub == "" {
		params.In.Sub = params.In.UID
	}
	if params.In.AccessTTL <= 0 || params.In.RefreshTTL <= 0 {
		res.Err = errors.New("positive TTLs are required: WithTTL")
		return
	}
	return IssueAndStore(params)
}
