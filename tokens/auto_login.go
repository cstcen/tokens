package tokens

import (
	"context"
	"crypto"
	"errors"
	"time"
)

// AutoLoginSeed contains minimal identity fields available before auto-login.
type AutoLoginSeed struct {
	UID      string
	DeviceID string
	ClientID string
	Scope    []string
}

// AutoLoginOption mutates parameters for the AutoLogin flow.
type AutoLoginOption func(*AutoLoginParams)

// AutoLoginParams collects inputs and behaviors for auto-login via refresh token.
type AutoLoginParams struct {
	Ctx        context.Context
	Store      TokenStore
	RefreshJWE string
	IssueOps   []IssueOption

	EncPrivKey      interface{}
	FindSigKeyByKID func(string) crypto.PublicKey
	Iss             string
	Aud             string

	AccessTTLFunc  func(AutoLoginSeed) time.Duration
	RefreshTTLFunc func(AutoLoginSeed) time.Duration

	UIDValidator func(context.Context, string) error

	PreSignRefreshExtra map[string]interface{}
}

// WithAutoLoginDecryptKey sets the private key for JWE decryption of the refresh token.
func WithAutoLoginDecryptKey(priv interface{}) AutoLoginOption {
	return func(p *AutoLoginParams) { p.EncPrivKey = priv }
}

// WithAutoLoginFindSigKey provides the KID->public key resolver used to verify the inner JWS.
func WithAutoLoginFindSigKey(f func(string) crypto.PublicKey) AutoLoginOption {
	return func(p *AutoLoginParams) { p.FindSigKeyByKID = f }
}

// WithAutoLoginAudience sets issuer and audience used to validate the incoming refresh token.
func WithAutoLoginAudience(iss, aud string) AutoLoginOption {
	return func(p *AutoLoginParams) { p.Iss = iss; p.Aud = aud }
}

// WithAutoLoginStore sets the TokenStore to persist and check tokens.
func WithAutoLoginStore(store TokenStore) AutoLoginOption {
	return func(p *AutoLoginParams) { p.Store = store }
}

// WithAutoLoginRefreshJWE sets the refresh JWE token for auto-login.
func WithAutoLoginRefreshJWE(token string) AutoLoginOption {
	return func(p *AutoLoginParams) { p.RefreshJWE = token }
}

// WithAutoLoginIssueOptions forwards standard Issue options (keys, audience, subject, device, client, scope, policy...).
func WithAutoLoginIssueOptions(opts ...IssueOption) AutoLoginOption {
	return func(p *AutoLoginParams) { p.IssueOps = append(p.IssueOps, opts...) }
}

// WithAutoLoginPreSignRefreshExtra sets extra payload stored with refresh RID (not embedded).
func WithAutoLoginPreSignRefreshExtra(extra map[string]interface{}) AutoLoginOption {
	return func(p *AutoLoginParams) { p.PreSignRefreshExtra = extra }
}

// WithAutoLoginTTL sets constant access/refresh TTLs.
func WithAutoLoginTTL(accessTTL, refreshTTL time.Duration) AutoLoginOption {
	return func(p *AutoLoginParams) {
		p.AccessTTLFunc = func(_ AutoLoginSeed) time.Duration { return accessTTL }
		p.RefreshTTLFunc = func(_ AutoLoginSeed) time.Duration { return refreshTTL }
	}
}

// WithAutoLoginTTLFunc sets functions to compute access/refresh TTL based on seed (e.g., UID-tiered TTL).
func WithAutoLoginTTLFunc(access func(AutoLoginSeed) time.Duration, refresh func(AutoLoginSeed) time.Duration) AutoLoginOption {
	return func(p *AutoLoginParams) { p.AccessTTLFunc = access; p.RefreshTTLFunc = refresh }
}

// WithAutoLoginUIDValidator sets a custom validator to check if a uid is allowed to login.
func WithAutoLoginUIDValidator(f func(context.Context, string) error) AutoLoginOption {
	return func(p *AutoLoginParams) { p.UIDValidator = f }
}

// AutoLogin performs auto-login via refresh JWE, with device checks and force login logic.
func AutoLogin(ctx context.Context, opts ...AutoLoginOption) (res IssueResult) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := AutoLoginParams{Ctx: ctx}
	for _, opt := range opts {
		if opt != nil {
			opt(&p)
		}
	}
	if p.Store == nil {
		res.Err = errors.New("store is required: WithAutoLoginStore")
		return
	}
	if p.RefreshJWE == "" {
		res.Err = errors.New("refresh JWE is required: WithAutoLoginRefreshJWE")
		return
	}
	if p.AccessTTLFunc == nil || p.RefreshTTLFunc == nil {
		res.Err = errors.New("TTL providers are required: WithAutoLoginTTL or WithAutoLoginTTLFunc")
		return
	}
	// 1. 解析 refreshJWE，获取 claims（需调用 DecryptAndVerifyRefresh）
	if p.EncPrivKey == nil || p.FindSigKeyByKID == nil || p.Iss == "" || p.Aud == "" {
		res.Err = errors.New("encPrivKey, findSigKeyByKID, iss, aud required: use WithAutoLoginDecryptKey/FindSigKey/Audience")
		return
	}
	claims, err := DecryptAndVerifyRefresh(p.RefreshJWE, p.EncPrivKey, p.FindSigKeyByKID, p.Iss, p.Aud)
	if err != nil {
		res.Err = err
		return
	}
	seed := AutoLoginSeed{UID: claims.UID, DeviceID: claims.DeviceID, ClientID: claims.ClientID, Scope: claims.Scope}
	if seed.UID == "" {
		res.Err = errors.New("uid is required in refresh claims")
		return
	}
	// 2. 检查设备ID、是否允许强制登录等（可通过 p.Store 或自定义逻辑）
	// TODO: 设备检测、强制登录逻辑
	if p.UIDValidator != nil {
		if err := p.UIDValidator(ctx, seed.UID); err != nil {
			res.Err = err
			return
		}
	}
	// 3. 计算 TTL
	aTTL := p.AccessTTLFunc(seed)
	rTTL := p.RefreshTTLFunc(seed)
	if aTTL <= 0 || rTTL <= 0 {
		res.Err = errors.New("computed TTLs must be positive")
		return
	}
	// 4. 发行新 token
	issueOps := append([]IssueOption{}, p.IssueOps...)
	issueOps = append(issueOps, WithTTL(aTTL, rTTL))
	if p.PreSignRefreshExtra != nil {
		issueOps = append(issueOps, WithRefreshPayload(p.PreSignRefreshExtra))
	}
	res = Issue(ctx, p.Store, issueOps...)
	return res
}
