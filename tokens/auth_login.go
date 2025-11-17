package tokens

import (
	"context"
	"errors"
	"time"
)

// AuthSeed contains minimal identity fields available before issuing.
type AuthSeed struct {
	UID      string
	DeviceID string
	ClientID string
	Scope    []string
}

// AuthLoginOption mutates parameters for the AuthLogin flow.
type AuthLoginOption func(*AuthLoginParams)

// AuthLoginParams collects inputs and behaviors for issuing tokens on login.
type AuthLoginParams struct {
	Ctx      context.Context
	Store    TokenStore
	IssueOps []IssueOption

	AccessTTLFunc  func(AuthSeed) time.Duration
	RefreshTTLFunc func(AuthSeed) time.Duration

	UIDValidator func(context.Context, string) error

	// Optional: extra top-level fields to embed into the signed JWTs at issuance time.
	PreSignAccessExtra  map[string]interface{}
	PreSignRefreshExtra map[string]interface{}
}

// WithAuthStore sets the TokenStore to persist and check tokens.
func WithAuthStore(store TokenStore) AuthLoginOption {
	return func(p *AuthLoginParams) { p.Store = store }
}

// WithAuthIssueOptions forwards standard Issue options (keys, audience, subject, device, client, scope, policy...).
func WithAuthIssueOptions(opts ...IssueOption) AuthLoginOption {
	return func(p *AuthLoginParams) { p.IssueOps = append(p.IssueOps, opts...) }
}

// WithAuthPreSignAccessExtra sets extra fields for the access JWT.
func WithAuthPreSignAccessExtra(extra map[string]interface{}) AuthLoginOption {
	return func(p *AuthLoginParams) { p.PreSignAccessExtra = extra }
}

// WithAuthPreSignRefreshExtra sets extra fields for the refresh JWT.
func WithAuthPreSignRefreshExtra(extra map[string]interface{}) AuthLoginOption {
	return func(p *AuthLoginParams) { p.PreSignRefreshExtra = extra }
}

// WithAuthTTL sets constant access/refresh TTLs.
func WithAuthTTL(accessTTL, refreshTTL time.Duration) AuthLoginOption {
	return func(p *AuthLoginParams) {
		p.AccessTTLFunc = func(_ AuthSeed) time.Duration { return accessTTL }
		p.RefreshTTLFunc = func(_ AuthSeed) time.Duration { return refreshTTL }
	}
}

// WithAuthTTLFunc sets functions to compute access/refresh TTL based on login seed (e.g., UID-tiered TTL).
func WithAuthTTLFunc(access func(AuthSeed) time.Duration, refresh func(AuthSeed) time.Duration) AuthLoginOption {
	return func(p *AuthLoginParams) { p.AccessTTLFunc = access; p.RefreshTTLFunc = refresh }
}

// WithAuthUIDValidator sets a custom validator to check if a uid is allowed to login.
func WithAuthUIDValidator(f func(context.Context, string) error) AuthLoginOption {
	return func(p *AuthLoginParams) { p.UIDValidator = f }
}

// AuthLogin performs a regular login issuance with optional UID validation and TTL providers.
// It forwards to Issue(...) after computing TTLs from the AuthSeed and appending WithTTL.
func AuthLogin(ctx context.Context, opts ...AuthLoginOption) (res IssueResult) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := AuthLoginParams{Ctx: ctx}
	for _, opt := range opts {
		if opt != nil {
			opt(&p)
		}
	}
	if p.Store == nil {
		res.Err = errors.New("store is required: WithAuthStore")
		return
	}
	if p.AccessTTLFunc == nil || p.RefreshTTLFunc == nil {
		res.Err = errors.New("TTL providers are required: WithAuthTTL or WithAuthTTLFunc")
		return
	}
	// Build a seed by applying IssueOptions into a temp params to extract UID/device/client/scope
	tmp := IssueAndStoreParams{}
	for _, io := range p.IssueOps {
		if io != nil {
			io(&tmp)
		}
	}
	seed := AuthSeed{UID: tmp.In.UID, DeviceID: tmp.In.DeviceID, ClientID: tmp.In.ClientID, Scope: tmp.In.Scope}
	if seed.UID == "" {
		res.Err = errors.New("uid is required: include WithSubject in WithAuthIssueOptions")
		return
	}
	// Optional: UID validation hook
	if p.UIDValidator != nil {
		if err := p.UIDValidator(ctx, seed.UID); err != nil {
			res.Err = err
			return
		}
	}
	// Compute TTLs
	aTTL := p.AccessTTLFunc(seed)
	rTTL := p.RefreshTTLFunc(seed)
	if aTTL <= 0 || rTTL <= 0 {
		res.Err = errors.New("computed TTLs must be positive")
		return
	}
	// Append TTL and call Issue
	issueOps := append([]IssueOption{}, p.IssueOps...)
	issueOps = append(issueOps, WithTTL(aTTL, rTTL))
	if p.PreSignAccessExtra != nil {
		issueOps = append(issueOps, WithPreSignAccessExtra(p.PreSignAccessExtra))
	}
	if p.PreSignRefreshExtra != nil {
		issueOps = append(issueOps, WithPreSignRefreshExtra(p.PreSignRefreshExtra))
	}
	return Issue(ctx, p.Store, issueOps...)
}
