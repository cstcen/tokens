package tokens

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

// DevicePolicy controls how to handle logins from the same device for the same user.
type DevicePolicy int

const (
	// Allow multiple concurrent sessions on the same device (default behavior).
	DevicePolicyAllowSameDevice DevicePolicy = iota
	// Reject new login if an active session for the same device already exists.
	DevicePolicyRejectIfSameDeviceExists
	// Keep only a single active session per device: new login supersedes the old one.
	// Old refresh token is revoked and device mapping is updated to the new RID.
	DevicePolicySingleActivePerDevice
)

// Custom handlers have been removed in favor of explicit policies + ForceReplace flag.

// SameDeviceOutcome indicates which path was taken when handling an existing same-device session.
type SameDeviceOutcome int

const (
	SameDeviceOutcomeUnknown SameDeviceOutcome = iota
	// No same-device check performed (missing dstore/uid/device)
	SameDeviceOutcomeNoCheck
	// Checked but no existing session for this device
	SameDeviceOutcomeNoExisting
	// Policy allow with existing session present
	SameDeviceOutcomeAllowedExisting
	// Policy reject with existing session present
	SameDeviceOutcomeRejected
	// Policy single-active with existing session (attempted to revoke previous)
	SameDeviceOutcomeSingleActive
)

// IssueResult captures side-effects and outcomes during issuing.
type IssueResult struct {
	SameDeviceChecked bool
	SameDeviceExisted bool
	SameDeviceOutcome SameDeviceOutcome
	OldRID            string
	NewRID            string
	// Issuance artifacts
	AccessJWE     string
	RefreshJWE    string
	AccessClaims  AccessCustomClaims
	RefreshClaims RefreshCustomClaims
	Err           error
}

// IssueAndStoreWithPolicy issues access/refresh JWE tokens, persists them in the TokenStore,
// and optionally enforces a device policy using a DeviceIndexStore.
// Pass dstore=nil to skip device checks/mapping.
func IssueAndStoreWithPolicy(
	ctx context.Context,
	store TokenStore,
	dstore DeviceIndexStore,
	signKid string,
	signPriv *ecdsa.PrivateKey,
	encKid string,
	encPubKey interface{},
	algs KeyAlgs,
	iss, aud, sub, uid, deviceID, clientID string,
	accessTTL, refreshTTL time.Duration,
	scope []string,
	policy DevicePolicy,
) (res IssueResult) {
	params := IssueAndStoreParams{
		Ctx:    ctx,
		Store:  store,
		DStore: dstore,
		In: IssueInputs{
			SignKid:    signKid,
			SignPriv:   signPriv,
			EncKid:     encKid,
			EncPubKey:  encPubKey,
			Algs:       algs,
			Iss:        iss,
			Aud:        aud,
			Sub:        sub,
			UID:        uid,
			DeviceID:   deviceID,
			ClientID:   clientID,
			AccessTTL:  accessTTL,
			RefreshTTL: refreshTTL,
			Scope:      scope,
		},
		Opts: IssueOptions{Policy: policy},
	}
	return IssueAndStore(params)
}

// IssueAndStoreWithPolicyWithHandler is like IssueAndStoreWithPolicy but supports a custom handler
// to process the case where an existing same-device session is found. If handler is nil, the default
// behavior defined by DevicePolicy is used.
// IssueAndStoreWithPolicyWithHandler has been removed; use Issue (functional options) or IssueAndStoreWithPolicy.

// IssueInputs groups the inputs required to issue a pair of tokens.
type IssueInputs struct {
	SignKid   string
	SignPriv  *ecdsa.PrivateKey
	EncKid    string
	EncPubKey interface{}
	Algs      KeyAlgs

	Iss        string
	Aud        string
	Sub        string
	UID        string
	DeviceID   string
	ClientID   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Scope      []string
}

// IssueOptions configures policy and optional handlers.
type IssueOptions struct {
	Policy DevicePolicy
	// When Policy enforces single client per device (DevicePolicySingleActivePerDevice),
	// ForceReplace=true allows replacing the same user's existing session on this device.
	// If another user occupies the device, replacement is not allowed and will be rejected.
	ForceReplace bool
	// When Policy is DevicePolicySingleActivePerDevice, ForceLogoutOtherDevices=true
	// will revoke this用户在其他设备上的会话（跨设备单会话）。
	// 对于其他策略无效。
	ForceLogoutOtherDevices bool
	// Independent toggle to control device-level multi-user allowance.
	// If set to true (default), multiple users can log in on the same device.
	// If set to false, a device can be occupied by only one user at a time.
	DeviceAllowMultiUser    bool
	DeviceAllowMultiUserSet bool
}

// IssueAndStoreParams wraps all parameters to reduce function argument count.
type IssueAndStoreParams struct {
	Ctx    context.Context
	Store  TokenStore
	DStore DeviceIndexStore
	In     IssueInputs
	Opts   IssueOptions
}

// IssueAndStore issues and persists tokens according to provided params, enforcing device policy.
func IssueAndStore(p IssueAndStoreParams) (res IssueResult) {
	ctx := p.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Initialize result sink
	res.SameDeviceOutcome = SameDeviceOutcomeUnknown
	res.SameDeviceChecked = false
	res.SameDeviceExisted = false
	res.OldRID = ""
	res.NewRID = ""

	// Pre-check device occupancy per configuration
	// Determine allowMulti based on explicit toggle or legacy policy mapping
	allowMulti := true
	if p.Opts.DeviceAllowMultiUserSet {
		allowMulti = p.Opts.DeviceAllowMultiUser
	} else {
		switch p.Opts.Policy {
		case DevicePolicyRejectIfSameDeviceExists, DevicePolicySingleActivePerDevice:
			allowMulti = false
		default:
			allowMulti = true
		}
	}
	if p.DStore != nil && p.In.DeviceID != "" {
		if allowMulti {
			res.SameDeviceChecked = false
			res.SameDeviceOutcome = SameDeviceOutcomeNoCheck
		} else {
			occUID, occRID, exists, derr := p.DStore.GetDeviceOccupant(ctx, p.In.DeviceID)
			if derr != nil {
				res.Err = derr
				return
			}
			res.SameDeviceChecked = true
			if !exists {
				res.SameDeviceExisted = false
				res.SameDeviceOutcome = SameDeviceOutcomeNoExisting
			} else {
				res.SameDeviceExisted = true
				res.OldRID = occRID
				if occUID != p.In.UID {
					res.SameDeviceOutcome = SameDeviceOutcomeRejected
					res.Err = errors.New("device already occupied by another user")
					return
				}
				if !p.Opts.ForceReplace {
					res.SameDeviceOutcome = SameDeviceOutcomeRejected
					res.Err = errors.New("user already logged in on this device")
					return
				}
				// Force replace: revoke old refresh best-effort
				if p.Store != nil && occRID != "" {
					if rc, ok, gerr := p.Store.GetRefresh(ctx, occRID); gerr == nil && ok {
						oldTTL := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
						_ = p.Store.RevokeRefresh(ctx, occRID, oldTTL)
					}
				}
				res.SameDeviceOutcome = SameDeviceOutcomeSingleActive
			}
		}
	} else {
		res.SameDeviceChecked = false
		res.SameDeviceOutcome = SameDeviceOutcomeNoCheck
	}

	// Optional: Enforce user-wide single session by logging out other devices of this user.
	if p.DStore != nil && p.In.UID != "" && p.Opts.ForceLogoutOtherDevices {
		if devs, derr := p.DStore.ListUserDevices(ctx, p.In.UID); derr == nil {
			for _, d := range devs {
				if d == p.In.DeviceID {
					continue
				}
				if rid, exists, _ := p.DStore.GetDeviceRID(ctx, p.In.UID, d); exists && rid != "" {
					if p.Store != nil {
						if rc, ok, gerr := p.Store.GetRefresh(ctx, rid); gerr == nil && ok {
							oldTTL := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
							_ = p.Store.RevokeRefresh(ctx, rid, oldTTL)
						}
					}
				}
				_ = p.DStore.DelDeviceRID(ctx, p.In.UID, d)
				if ouid, _, occ, _ := p.DStore.GetDeviceOccupant(ctx, d); occ && ouid == p.In.UID {
					_ = p.DStore.DelDeviceOccupant(ctx, d)
				}
			}
		}
	}

	// Issue after pre-check
	var accessJWE, refreshJWE string
	var accessClaims AccessCustomClaims
	var refreshClaims RefreshCustomClaims
	accessJWE, refreshJWE, accessClaims, refreshClaims, res.Err = IssueAccessAndRefreshJWEWithClaims(
		p.In.SignKid, p.In.SignPriv,
		p.In.EncKid, p.In.EncPubKey,
		p.In.Algs,
		p.In.Iss, p.In.Aud, p.In.Sub, p.In.UID, p.In.DeviceID, p.In.ClientID,
		p.In.AccessTTL, p.In.RefreshTTL,
		p.In.Scope,
	)
	if res.Err != nil {
		return
	}
	res.AccessJWE = accessJWE
	res.RefreshJWE = refreshJWE
	res.AccessClaims = accessClaims
	res.RefreshClaims = refreshClaims
	res.NewRID = refreshClaims.RID

	// Persist
	aTTL := ttlFromExpiry(accessClaims.Claims.Expiry.Time(), 0)
	rTTL := ttlFromExpiry(refreshClaims.Claims.Expiry.Time(), 0)
	if res.Err = p.Store.SaveAccessRefreshAtomic(ctx,
		accessClaims.Claims.ID, accessClaims, aTTL,
		refreshClaims.RID, refreshClaims.FID, refreshClaims, rTTL,
	); res.Err != nil {
		return
	}
	if p.DStore != nil && p.In.DeviceID != "" {
		// Maintain per-user mapping for refresh validation
		if p.In.UID != "" {
			_ = p.DStore.SetDeviceRID(ctx, p.In.UID, p.In.DeviceID, refreshClaims.RID, rTTL)
		}
		// Maintain device-wide occupant only when multi-user is not allowed
		if !allowMulti {
			_ = p.DStore.SetDeviceOccupant(ctx, p.In.DeviceID, p.In.UID, refreshClaims.RID, rTTL)
		}
	}
	return
}

// IsSameDeviceLoggedIn checks if there's an active device mapping for uid+deviceID.
func IsSameDeviceLoggedIn(ctx context.Context, dstore DeviceIndexStore, uid, deviceID string) (bool, error) {
	if dstore == nil || uid == "" || deviceID == "" {
		return false, nil
	}
	_, exists, err := dstore.GetDeviceRID(ctx, uid, deviceID)
	return exists, err
}

// ValidateRefreshForDevice verifies the provided refresh claims match the current device mapping
// (if any). When a single-active-per-device policy is used, this helps reject superseded tokens.
func ValidateRefreshForDevice(ctx context.Context, dstore DeviceIndexStore, claims RefreshCustomClaims) error {
	if dstore == nil || claims.UID == "" || claims.DeviceID == "" {
		return nil
	}
	rid, exists, err := dstore.GetDeviceRID(ctx, claims.UID, claims.DeviceID)
	if err != nil {
		return err
	}
	if exists && rid != claims.RID {
		return errors.New("refresh token is not current for this device")
	}
	return nil
}
