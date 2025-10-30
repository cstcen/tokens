package tokens

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

// DevicePolicy removed: behavior is now controlled by explicit options on IssueOptions.

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

// IssueAndStoreWithPolicy removed; use Issue (functional options) or IssueAndStore with IssueOptions.

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
	// ForceReplace=true 表示“同用户在不同设备登录时，是否允许顶号（强制下线其它设备的会话）”。
	// 注意：同用户在同设备再次登录默认会顶号，不需要此开关。
	ForceReplace bool
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

	// Pre-check per-user, same-device existing session: always replace by default
	if p.DStore != nil && p.In.UID != "" && p.In.DeviceID != "" {
		if oldRID, exists, _ := p.DStore.GetDeviceRID(ctx, p.In.UID, p.In.DeviceID); exists && oldRID != "" {
			res.SameDeviceChecked = true
			res.SameDeviceExisted = true
			res.OldRID = oldRID
			if p.Store != nil {
				if rc, ok, gerr := p.Store.GetRefresh(ctx, oldRID); gerr == nil && ok {
					oldTTL := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
					_ = p.Store.RevokeRefresh(ctx, oldRID, oldTTL)
				}
			}
			res.SameDeviceOutcome = SameDeviceOutcomeSingleActive
		}
	}

	// Pre-check device occupancy per configuration (different-user block when multi-user disabled)
	// Determine allowMulti (default true) and allow override via DeviceAllowMultiUser
	allowMulti := true
	if p.Opts.DeviceAllowMultiUserSet {
		allowMulti = p.Opts.DeviceAllowMultiUser
	}
	if p.DStore != nil && p.In.DeviceID != "" {
		if allowMulti {
			if !res.SameDeviceChecked {
				res.SameDeviceChecked = false
				res.SameDeviceOutcome = SameDeviceOutcomeNoCheck
			}
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
				// Occupied by someone
				if occUID != p.In.UID {
					res.SameDeviceOutcome = SameDeviceOutcomeRejected
					res.Err = errors.New("device already occupied by another user")
					return
				}
				// same user occupying: already handled by per-user pre-check above (best-effort revoke)
				res.SameDeviceExisted = true
				res.OldRID = occRID
			}
		}
	} else {
		res.SameDeviceChecked = false
		res.SameDeviceOutcome = SameDeviceOutcomeNoCheck
	}

	// Optional: Cross-device replace for same user (顶号其它设备)
	if p.DStore != nil && p.In.UID != "" && p.Opts.ForceReplace {
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
	} else if p.DStore != nil && p.In.UID != "" && !p.Opts.ForceReplace {
		// Cross-device login NOT allowed: if any other device has active session for this user, reject now
		if devs, derr := p.DStore.ListUserDevices(ctx, p.In.UID); derr == nil {
			for _, d := range devs {
				if d == p.In.DeviceID {
					continue
				}
				if rid, exists, _ := p.DStore.GetDeviceRID(ctx, p.In.UID, d); exists && rid != "" {
					res.SameDeviceOutcome = SameDeviceOutcomeRejected
					res.Err = errors.New("user already logged in on another device")
					return
				}
				// cleanup stale entries
				_ = p.DStore.RemoveUserDevice(ctx, p.In.UID, d)
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
