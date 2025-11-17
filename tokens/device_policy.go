package tokens

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"time"
)

// IssueResult captures side-effects and outcomes during issuing.
type IssueResult struct {
	OldRID string
	NewRID string
	// Whether this account already had active sessions on other devices during pre-check
	LoggedInOnOtherDevices bool
	// Whether there is another account already logged in on this device (if determinable)
	OtherUsersOnThisDevice bool
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
	// Optional: mutate claims before saving to store/cache.
	// Do NOT change access.Claims.ID (JTI), refresh.RID or refresh.FID.
	ClaimsMutator func(context.Context, *AccessCustomClaims, *RefreshCustomClaims) error
	// Optional: mutate claims BEFORE signing so custom fields are embedded in tokens.
	// MUST NOT change identifiers: access.Claims.ID (JTI), refresh.RID, refresh.FID.
	PreSignClaimsMutator func(context.Context, *AccessCustomClaims, *RefreshCustomClaims) error
	// Optional: externalized payload associated with refresh RID.
	// When provided and the store supports atomic writes, it will be saved in the
	// same Redis transaction and with the same TTL as the RID/FID records.
	RefreshPayload interface{}
}

// IssueAndStore issues and persists tokens according to provided params, enforcing device policy.
func IssueAndStore(p IssueAndStoreParams) (res IssueResult) {
	ctx := p.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Defaults rely on Go zero values

	// Pre-check per-user, same-device existing session: always replace by default
	if p.DStore != nil && p.In.UID != "" && p.In.DeviceID != "" {
		if oldRID, exists, _ := p.DStore.GetDeviceRID(ctx, p.In.UID, p.In.DeviceID); exists && oldRID != "" {
			res.OldRID = oldRID
			if p.Store != nil {
				if rc, ok, gerr := p.Store.GetRefresh(ctx, oldRID); gerr == nil && ok {
					oldTTL := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
					_ = p.Store.RevokeRefresh(ctx, oldRID, oldTTL)
				}
			}
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
			// no device-occupant enforcement
		} else {
			occUID, occRID, exists, derr := p.DStore.GetDeviceOccupant(ctx, p.In.DeviceID)
			if derr != nil {
				res.Err = derr
				return
			}
			if !exists {
				res.OtherUsersOnThisDevice = false
			} else {
				// Occupied by someone
				if occUID != p.In.UID {
					res.OtherUsersOnThisDevice = true
					res.Err = ErrDeviceOccupied
					return
				}
				// same user occupying: already handled by per-user pre-check above (best-effort revoke)
				res.OldRID = occRID
				res.OtherUsersOnThisDevice = false
			}
		}
	} else {
		// Unknown in multi-user mode without occupancy index; default false
		// res.OtherUsersOnThisDevice remains false
	}

	// Optional: Cross-device replace for same user (顶号其它设备)
	if p.DStore != nil && p.In.UID != "" && p.Opts.ForceReplace {
		if devs, derr := p.DStore.ListUserDevices(ctx, p.In.UID); derr == nil {
			for _, d := range devs {
				if d == p.In.DeviceID {
					continue
				}
				if rid, exists, _ := p.DStore.GetDeviceRID(ctx, p.In.UID, d); exists && rid != "" {
					res.LoggedInOnOtherDevices = true
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
					res.LoggedInOnOtherDevices = true
					res.Err = ErrUserLoggedInElsewhere
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
	if p.PreSignClaimsMutator != nil {
		accessJWE, refreshJWE, accessClaims, refreshClaims, res.Err = IssueAccessAndRefreshJWEWithClaimsCustom(
			p.In.SignKid, p.In.SignPriv,
			p.In.EncKid, p.In.EncPubKey,
			p.In.Algs,
			p.In.Iss, p.In.Aud, p.In.Sub, p.In.UID, p.In.DeviceID, p.In.ClientID,
			p.In.AccessTTL, p.In.RefreshTTL,
			p.In.Scope,
			func(ac *AccessCustomClaims, rc *RefreshCustomClaims) error {
				return p.PreSignClaimsMutator(ctx, ac, rc)
			},
		)
	} else {
		accessJWE, refreshJWE, accessClaims, refreshClaims, res.Err = IssueAccessAndRefreshJWEWithClaims(
			p.In.SignKid, p.In.SignPriv,
			p.In.EncKid, p.In.EncPubKey,
			p.In.Algs,
			p.In.Iss, p.In.Aud, p.In.Sub, p.In.UID, p.In.DeviceID, p.In.ClientID,
			p.In.AccessTTL, p.In.RefreshTTL,
			p.In.Scope,
		)
	}
	if res.Err != nil {
		return
	}
	res.AccessJWE = accessJWE
	res.RefreshJWE = refreshJWE
	res.AccessClaims = accessClaims
	res.RefreshClaims = refreshClaims
	res.NewRID = refreshClaims.RID

	// Optional: mutate claims before persistence/caching, without affecting token contents.
	if p.ClaimsMutator != nil {
		origAJTI := accessClaims.Claims.ID
		origRID := refreshClaims.RID
		origFID := refreshClaims.FID
		// Defensive copies to avoid slice aliasing (e.g., Scope)
		aCopy := accessClaims
		aCopy.Scope = append([]string(nil), accessClaims.Scope...)
		rCopy := refreshClaims
		rCopy.Scope = append([]string(nil), refreshClaims.Scope...)
		if mErr := p.ClaimsMutator(ctx, &aCopy, &rCopy); mErr != nil {
			res.Err = mErr
			return
		}
		if aCopy.Claims.ID != origAJTI || rCopy.RID != origRID || rCopy.FID != origFID {
			res.Err = errors.New("claims mutator cannot change JTI/RID/FID")
			return
		}
		accessClaims = aCopy
		refreshClaims = rCopy
	}

	// Persist (compute TTL after potential mutation)
	rTTL := ttlFromExpiry(refreshClaims.Claims.Expiry.Time(), 0)
	// Refresh persistence: save refresh + fid mapping (+ optional payload)
	if p.RefreshPayload != nil {
		if txStore, ok := p.Store.(interface {
			SaveRefreshWithPayload(context.Context, string, string, RefreshCustomClaims, interface{}, time.Duration) error
		}); ok {
			if res.Err = txStore.SaveRefreshWithPayload(ctx, refreshClaims.RID, refreshClaims.FID, refreshClaims, p.RefreshPayload, rTTL); res.Err != nil {
				return
			}
		} else {
			// Fallback (non-atomic with respect to payload)
			if res.Err = p.Store.SaveRefresh(ctx, refreshClaims.RID, refreshClaims.FID, refreshClaims, rTTL); res.Err != nil {
				return
			}
			if ps, ok := p.Store.(PayloadStore); ok {
				// Best-effort same TTL
				_ = ps.SaveRefreshPayload(ctx, refreshClaims.RID, p.RefreshPayload, rTTL)
			}
		}
	} else {
		// No payload: just save refresh + fid mapping
		if res.Err = p.Store.SaveRefresh(ctx, refreshClaims.RID, refreshClaims.FID, refreshClaims, rTTL); res.Err != nil {
			return
		}
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
		return ErrRefreshNotCurrent
	}
	return nil
}
