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

// SameDeviceHandler allows custom business handling when a same-device session already exists.
// If provided, it will be called instead of the default DevicePolicy.HandleSameDevice.
// Returning a non-nil error will abort the issuing flow.
type SameDeviceHandler func(
	ctx context.Context,
	store TokenStore,
	dstore DeviceIndexStore,
	uid, deviceID, oldRID string,
	newRefresh RefreshCustomClaims,
	policy DevicePolicy,
) error

// HandleSameDevice encapsulates the business handling when a same-device session already exists.
// For policies:
// - Allow: no-op
// - Reject: returns error
// - SingleActive: best-effort revoke previous refresh (if found in store)
func (p DevicePolicy) HandleSameDevice(
	ctx context.Context,
	store TokenStore,
	dstore DeviceIndexStore,
	uid, deviceID, oldRID string,
	newRefresh RefreshCustomClaims,
) error {
	switch p {
	case DevicePolicyRejectIfSameDeviceExists:
		return errors.New("same device already logged in")
	case DevicePolicySingleActivePerDevice:
		// Best-effort revoke previous refresh if present
		if store != nil && oldRID != "" {
			if rc, ok, err := store.GetRefresh(ctx, oldRID); err == nil && ok {
				oldTTL := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
				_ = store.RevokeRefresh(ctx, oldRID, oldTTL)
			}
		}
		return nil
	default:
		// Allow: do nothing
		return nil
	}
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
) (accessJWE, refreshJWE string, accessClaims AccessCustomClaims, refreshClaims RefreshCustomClaims, err error) {
	return IssueAndStoreWithPolicyWithHandler(
		ctx, store, dstore,
		signKid, signPriv,
		encKid, encPubKey,
		algs,
		iss, aud, sub, uid, deviceID, clientID,
		accessTTL, refreshTTL,
		scope,
		policy,
		nil,
	)
}

// IssueAndStoreWithPolicyWithHandler is like IssueAndStoreWithPolicy but supports a custom handler
// to process the case where an existing same-device session is found. If handler is nil, the default
// behavior defined by DevicePolicy is used.
func IssueAndStoreWithPolicyWithHandler(
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
	handler SameDeviceHandler,
) (accessJWE, refreshJWE string, accessClaims AccessCustomClaims, refreshClaims RefreshCustomClaims, err error) {
	// Fast-path: issue tokens first; we won't persist if policy blocks.
	accessJWE, refreshJWE, accessClaims, refreshClaims, err = IssueAccessAndRefreshJWEWithClaims(
		signKid, signPriv, encKid, encPubKey, algs,
		iss, aud, sub, uid, deviceID, clientID,
		accessTTL, refreshTTL, scope,
	)
	if err != nil {
		return
	}

	// Policy enforcement (if device index available and deviceID provided)
	if dstore != nil && deviceID != "" && uid != "" {
		if oldRID, exists, derr := dstore.GetDeviceRID(ctx, uid, deviceID); derr != nil {
			err = derr
			return
		} else if exists && oldRID != "" {
			if handler != nil {
				if herr := handler(ctx, store, dstore, uid, deviceID, oldRID, refreshClaims, policy); herr != nil {
					err = herr
					return
				}
			} else if herr := policy.HandleSameDevice(ctx, store, dstore, uid, deviceID, oldRID, refreshClaims); herr != nil {
				err = herr
				return
			}
		}
	}

	// Persist atoms: access+refresh+fid
	aTTL := ttlFromExpiry(accessClaims.Claims.Expiry.Time(), 0)
	rTTL := ttlFromExpiry(refreshClaims.Claims.Expiry.Time(), 0)
	if err = store.SaveAccessRefreshAtomic(ctx,
		accessClaims.Claims.ID, accessClaims, aTTL,
		refreshClaims.RID, refreshClaims.FID, refreshClaims, rTTL,
	); err != nil {
		return
	}

	// Update device mapping if available
	if dstore != nil && deviceID != "" && uid != "" {
		// For all policies except Reject (which we would have returned earlier)
		_ = dstore.SetDeviceRID(ctx, uid, deviceID, refreshClaims.RID, rTTL)
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
