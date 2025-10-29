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
		switch policy {
		case DevicePolicyRejectIfSameDeviceExists:
			if _, exists, derr := dstore.GetDeviceRID(ctx, uid, deviceID); derr != nil {
				err = derr
				return
			} else if exists {
				err = errors.New("same device already logged in")
				return
			}
		case DevicePolicySingleActivePerDevice:
			if oldRID, exists, derr := dstore.GetDeviceRID(ctx, uid, deviceID); derr != nil {
				err = derr
				return
			} else if exists && oldRID != "" {
				// Try to revoke the previous refresh if present
				if rc, ok, gerr := store.GetRefresh(ctx, oldRID); gerr == nil && ok {
					oldTTL := ttlFromExpiry(rc.Claims.Expiry.Time(), 0)
					// Best-effort revoke; ignore revoke error to avoid blocking login
					_ = store.RevokeRefresh(ctx, oldRID, oldTTL)
				} else {
					// If not found, still clear mapping below
				}
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
