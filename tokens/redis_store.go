package tokens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenStore defines minimal operations to persist tokens/claims in Redis.
// It supports both stateful management (opaque/reference) and caching of parsed JWT/JWE.
type TokenStore interface {
	SaveRefresh(ctx context.Context, rid, fid string, claims RefreshCustomClaims, ttl time.Duration) error
	GetRefresh(ctx context.Context, rid string) (RefreshCustomClaims, bool, error)

	// Family mapping helpers: current RID for a given FID
	GetFID(ctx context.Context, fid string) (string, bool, error)

	// Revoke deletes stored entries and optionally marks identifiers as revoked.
	RevokeAccess(ctx context.Context, jti string, ttl time.Duration) error // blacklist access by JTI
	RevokeRefresh(ctx context.Context, rid string, ttl time.Duration) error
	// Atomically rotate refresh: set new refresh (+FID->newRID), delete old refresh, write tombstone
	RotateRefreshAtomic(ctx context.Context,
		oldRID string, oldTTL time.Duration,
		newRRID, fid string, newRClaims RefreshCustomClaims, newRTTL time.Duration,
	) error

	// Access blacklist query
	IsAccessRevoked(ctx context.Context, jti string) (bool, error)
}

// RedisTokenStore is a Redis-backed implementation.
// Key schema (with configurable prefix p):
//
// p+"rtk:"+rid            -> JSON(RefreshCustomClaims)          EX=ttl (authoritative refresh claims)
// p+"fid:"+fid            -> rid                                EX=ttl (family mapping: current RID for FID)
// p+"rev:a:"+jti          -> "1"                               EX=ttl (access revocation tombstone by JTI)
// p+"rev:r:"+rid          -> "1"                               EX=ttl (refresh revocation tombstone by RID)
// p+"uxd:"+uid+"|"+device -> rid                                EX=ttl (per-user per-device active RID)
// p+"xd:"+deviceID        -> JSON({uid,rid})                     EX=ttl (device occupant when multi-user disabled)
// p+"uxds:"+uid           -> Set(deviceIDs)                      (no TTL; logical index of devices for user)
// p+"pl:r:"+rid           -> JSON(external payload)              EX=ttl (refresh externalized payload/extra)
type RedisTokenStore struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisTokenStore creates a store using an existing redis client and optional key prefix.
func NewRedisTokenStore(rdb redis.UniversalClient, prefix string) *RedisTokenStore {
	return &RedisTokenStore{rdb: rdb, prefix: prefix}
}

func (s *RedisTokenStore) key(parts ...string) string {
	k := s.prefix
	for _, p := range parts {
		k += p
	}
	return k
}

// SaveRefresh stores refresh claims by RID and maps FID->RID to support rotation checks.
func (s *RedisTokenStore) SaveRefresh(ctx context.Context, rid, fid string, claims RefreshCustomClaims, ttl time.Duration) error {
	b, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	if err := s.rdb.Set(ctx, s.key("rtk:", rid), b, ttl).Err(); err != nil {
		return err
	}
	// Map FID to RID with same TTL (used once semantics can be enforced by DEL after use)
	return s.rdb.Set(ctx, s.key("fid:", fid), rid, ttl).Err()
}

func (s *RedisTokenStore) GetRefresh(ctx context.Context, rid string) (RefreshCustomClaims, bool, error) {
	var out RefreshCustomClaims
	res, err := s.rdb.Get(ctx, s.key("rtk:", rid)).Bytes()
	if err == redis.Nil {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return out, false, err
	}
	return out, true, nil
}

func (s *RedisTokenStore) GetFID(ctx context.Context, fid string) (string, bool, error) {
	res, err := s.rdb.Get(ctx, s.key("fid:", fid)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return res, true, nil
}

// RevokeAccess deletes the stored access and writes a short-lived tombstone to prevent token replay when storage is eventually consistent.
func (s *RedisTokenStore) RevokeAccess(ctx context.Context, jti string, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.key("rev:a:", jti), "1", ttl).Err()
}

// RevokeRefresh deletes refresh and writes a tombstone; callers may also DEL fid mapping.
func (s *RedisTokenStore) RevokeRefresh(ctx context.Context, rid string, ttl time.Duration) error {
	if err := s.rdb.Del(ctx, s.key("rtk:", rid)).Err(); err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("rev:r:", rid), "1", ttl).Err()
}

// RotateRefreshAtomic performs refresh rotation atomically:
// - set new refresh
// - update fid -> newRID
// - delete old refresh
// - write tombstone for old refresh rid
func (s *RedisTokenStore) RotateRefreshAtomic(
	ctx context.Context,
	oldRID string, oldTTL time.Duration,
	newRRID, fid string, newRClaims RefreshCustomClaims, newRTTL time.Duration,
) error {
	rb, err := json.Marshal(newRClaims)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, s.key("rtk:", newRRID), rb, newRTTL)
		pipe.Set(ctx, s.key("fid:", fid), newRRID, newRTTL)
		pipe.Del(ctx, s.key("rtk:", oldRID))
		pipe.Set(ctx, s.key("rev:r:", oldRID), "1", oldTTL)
		return nil
	})
	return err
}

// (Parsed token cache removed; rely on direct decrypt/verify + authoritative RID records)

// IsAccessRevoked checks if an access JTI has a revocation tombstone.
func (s *RedisTokenStore) IsAccessRevoked(ctx context.Context, jti string) (bool, error) {
	_, err := s.rdb.Get(ctx, s.key("rev:a:", jti)).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ------ Optional device index helpers (UID + DeviceID -> current RID) ------

// DeviceIndexStore exposes per-user, per-device session mapping helpers.
// Implemented by RedisTokenStore below.
type DeviceIndexStore interface {
	GetDeviceRID(ctx context.Context, uid, deviceID string) (string, bool, error)
	SetDeviceRID(ctx context.Context, uid, deviceID, rid string, ttl time.Duration) error
	DelDeviceRID(ctx context.Context, uid, deviceID string) error
	// Device-wide occupancy: only one active session per device (regardless of user)
	// When set, value stores both uid and rid for the occupant.
	GetDeviceOccupant(ctx context.Context, deviceID string) (uid string, rid string, exists bool, err error)
	SetDeviceOccupant(ctx context.Context, deviceID, uid, rid string, ttl time.Duration) error
	DelDeviceOccupant(ctx context.Context, deviceID string) error
	// User-wide device index helpers
	ListUserDevices(ctx context.Context, uid string) ([]string, error)
	AddUserDevice(ctx context.Context, uid, deviceID string) error
	RemoveUserDevice(ctx context.Context, uid, deviceID string) error
}

// PayloadStore exposes helpers to store large, out-of-token payloads keyed by
// token identifiers to keep JWT/JWE minimal in size. Implemented by RedisTokenStore.
type PayloadStore interface {
	// Refresh payload helpers (keyed by RID)
	SaveRefreshPayload(ctx context.Context, rid string, v interface{}, ttl time.Duration) error
	GetRefreshPayloadJSON(ctx context.Context, rid string) ([]byte, bool, error)
}

// RefreshPayloadTxnStore exposes an atomic save that writes refresh artifacts and
// its externalized payload in a single Redis transaction with identical TTLs.
// Implemented by RedisTokenStore.
type RefreshPayloadTxnStore interface {
	SaveRefreshWithPayload(ctx context.Context, rid, fid string, claims RefreshCustomClaims, payload interface{}, ttl time.Duration) error
}

func (s *RedisTokenStore) deviceKey(uid, deviceID string) string {
	// Key: prefix + "uxd:" + uid + "|" + deviceID
	return s.key("uxd:", uid, "|", deviceID)
}

func (s *RedisTokenStore) userDevicesKey(uid string) string {
	// Set of deviceIDs for a user
	return s.key("uxds:", uid)
}

// GetDeviceRID returns the currently recorded RID for a given user+device.
func (s *RedisTokenStore) GetDeviceRID(ctx context.Context, uid, deviceID string) (string, bool, error) {
	res, err := s.rdb.Get(ctx, s.deviceKey(uid, deviceID)).Result()
	if err == redis.Nil {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return res, true, nil
}

// SetDeviceRID sets/updates the device mapping with a TTL (typically refresh TTL).
func (s *RedisTokenStore) SetDeviceRID(ctx context.Context, uid, deviceID, rid string, ttl time.Duration) error {
	if err := s.rdb.Set(ctx, s.deviceKey(uid, deviceID), rid, ttl).Err(); err != nil {
		return err
	}
	// Track device in user's set (best-effort; no TTL to avoid removing set prematurely)
	_ = s.rdb.SAdd(ctx, s.userDevicesKey(uid), deviceID).Err()
	return nil
}

// DelDeviceRID removes the device mapping.
func (s *RedisTokenStore) DelDeviceRID(ctx context.Context, uid, deviceID string) error {
	if err := s.rdb.Del(ctx, s.deviceKey(uid, deviceID)).Err(); err != nil {
		return err
	}
	// Best-effort cleanup from user's set
	_ = s.rdb.SRem(ctx, s.userDevicesKey(uid), deviceID).Err()
	return nil
}

func (s *RedisTokenStore) deviceOccupantKey(deviceID string) string {
	return s.key("xd:", deviceID)
}

type deviceOccupant struct {
	UID string `json:"uid"`
	RID string `json:"rid"`
}

// GetDeviceOccupant returns (uid,rid) if a device-wide occupant exists.
func (s *RedisTokenStore) GetDeviceOccupant(ctx context.Context, deviceID string) (string, string, bool, error) {
	res, err := s.rdb.Get(ctx, s.deviceOccupantKey(deviceID)).Bytes()
	if err == redis.Nil {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	var occ deviceOccupant
	if jerr := json.Unmarshal(res, &occ); jerr != nil {
		return "", "", false, jerr
	}
	return occ.UID, occ.RID, true, nil
}

// SetDeviceOccupant sets device occupant to (uid,rid) with TTL.
func (s *RedisTokenStore) SetDeviceOccupant(ctx context.Context, deviceID, uid, rid string, ttl time.Duration) error {
	b, err := json.Marshal(deviceOccupant{UID: uid, RID: rid})
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.deviceOccupantKey(deviceID), b, ttl).Err()
}

// DelDeviceOccupant removes the device-wide occupant mapping.
func (s *RedisTokenStore) DelDeviceOccupant(ctx context.Context, deviceID string) error {
	return s.rdb.Del(ctx, s.deviceOccupantKey(deviceID)).Err()
}

// ListUserDevices returns deviceIDs currently recorded for the user.
// Note: Entries may be stale if per-device mapping expired; callers can validate and clean up.
func (s *RedisTokenStore) ListUserDevices(ctx context.Context, uid string) ([]string, error) {
	res, err := s.rdb.SMembers(ctx, s.userDevicesKey(uid)).Result()
	if err == redis.Nil {
		return []string{}, nil
	}
	return res, err
}

func (s *RedisTokenStore) AddUserDevice(ctx context.Context, uid, deviceID string) error {
	return s.rdb.SAdd(ctx, s.userDevicesKey(uid), deviceID).Err()
}

func (s *RedisTokenStore) RemoveUserDevice(ctx context.Context, uid, deviceID string) error {
	return s.rdb.SRem(ctx, s.userDevicesKey(uid), deviceID).Err()
}

// ------ Large payload externalization (keep tokens minimal) ------

func (s *RedisTokenStore) refreshPayloadKey(rid string) string { return s.key("pl:r:", rid) }

// SaveRefreshPayload stores arbitrary JSON-serializable payload keyed by refresh RID.
func (s *RedisTokenStore) SaveRefreshPayload(ctx context.Context, rid string, v interface{}, ttl time.Duration) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.refreshPayloadKey(rid), b, ttl).Err()
}

// GetRefreshPayloadJSON returns raw JSON payload for RID if present.
func (s *RedisTokenStore) GetRefreshPayloadJSON(ctx context.Context, rid string) ([]byte, bool, error) {
	res, err := s.rdb.Get(ctx, s.refreshPayloadKey(rid)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return res, true, nil
}

// SaveRefreshWithPayload stores refresh claims, the FID->RID mapping, and an external payload
// for the refresh RID in a single transaction with the same TTL.
func (s *RedisTokenStore) SaveRefreshWithPayload(ctx context.Context, rid, fid string, claims RefreshCustomClaims, payload interface{}, ttl time.Duration) error {
	rb, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, s.key("rtk:", rid), rb, ttl)
		pipe.Set(ctx, s.key("fid:", fid), rid, ttl)
		pipe.Set(ctx, s.refreshPayloadKey(rid), pb, ttl)
		return nil
	})
	return err
}

// Helper: TTL remaining from claims' exp (clamped to >=0 and at most maxTTL if >0)
func ttlFromExpiry(exp time.Time, maxTTL time.Duration) time.Duration {
	ttl := time.Until(exp)
	if ttl < 0 {
		return 0
	}
	if maxTTL > 0 && ttl > maxTTL {
		return maxTTL
	}
	return ttl
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
