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
	SaveAccess(ctx context.Context, jti string, claims AccessCustomClaims, ttl time.Duration) error
	SaveRefresh(ctx context.Context, rid, fid string, claims RefreshCustomClaims, ttl time.Duration) error
	// Atomically save access and refresh (including FID->RID mapping) in one transaction
	SaveAccessRefreshAtomic(ctx context.Context,
		jti string, aClaims AccessCustomClaims, aTTL time.Duration,
		rid, fid string, rClaims RefreshCustomClaims, rTTL time.Duration,
	) error

	GetAccess(ctx context.Context, jti string) (AccessCustomClaims, bool, error)
	GetRefresh(ctx context.Context, rid string) (RefreshCustomClaims, bool, error)

	// Family mapping helpers: current RID for a given FID
	GetFID(ctx context.Context, fid string) (string, bool, error)

	// Revoke deletes stored entries and optionally marks identifiers as revoked.
	RevokeAccess(ctx context.Context, jti string, ttl time.Duration) error
	RevokeRefresh(ctx context.Context, rid string, ttl time.Duration) error
	// Atomically rotate refresh: save new access/refresh (+FID->newRID), delete old refresh, write tombstone
	RotateRefreshAndSaveAccessAtomic(ctx context.Context,
		oldRID string, oldTTL time.Duration,
		newAJTI string, newAClaims AccessCustomClaims, newATTL time.Duration,
		newRRID, fid string, newRClaims RefreshCustomClaims, newRTTL time.Duration,
	) error

	// Cache helpers to avoid repeated JWE decrypt/verify for the same token during its lifetime
	CacheAccessClaims(ctx context.Context, token string, claims AccessCustomClaims, ttl time.Duration) error
	CacheRefreshClaims(ctx context.Context, token string, claims RefreshCustomClaims, ttl time.Duration) error
	GetCachedAccess(ctx context.Context, token string) (AccessCustomClaims, bool, error)
	GetCachedRefresh(ctx context.Context, token string) (RefreshCustomClaims, bool, error)
}

// RedisTokenStore is a Redis-backed implementation.
// Key schema (with configurable prefix p):
//
//	p+"atk:"+jti     -> JSON(AccessCustomClaims)   EX=ttl
//	p+"rtk:"+rid     -> JSON(RefreshCustomClaims)  EX=ttl
//	p+"fid:"+fid     -> rid                         EX=ttl (to check one-time use / rotation)
//	p+"rev:a:"+jti   -> "1"                        EX=ttl (revocation tombstone)
//	p+"rev:r:"+rid   -> "1"                        EX=ttl
//	p+"ac-cache:"+H  -> JSON(AccessCustomClaims)   EX=ttl (parsed token cache)
//	p+"rc-cache:"+H  -> JSON(RefreshCustomClaims)  EX=ttl
type RedisTokenStore struct {
	rdb    *redis.Client
	prefix string
}

// NewRedisTokenStore creates a store using an existing redis client and optional key prefix.
func NewRedisTokenStore(rdb *redis.Client, prefix string) *RedisTokenStore {
	return &RedisTokenStore{rdb: rdb, prefix: prefix}
}

func (s *RedisTokenStore) key(parts ...string) string {
	k := s.prefix
	for _, p := range parts {
		k += p
	}
	return k
}

// SaveAccess stores access claims by JTI with TTL.
func (s *RedisTokenStore) SaveAccess(ctx context.Context, jti string, claims AccessCustomClaims, ttl time.Duration) error {
	b, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("atk:", jti), b, ttl).Err()
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

// SaveAccessRefreshAtomic writes access, refresh and fid mapping atomically (MULTI/EXEC)
func (s *RedisTokenStore) SaveAccessRefreshAtomic(
	ctx context.Context,
	jti string, aClaims AccessCustomClaims, aTTL time.Duration,
	rid, fid string, rClaims RefreshCustomClaims, rTTL time.Duration,
) error {
	ab, err := json.Marshal(aClaims)
	if err != nil {
		return err
	}
	rb, err := json.Marshal(rClaims)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Set(ctx, s.key("atk:", jti), ab, aTTL)
		pipe.Set(ctx, s.key("rtk:", rid), rb, rTTL)
		pipe.Set(ctx, s.key("fid:", fid), rid, rTTL)
		return nil
	})
	return err
}

func (s *RedisTokenStore) GetAccess(ctx context.Context, jti string) (AccessCustomClaims, bool, error) {
	var out AccessCustomClaims
	res, err := s.rdb.Get(ctx, s.key("atk:", jti)).Bytes()
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
	if err := s.rdb.Del(ctx, s.key("atk:", jti)).Err(); err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("rev:a:", jti), "1", ttl).Err()
}

// RevokeRefresh deletes refresh and writes a tombstone; callers may also DEL fid mapping.
func (s *RedisTokenStore) RevokeRefresh(ctx context.Context, rid string, ttl time.Duration) error {
	if err := s.rdb.Del(ctx, s.key("rtk:", rid)).Err(); err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("rev:r:", rid), "1", ttl).Err()
}

// RotateRefreshAndSaveAccessAtomic performs refresh rotation atomically:
// - set new access
// - set new refresh
// - update fid -> newRID
// - delete old refresh
// - write tombstone for old refresh rid
func (s *RedisTokenStore) RotateRefreshAndSaveAccessAtomic(
	ctx context.Context,
	oldRID string, oldTTL time.Duration,
	newAJTI string, newAClaims AccessCustomClaims, newATTL time.Duration,
	newRRID, fid string, newRClaims RefreshCustomClaims, newRTTL time.Duration,
) error {
	ab, err := json.Marshal(newAClaims)
	if err != nil {
		return err
	}
	rb, err := json.Marshal(newRClaims)
	if err != nil {
		return err
	}
	_, err = s.rdb.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		// new values
		pipe.Set(ctx, s.key("atk:", newAJTI), ab, newATTL)
		pipe.Set(ctx, s.key("rtk:", newRRID), rb, newRTTL)
		pipe.Set(ctx, s.key("fid:", fid), newRRID, newRTTL)
		// remove old refresh and write tombstone
		pipe.Del(ctx, s.key("rtk:", oldRID))
		pipe.Set(ctx, s.key("rev:r:", oldRID), "1", oldTTL)
		return nil
	})
	return err
}

// CacheAccessClaims caches parsed access claims keyed by hash(token) with TTL.
func (s *RedisTokenStore) CacheAccessClaims(ctx context.Context, token string, claims AccessCustomClaims, ttl time.Duration) error {
	b, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("ac-cache:", hashToken(token)), b, ttl).Err()
}

// CacheRefreshClaims caches parsed refresh claims keyed by hash(token) with TTL.
func (s *RedisTokenStore) CacheRefreshClaims(ctx context.Context, token string, claims RefreshCustomClaims, ttl time.Duration) error {
	b, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, s.key("rc-cache:", hashToken(token)), b, ttl).Err()
}

func (s *RedisTokenStore) GetCachedAccess(ctx context.Context, token string) (AccessCustomClaims, bool, error) {
	var out AccessCustomClaims
	res, err := s.rdb.Get(ctx, s.key("ac-cache:", hashToken(token))).Bytes()
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

func (s *RedisTokenStore) GetCachedRefresh(ctx context.Context, token string) (RefreshCustomClaims, bool, error) {
	var out RefreshCustomClaims
	res, err := s.rdb.Get(ctx, s.key("rc-cache:", hashToken(token))).Bytes()
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
