# JWE Tokens (nested JWS -> JWE)

This module provides helpers to issue Access/Refresh tokens as nested JWS (ES256) wrapped in JWE (RSA-OAEP-256 + A256GCM), plus a tiny demo server.

## Layout

- `tokens/` package
  - `IssueAccessAndRefreshJWE` — sign (ES256) then encrypt (JWE)
  - `DecryptAndVerifyAccess` / `DecryptAndVerifyRefresh` — decrypt JWE, verify inner JWS, parse claims
  - `GenerateES256Key` / `GenerateRSA2048` — demo key generators
- `cmd/server` — demo HTTP server exposing `/issue` and `/verify`

## Algorithms

- Inner JWS: ES256 (P-256). Header: `typ=JWT`, `kid=<sig_kid>`
- Outer JWE: ECDH-ES + A256KW (key mgmt) + A256GCM (content). Header: `cty=JWT`, `kid=<enc_kid>`

### Notes

“ES256”是JWS签名算法名称；JWE没有“ES256”算法，使用的是基于椭圆曲线的 ECDH-ES（可选直连或 A256KW 包裹）。

- 如需 RSA，也可改为 `RSA_OAEP_256` + `A256GCM`。

## Performance considerations

- Crypto cost: issuing a token performs one ECDSA-P256 signature and one JWE encryption (AES-GCM + RSA/ECDH key agreement). On modern CPUs this is typically sub-millisecond to a few milliseconds per token, but depends on hardware and key choice. Decrypt+verify is similar in reverse. If you expect very high QPS, prefer:
  - Reuse jose.Signer and jose.Encrypter instances where practical.
  - Keep claims minimal to reduce payload size.
  - Use ECDH-ES + A256GCM for JWE on EC keys to avoid RSA costs if your infra supports it.
  - Offload repeated verifications by caching parsed claims keyed by a token hash (see Redis section).
  - If you can avoid confidentiality, consider JWS-only access tokens and keep refresh tokens encrypted.

## Run locally (optional)

1) Ensure Go 1.22+ is installed.
2) From this folder:

```powershell
# Optional: download deps
# go mod tidy

# Run demo server
# go run ./cmd/server
```

Endpoints:

- `POST /issue` body:

```json
{
  "uid": "u123",
  "sub": "u123",
  "aud": "api://local",
  "iss": "https://auth.local",
  "device_id": "dev1",
  "client_id": "web",
  "scope": ["read"],
  "access_ttl_minutes": 10,
  "refresh_ttl_days": 14
}
```

Response:

```json
{ "access_jwe": "...", "refresh_jwe": "..." }
```

- `POST /verify` body:

```json
{ "type": "access", "token": "<JWE>", "iss": "https://auth.local", "aud": "api://local" }
```

## Move into E:\\Code\\tokens

If your target repo is `E:\Code\tokens`, you can:

- Copy this `authjwe` folder into `E:\Code\tokens` (or merge `tokens/` into your package path of choice)
- Update `module` path in `go.mod` to match your repository, e.g. `module github.com/cstcen/tokens`
- Adjust imports if you move the package path
- Run:

```powershell
# In E:\Code\tokens
# go mod tidy
# go build ./...
# go test ./...
```

## Production notes

- For production, manage separate JWKS for `use=sig` and `use=enc`, rotate `kid` regularly, and pin algorithm allowlists.
- If you prefer ECDH-ES instead of RSA-OAEP-256 for JWE, change `KeyMgmtAlg` accordingly and supply EC keys.

## Redis integration

This repo includes an optional `RedisTokenStore` (`tokens/redis_store.go`) to integrate with Redis for two purposes:

### 1) Stateful/session style tokens (reference tokens)

- Store access by JTI and refresh by RID with TTL matching their expiry:

```go
store := tokens.NewRedisTokenStore(redisClient, "auth:")
// After issuing tokens
_ = store.SaveAccess(ctx, accessClaims.ID, accessClaims, time.Until(accessClaims.Claims.Expiry.Time()))
_ = store.SaveRefresh(ctx, refreshClaims.RID, refreshClaims.FID, refreshClaims, time.Until(refreshClaims.Claims.Expiry.Time()))

// On API request: extract JTI from claims (after verify) and check revocation or fetch session
if _, found, _ := store.GetAccess(ctx, accessClaims.ID); !found { /* treat as revoked/expired */ }
```

- Revoke by deleting keys and writing a short-lived tombstone to prevent racey reuse:

```go
_ = store.RevokeAccess(ctx, accessClaims.ID, 10*time.Minute)
_ = store.RevokeRefresh(ctx, refreshClaims.RID, 24*time.Hour)
```

### 2) Cache parsed claims to reduce JWE decrypt/verify CPU

- Cache on first successful verify using a hash(token) key with TTL up to expiry:

```go
// Verify path (access)
if cached, ok, _ := store.GetCachedAccess(ctx, token); ok {
  return cached
}
claims, err := tokens.DecryptAndVerifyAccess(token, encPrivKey, findSigKeyByKID, iss, aud)
if err != nil { /* handle */ }
_ = store.CacheAccessClaims(ctx, token, claims, time.Until(claims.Claims.Expiry.Time()))
```

This does not eliminate crypto entirely (first hit still decrypts), but it avoids repeated decrypt+verify for the same token across services behind a shared Redis.

Opaque tokens alternative

If you want to avoid JWE/JWS cost entirely on hot paths, issue opaque random tokens to clients and store all claims in Redis keyed by that opaque ID with TTL. This changes the trust model (now fully server-side state) but can be the most CPU-efficient for very high throughput APIs.

## Same-device login controls (可选)

典型需求：

- 单设备是否允许多个用户同时登录
- 单用户若已在其它设备登录，是否强制下线其它设备账号（跨设备单会话）

本包提供 Redis 索引与开关项（Functional Options）：

- 设备索引：
  - `uxd:<uid>|<device_id> -> rid`（用户+设备当前会话）
  - `xd:<device_id> -> {uid,rid}`（设备占用；当不允许多用户时使用）
  - `uxds:<uid>`（用户的设备集合，用于枚举清理）

- 行为开关（推荐）：
  - `WithDeviceAllowMultiUser(true|false)`：单设备是否允许多用户（默认 true）
  - `WithForceReplace(true|false)`：同用户在同设备再次登录是否顶号
  - `WithForceLogoutOtherDevices(true|false)`：该用户是否跨设备单会话（登录时踢掉其它设备）

发行并持久化（示例）：

```go
res := tokens.Issue(ctx, store,
    tokens.WithKeys(signKid, signPriv, encKid, &encPubKey, algs),
    tokens.WithAudience(iss, aud),
    tokens.WithSubject(uid, sub),
    tokens.WithDevice(deviceID),
    tokens.WithClient(clientID),
    tokens.WithScope(scope...),
    tokens.WithTTL(10*time.Minute, 14*24*time.Hour),
    tokens.WithDeviceAllowMultiUser(false),   // 设备不允许多用户
    tokens.WithForceReplace(true),            // 同用户同设备顶号
    tokens.WithForceLogoutOtherDevices(true), // 跨设备单会话
)
if res.Err != nil { /* handle */ }
```

辅助检查：

```go
// 判断是否同设备已登录（针对 uxd 索引）
ok, _ := tokens.IsSameDeviceLoggedIn(ctx, store, uid, deviceID)

// 在刷新接口中校验：若使用“设备单客户端”，可防止被新会话“挤下线”的旧 refresh 继续使用
if err := tokens.ValidateRefreshForDevice(ctx, store, rc); err != nil {
    // 该 refresh 非当前设备的最新会话，拒绝
}
```

说明：这里主要控制刷新令牌（会话）的唯一性。访问令牌通常短时有效，不一定逐个撤销；
可根据需要缩短访问令牌 TTL 或增加访问令牌的服务端校验（例如通过 JTI 索引实现热撤销）。
