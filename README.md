# JWE Tokens (Nested signed JWT (JWS) -> JWE)

[中文版 README](./README.zh.md) ｜ English & Chinese mixed summary below

English | 中文双语 README，面向高并发下的安全访问 / 刷新令牌发行、验证、轮换、撤销与设备会话控制。

This library issues Access & Refresh tokens as nested signed JWT (JWS, ES256) wrapped in JWE (ECDH-ES + A256KW + A256GCM by default, optional RSA-OAEP-256). It provides:

- Functional Options based issuance API (`Issue`, `AuthLogin`, `AutoLoginWithRefresh`).
- Device + cross-device session policies (multi-user per device, force replace, single active).
- Redis-backed state (refresh persistence, rotation, revocation tombstones, parsed-claims cache, device indexes).
- Stateless fallback (pure cryptographic tokens) when Redis is not enabled.
- Unified verification helpers supporting JWE, JWS-only, and legacy opaque tokens.

```mermaid
flowchart TD
  A[Init] --> A1[Load ES256 sign key + enc key]
  A --> A2[Configure KeyAlgs + options]

  subgraph Issuance
    B([issue / Issue]) --> C{Redis enabled?}
    C -- yes --> D{Device policy\nallow_multi / force_replace}
    D -- violate --> E[Reject]
    D -- pass --> F[Update indexes\nuxd / xd / uxds]
    C -- no --> G[Skip policy]
    F --> H[Build claims (access, refresh)]
    G --> H
    H --> I[Sign JWT (ES256)]
    I --> J[Encrypt JWE (ECDH-ES+A256KW+A256GCM)]
    J --> K{Stateful?}
    K -- yes --> L[Persist refresh + mappings]
    K -- no --> M[Stateless]
    L --> N[Return tokens]
    M --> N
  end

  subgraph Verification
    V([verify / DecryptAndVerify]) --> V0{Cache hit?}
    V0 -- yes --> V1[Return cached claims]
    V0 -- no --> V2[Decrypt JWE]
    V2 --> V3[Verify inner JWT]
    V3 --> V4[Validate iss aud exp nbf]
    V4 --> V5{Check Redis state}
    V5 -- revoked --> V7[Reject]
    V5 -- ok --> V8[Accept]
    V8 --> V9[Cache claims]
    V9 --> V1
  end

  subgraph Refresh
    R([refresh / auto_login]) --> R1[Decrypt+Verify refresh]
    R1 --> R2{ValidateRefreshForDevice}
    R2 -- fail --> R3[Reject]
    R2 -- pass --> R4[Issue new pair]
    R4 --> R5[Rotate old refresh (tombstone)]
  end

  subgraph Revocation
    X([logout / revoke]) --> X1[Write tombstone + delete]
  end

  N --> V
  V1 --> R
  R5 --> V
```

## Contents

- Overview / 目标
- Quick Start
- Core Features
- Algorithms & Formats
- Architecture & Flows
- API Surface (Summary)
- Device & Session Policies
- Redis Data Model
- Verification Modes & Opaque Alternative
- Performance Notes
- Production Guidance
- Demo Server Endpoints
- Code Examples

## 1. Overview / 目标


Provide secure, compact, cache-friendly Access & Refresh tokens with optional server-side state and fine-grained device / cross-device constraints. 可在“纯加密无状态”与“Redis 有状态”间自由切换。

---

## 2. Quick Start

```powershell
go mod tidy
go run ./cmd/server
```

Issue a token pair (stateless or stateful if Redis configured) via POST `/issue`.

---

## 3. Core Features

- Nested signed JWT (JWS) -> JWE (confidentiality + integrity); optional signed JWT (JWS)-only for access.
- Functional Options for issuance (`Issue`, `AuthLogin`, `AutoLoginWithRefresh`).
- Refresh rotation & tombstone revocation.
- Device occupancy + cross-device single-session enforcement.
- Parsed-claims cache to offload crypto on hot paths.
- Extensible verification: `VerifyAnyAccess` / `VerifyAnyRefresh` auto-detect JWE/signed JWT (JWS)/legacy.
- Mutator hook for persisted claims (without altering signed IDs).

---

## 4. Algorithms & Formats

- Inner signed JWT (JWS): ES256 (P-256) header: `typ=JWT`, `kid=<sig_kid>`
- Outer JWE (default): ECDH-ES + A256KW + A256GCM header: `cty=JWT`, `kid=<enc_kid>`
- Optional RSA: `RSA_OAEP_256` + `A256GCM` (adjust `KeyAlgs.KeyMgmtAlg`).
- Refresh claims include `RID` (refresh id) and `FID` (family id) for rotation.

“ES256” 是签名算法；JWE 使用 ECDH-ES (可选直接或 A256KW 包裹) 与内容加密算法。

---

## 5. Architecture & Flows

See Mermaid diagram above: Issuance, Verification, Refresh/Rotation, Revocation, Policy checks.

---

## 6. API Surface (Summary)

Key Types:

- `AccessCustomClaims`, `RefreshCustomClaims`, `KeyAlgs`, `IssueResult`, `AuthSeed`.
- Errors: `ErrDeviceOccupied`, `ErrUserLoggedInElsewhere`, `ErrRefreshNotCurrent`, `ErrUserLoginForbidden`.

Issuance:

- Low-level: `IssueAccessAndRefreshJWE`, `IssueAccessAndRefreshJWEWithClaims`.
- High-level: `Issue(...)` with options: `WithKeys`, `WithSubject`, `WithAudience`, `WithClient`, `WithDevice`, `WithScope`, `WithTTL`, `WithForceReplace`, `WithDeviceAllowMultiUser`, `WithDeviceIndex`.
- Auth login: `AuthLogin` + `WithAuthStore`, `WithAuthIssueOptions`, `WithAuthTTL`, `WithAuthTTLFunc`, `WithAuthUIDValidator`.
- Auto login (silent refresh): `AutoLoginWithRefresh` + `WithAuto*` options.

Verification:

- `DecryptAndVerifyAccess`, `DecryptAndVerifyRefresh`.
- `VerifyAccessJWS`, `VerifyRefreshJWS`, `VerifyAnyAccess`, `VerifyAnyRefresh`, `GuessTokenKind`.

Policy Helpers:

- `IsSameDeviceLoggedIn`, `ValidateRefreshForDevice`.

State / Store:

- `RedisTokenStore` implements `TokenStore` + `DeviceIndexStore` (refresh persistence / rotation / occupant & per-user device index / parsed claims cache / revocation tombstones).

Keys:

- `GenerateES256Key`, `GenerateRSA2048`.

---

## 7. Device & Session Policies / 设备与会话策略

Functional Options control behavior:

| Option | 描述 |
|--------|------|
| `WithDeviceAllowMultiUser(false)` | 单设备独占模式（默认 true 允许多用户）|
| `WithForceReplace(true)` | 跨设备单会话：同用户在其它设备已登录时顶号；false 则拒绝新的登录|
| 默认同设备再次登录 | 自动顶号，无需额外开关 |

辅助检查：`ValidateRefreshForDevice` 确保刷新令牌为当前设备最新；`IsSameDeviceLoggedIn` 查询同设备是否已有会话。

---

## 8. Redis Data Model / 键模式

Prefix configurable (examples use `auth:`). Keys:

- `rtk:{rid}`: JSON(refresh claims) EX=ttl
- `fid:{fid}`: current RID for family rotation
- `rev:a:{jti}`: access revocation tombstone
- `rev:r:{rid}`: refresh revocation tombstone
- `rc-cache:{sha256(token)}`: cached parsed refresh claims
- `uxd:{uid}|{device}`: current RID per user+device
- `xd:{device}`: occupant `{uid,rid}` when multi-user disabled
- `uxds:{uid}`: set of device IDs (per user)

TTL derives from token expiry; tombstones mitigate replay after deletion.

---

## 9. Verification Modes & Opaque Alternative

`VerifyAnyAccess` / `VerifyAnyRefresh` attempt: structure guess -> JWE -> signed JWT (JWS) -> legacy decoder.

Opaque Alternative: issue random IDs, store full claims server-side (reference tokens). Trades cryptographic self-containment for CPU savings & instantaneous revocation.

---

## 10. Performance Notes

Issuance: 1 ECDSA-P256 signature + 1 JWE encryption (ECDH-ES key agreement + AES-GCM). Verify does inverse operations. Tips:

- Reuse signer/encrypter instances when batching.
- Keep claims small (minimize ciphertext length & CPU).
- Cache parsed claims for repeat verification in shared Redis.
- Consider signed JWT (JWS)-only access (no confidentiality) for lighter hot-path tokens.

---

## 11. Production Guidance / 生产建议

- Separate key sets (`use=sig` vs `use=enc`), rotate `kid` regularly.
- Pin allowed algorithms; reject unexpected header algs.
- Enforce TTL bounds; monitor refresh rotation suspicious frequencies.
- Consider key pinning per client/service; apply rate limiting on refresh endpoints.
- Use structured auditing for revocation / force-replace events.

---

## 12. Demo Server Endpoints

`POST /issue` – basic issuance (stateless fallback).
`POST /issue_policy` – issuance with device/cross-device flags (`allow_multi`, `force_replace`).
`POST /verify` – verify access or refresh (`type=access|refresh`).
`POST /refresh` – rotate refresh + new access (simple TTLs).
`POST /auto_login` – silent sign-in using a refresh token.
`POST /refresh_policy` – refresh with device policy check.
`POST /logout` – revoke by token/JTI/RID.
`POST /revoke` – tombstone revoke (access or refresh).
`POST /device_status` – check same-device login existence.

Example `/issue` request:

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

Policy request extra fields:

```json
{
  "allow_multi": true,
  "force_replace": false
}
```

---

## 13. Code Examples

Minimal issuance (stateful with Redis device policy):

```go
algs := tokens.KeyAlgs{SignAlg: jose.ES256, KeyMgmtAlg: jose.ECDH_ES_A256KW, ContentEncryption: jose.A256GCM}
res := tokens.Issue(ctx, store,
    tokens.WithKeys(signKid, signPriv, encKid, &encPubKey, algs),
    tokens.WithAudience(iss, aud),
    tokens.WithSubject(uid, sub),
    tokens.WithDevice(deviceID),
    tokens.WithClient(clientID),
    tokens.WithScope("read"),
    tokens.WithTTL(10*time.Minute, 14*24*time.Hour),
    tokens.WithDeviceAllowMultiUser(false), // device exclusive
    tokens.WithForceReplace(true),          // cross-device single session
)
if res.Err != nil { panic(res.Err) }
fmt.Println(res.AccessJWE, res.RefreshJWE)
```

Silent auto-login (refresh rotation + new pair):

```go
newAccess, newRefresh, ac, rc, err := tokens.AutoLoginWithRefresh(
    ctx,
    tokens.WithAutoStore(store),
    tokens.WithAutoDecryptKey(encPriv),
    tokens.WithAutoFindSigKey(findSigKeyByKID),
    tokens.WithAutoKeys(signKid, signPriv, encKid, &encPubKey, algs),
    tokens.WithAutoAudience(iss, aud),
    tokens.WithAutoTTL(10*time.Minute, 14*24*time.Hour),
    tokens.WithAutoRefreshToken(oldRefresh),
)
```

Unified verification (works for JWE/signed JWT (JWS)/opaque):

```go
claims, err := tokens.VerifyAnyAccess(token, encPriv, findSigKeyByKID, iss, aud, legacyDecoder)
```

Validate refresh token for current device mapping:

```go
if err := tokens.ValidateRefreshForDevice(ctx, dstore, refreshClaims); err != nil {
    // reject: not current
}
```

Opaque token strategy (示例思路): random 32-byte ID -> Redis `opaque:<id>` JSON(claims) TTL=exp.

---

## Move Module / 调整模块路径

Update `go.mod` to your module path (e.g. `module github.com/yourorg/tokens`) and fix imports.

```powershell
go mod tidy
go build ./...
go test ./...
```

---

## FAQ

Q: Why nested JWE?  Confidentiality of claims (device/client/scope) and kid separation; enables selective disclosure scenarios.
Q: Why keep refresh state but not access?  Access can remain short-lived & stateless for scale; refresh rotation + revocation handles session security.
Q: How to switch to RSA?  Replace `KeyAlgs.KeyMgmtAlg` with `jose.RSA_OAEP_256` and supply `*rsa.PublicKey` / private for decrypt.

---

## License

Internal / TBD (add your license statement here).

---

## Change Log (Highlights)

- Introduced functional options issuance (`Issue`, `AuthLogin`, `AutoLoginWithRefresh`).
- Added device indexes (uxd / xd / uxds) and cross-device policies.
- Added parsed claims cache + VerifyAny* helpers.
- Added refresh family rotation (RID/FID + atomic rotate).

---
欢迎反馈改进建议。Enjoy secure & efficient token flows!
