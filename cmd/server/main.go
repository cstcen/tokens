package main

import (
	"context"
	"crypto"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	redis "github.com/redis/go-redis/v9"

	"github.com/cstcen/tokens/tokens"
)

type issueReq struct {
	UID              string   `json:"uid"`
	Sub              string   `json:"sub"`
	Aud              string   `json:"aud"`
	Iss              string   `json:"iss"`
	DeviceID         string   `json:"device_id"`
	ClientID         string   `json:"client_id"`
	Scope            []string `json:"scope"`
	AccessTTLMinutes int      `json:"access_ttl_minutes"`
	RefreshTTLDays   int      `json:"refresh_ttl_days"`
}

type issueResp struct {
	AccessJWE  string `json:"access_jwe"`
	RefreshJWE string `json:"refresh_jwe"`
}

// Policy issue request
type issuePolicyReq struct {
	issueReq
	// Policy: "allow" (default) | "reject" | "single"
	Policy string `json:"policy"`
}

type deviceStatusReq struct {
	UID      string `json:"uid"`
	DeviceID string `json:"device_id"`
}

type deviceStatusResp struct {
	Exists bool   `json:"exists"`
	Error  string `json:"error,omitempty"`
}

type verifyReq struct {
	Type  string `json:"type"` // "access" | "refresh"
	Token string `json:"token"`
	Iss   string `json:"iss"`
	Aud   string `json:"aud"`
}

type verifyResp struct {
	Valid  bool        `json:"valid"`
	Claims interface{} `json:"claims,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func main() {
	// Keys (in-memory demo):
	signKid := "sig-1"
	encKid := "enc-1"

	signPriv, err := tokens.GenerateES256Key()
	if err != nil {
		log.Fatalf("generate es256: %v", err)
	}
	// Use EC key for JWE (ECDH-ES) instead of RSA
	encPriv, err := tokens.GenerateES256Key()
	if err != nil {
		log.Fatalf("generate es256(enc): %v", err)
	}

	// Key registry for verification
	var sigKeyPub crypto.PublicKey = &signPriv.PublicKey
	findSigKeyByKID := func(kid string) crypto.PublicKey {
		if kid == signKid {
			return sigKeyPub
		}
		return nil
	}

	// Optional Redis integration
	var store tokens.TokenStore
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb := redis.NewClient(&redis.Options{
			Addr:     addr,
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       0,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("redis disabled (ping failed): %v", err)
		} else {
			prefix := os.Getenv("REDIS_PREFIX")
			store = tokens.NewRedisTokenStore(rdb, prefix)
			log.Printf("redis enabled at %s with prefix '%s'", addr, prefix)
		}
		cancel()
	} else {
		log.Printf("redis disabled (REDIS_ADDR not set)")
	}

	algs := tokens.KeyAlgs{
		SignAlg:           jose.ES256,
		KeyMgmtAlg:        jose.ECDH_ES_A256KW,
		ContentEncryption: jose.A256GCM,
	}

	http.HandleFunc("/issue", func(w http.ResponseWriter, r *http.Request) {
		var req issueReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Iss == "" {
			req.Iss = "https://auth.local"
		}
		if req.Aud == "" {
			req.Aud = "api://local"
		}
		if req.Sub == "" {
			req.Sub = req.UID
		}
		if req.AccessTTLMinutes <= 0 {
			req.AccessTTLMinutes = 10
		}
		if req.RefreshTTLDays <= 0 {
			req.RefreshTTLDays = 14
		}

		// Use new Functional Options API when Redis is enabled; otherwise fallback to stateless issue
		if store != nil {
			// If store also supports device index, provide it (policy default allow here)
			opts := []tokens.IssueOption{
				tokens.WithKeys(signKid, signPriv, encKid, &encPriv.PublicKey, algs),
				tokens.WithAudience(req.Iss, req.Aud),
				tokens.WithSubject(req.UID, req.Sub),
				tokens.WithClient(req.ClientID),
				tokens.WithDevice(req.DeviceID),
				tokens.WithScope(req.Scope...),
				tokens.WithTTL(time.Duration(req.AccessTTLMinutes)*time.Minute, time.Duration(req.RefreshTTLDays)*24*time.Hour),
			}
			if rs, ok := store.(tokens.DeviceIndexStore); ok {
				opts = append(opts, tokens.WithDeviceIndex(rs))
			}
			access, refresh, acClaims, rcClaims, err := tokens.Issue(r.Context(), store, opts...)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			// Optional: warm caches
			if acClaims.Claims.Expiry != nil {
				_ = store.CacheAccessClaims(r.Context(), access, acClaims, time.Until(acClaims.Claims.Expiry.Time()))
			}
			if rcClaims.Claims.Expiry != nil {
				_ = store.CacheRefreshClaims(r.Context(), refresh, rcClaims, time.Until(rcClaims.Claims.Expiry.Time()))
			}
			_ = json.NewEncoder(w).Encode(issueResp{AccessJWE: access, RefreshJWE: refresh})
			return
		}

		// Fallback: issue without persistence when Redis disabled
		access, refresh, _, _, err := tokens.IssueAccessAndRefreshJWEWithClaims(
			signKid, signPriv,
			encKid, &encPriv.PublicKey,
			algs,
			req.Iss, req.Aud, req.Sub, req.UID, req.DeviceID, req.ClientID,
			time.Duration(req.AccessTTLMinutes)*time.Minute,
			time.Duration(req.RefreshTTLDays)*24*time.Hour,
			req.Scope,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(issueResp{AccessJWE: access, RefreshJWE: refresh})
	})

	// Minimal example: issue with same-device policy
	// Body: { ...issueReq fields..., "policy":"allow|reject|single" }
	http.HandleFunc("/issue_policy", func(w http.ResponseWriter, r *http.Request) {
		var req issuePolicyReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Iss == "" {
			req.Iss = "https://auth.local"
		}
		if req.Aud == "" {
			req.Aud = "api://local"
		}
		if req.Sub == "" {
			req.Sub = req.UID
		}
		if req.AccessTTLMinutes <= 0 {
			req.AccessTTLMinutes = 10
		}
		if req.RefreshTTLDays <= 0 {
			req.RefreshTTLDays = 14
		}

		// Map string policy to enum
		pol := tokens.DevicePolicyAllowSameDevice
		switch req.Policy {
		case "reject":
			pol = tokens.DevicePolicyRejectIfSameDeviceExists
		case "single":
			pol = tokens.DevicePolicySingleActivePerDevice
		}

		// If Redis available, use new Issue API with policy; otherwise, allow-only fallback
		if store != nil {
			opts := []tokens.IssueOption{
				tokens.WithKeys(signKid, signPriv, encKid, &encPriv.PublicKey, algs),
				tokens.WithAudience(req.Iss, req.Aud),
				tokens.WithSubject(req.UID, req.Sub),
				tokens.WithClient(req.ClientID),
				tokens.WithDevice(req.DeviceID),
				tokens.WithScope(req.Scope...),
				tokens.WithTTL(time.Duration(req.AccessTTLMinutes)*time.Minute, time.Duration(req.RefreshTTLDays)*24*time.Hour),
				tokens.WithPolicy(pol),
			}
			if rs, ok := store.(tokens.DeviceIndexStore); ok {
				opts = append(opts, tokens.WithDeviceIndex(rs))
			}
			access, refresh, _, _, err := tokens.Issue(r.Context(), store, opts...)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(issueResp{AccessJWE: access, RefreshJWE: refresh})
			return
		}
		if pol != tokens.DevicePolicyAllowSameDevice {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy requires redis store"})
			return
		}
		// Fallback stateless issue for allow policy
		access, refresh, _, _, err := tokens.IssueAccessAndRefreshJWEWithClaims(
			signKid, signPriv,
			encKid, &encPriv.PublicKey,
			algs,
			req.Iss, req.Aud, req.Sub, req.UID, req.DeviceID, req.ClientID,
			time.Duration(req.AccessTTLMinutes)*time.Minute,
			time.Duration(req.RefreshTTLDays)*24*time.Hour,
			req.Scope,
		)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(issueResp{AccessJWE: access, RefreshJWE: refresh})
	})

	// Query if same-device already logged in (requires Redis)
	http.HandleFunc("/device_status", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(deviceStatusResp{Error: "redis not enabled"})
			return
		}
		rs, ok := store.(tokens.DeviceIndexStore)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(deviceStatusResp{Error: "device index not supported"})
			return
		}
		var req deviceStatusReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		exists, err := tokens.IsSameDeviceLoggedIn(r.Context(), rs, req.UID, req.DeviceID)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(deviceStatusResp{Error: err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(deviceStatusResp{Exists: exists})
	})

	http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		var req verifyReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Iss == "" {
			req.Iss = "https://auth.local"
		}
		if req.Aud == "" {
			req.Aud = "api://local"
		}

		switch req.Type {
		case "refresh":
			if store != nil {
				if cached, ok, _ := store.GetCachedRefresh(r.Context(), req.Token); ok {
					_ = json.NewEncoder(w).Encode(verifyResp{Valid: true, Claims: cached})
					return
				}
			}
			claims, err := tokens.DecryptAndVerifyRefresh(req.Token, encPriv, findSigKeyByKID, req.Iss, req.Aud)
			if err != nil {
				_ = json.NewEncoder(w).Encode(verifyResp{Valid: false, Error: err.Error()})
				return
			}
			if store != nil {
				if _, found, _ := store.GetRefresh(r.Context(), claims.RID); !found {
					_ = json.NewEncoder(w).Encode(verifyResp{Valid: false, Error: "revoked or not found"})
					return
				}
				if claims.Claims.Expiry != nil {
					_ = store.CacheRefreshClaims(r.Context(), req.Token, claims, time.Until(claims.Claims.Expiry.Time()))
				}
			}
			_ = json.NewEncoder(w).Encode(verifyResp{Valid: true, Claims: claims})
		default:
			if store != nil {
				if cached, ok, _ := store.GetCachedAccess(r.Context(), req.Token); ok {
					_ = json.NewEncoder(w).Encode(verifyResp{Valid: true, Claims: cached})
					return
				}
			}
			claims, err := tokens.DecryptAndVerifyAccess(req.Token, encPriv, findSigKeyByKID, req.Iss, req.Aud)
			if err != nil {
				_ = json.NewEncoder(w).Encode(verifyResp{Valid: false, Error: err.Error()})
				return
			}
			if store != nil {
				if _, found, _ := store.GetAccess(r.Context(), claims.Claims.ID); !found {
					_ = json.NewEncoder(w).Encode(verifyResp{Valid: false, Error: "revoked or not found"})
					return
				}
				if claims.Claims.Expiry != nil {
					_ = store.CacheAccessClaims(r.Context(), req.Token, claims, time.Until(claims.Claims.Expiry.Time()))
				}
			}
			_ = json.NewEncoder(w).Encode(verifyResp{Valid: true, Claims: claims})
		}
	})

	// Refresh route: rotate refresh and issue new access
	type refreshReq struct {
		Token string `json:"token"`
		Iss   string `json:"iss"`
		Aud   string `json:"aud"`
	}
	type refreshResp struct {
		AccessJWE  string `json:"access_jwe"`
		RefreshJWE string `json:"refresh_jwe"`
	}

	// Refresh with device policy (minimal): policy = "allow" (default) | "single"
	type refreshPolicyReq struct {
		Token            string `json:"token"`
		Iss              string `json:"iss"`
		Aud              string `json:"aud"`
		Policy           string `json:"policy"`
		AccessTTLMinutes int    `json:"access_ttl_minutes"`
		RefreshTTLDays   int    `json:"refresh_ttl_days"`
	}
	type refreshPolicyResp struct {
		AccessJWE  string `json:"access_jwe"`
		RefreshJWE string `json:"refresh_jwe"`
	}
	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		var req refreshReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Iss == "" {
			req.Iss = "https://auth.local"
		}
		if req.Aud == "" {
			req.Aud = "api://local"
		}

		// Cache-first for refresh claims
		var rc tokens.RefreshCustomClaims
		var err error
		if store != nil {
			if cached, ok, _ := store.GetCachedRefresh(r.Context(), req.Token); ok {
				rc = cached
			}
		}
		if rc.RID == "" {
			rc, err = tokens.DecryptAndVerifyRefresh(req.Token, encPriv, findSigKeyByKID, req.Iss, req.Aud)
			if err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}
		// State checks
		if store != nil {
			if _, found, _ := store.GetRefresh(r.Context(), rc.RID); !found {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "revoked or not found"})
				return
			}
			if cur, ok, _ := store.GetFID(r.Context(), rc.FID); ok && cur != rc.RID {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "refresh reuse detected"})
				return
			}
		}

		// Issue new tokens; keep same sub/uid/device/client/scope
		acJWE, rfJWE, acClaims, rfClaims, err := tokens.IssueAccessAndRefreshJWEWithClaims(
			signKid, signPriv,
			encKid, &encPriv.PublicKey,
			algs,
			rc.Claims.Issuer, rc.Claims.Audience[0], rc.UID, rc.UID, rc.DeviceID, rc.ClientID,
			10*time.Minute, 14*24*time.Hour,
			rc.Scope,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if store != nil {
			// Atomic rotation: save new A/R, update fid->rid, delete old rid, write tombstone
			oldTTL := 24 * time.Hour
			if rc.Claims.Expiry != nil {
				oldTTL = time.Until(rc.Claims.Expiry.Time())
				if oldTTL < 0 {
					oldTTL = 0
				}
			}
			aTTL := 0 * time.Second
			rTTL := 0 * time.Second
			if acClaims.Claims.Expiry != nil {
				aTTL = time.Until(acClaims.Claims.Expiry.Time())
			}
			if rfClaims.Claims.Expiry != nil {
				rTTL = time.Until(rfClaims.Claims.Expiry.Time())
			}
			_ = store.RotateRefreshAndSaveAccessAtomic(r.Context(),
				rc.RID, oldTTL,
				acClaims.Claims.ID, acClaims, aTTL,
				rfClaims.RID, rfClaims.FID, rfClaims, rTTL,
			)
			if aTTL > 0 {
				_ = store.CacheAccessClaims(r.Context(), acJWE, acClaims, aTTL)
			}
			if rTTL > 0 {
				_ = store.CacheRefreshClaims(r.Context(), rfJWE, rfClaims, rTTL)
			}
		}
		_ = json.NewEncoder(w).Encode(refreshResp{AccessJWE: acJWE, RefreshJWE: rfJWE})
	})

	http.HandleFunc("/refresh_policy", func(w http.ResponseWriter, r *http.Request) {
		var req refreshPolicyReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Iss == "" {
			req.Iss = "https://auth.local"
		}
		if req.Aud == "" {
			req.Aud = "api://local"
		}
		if req.AccessTTLMinutes <= 0 {
			req.AccessTTLMinutes = 10
		}
		if req.RefreshTTLDays <= 0 {
			req.RefreshTTLDays = 14
		}

		// Decrypt + verify refresh
		rc, err := tokens.DecryptAndVerifyRefresh(req.Token, encPriv, findSigKeyByKID, req.Iss, req.Aud)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		// Optional state checks when Redis enabled
		var dstore tokens.DeviceIndexStore
		if store != nil {
			if _, found, _ := store.GetRefresh(r.Context(), rc.RID); !found {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "revoked or not found"})
				return
			}
			if cur, ok, _ := store.GetFID(r.Context(), rc.FID); ok && cur != rc.RID {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "refresh reuse detected"})
				return
			}
			if rs, ok := store.(tokens.DeviceIndexStore); ok {
				dstore = rs
			}
		}

		// Enforce device policy (minimal): if policy==single, ensure rc is current for device
		if req.Policy == "single" && dstore != nil {
			if err := tokens.ValidateRefreshForDevice(r.Context(), dstore, rc); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
		}

		// Issue new tokens, preserving identity/device info
		acJWE, rfJWE, acClaims, rfClaims, err := tokens.IssueAccessAndRefreshJWEWithClaims(
			signKid, signPriv,
			encKid, &encPriv.PublicKey,
			algs,
			rc.Claims.Issuer, rc.Claims.Audience[0], rc.UID, rc.UID, rc.DeviceID, rc.ClientID,
			time.Duration(req.AccessTTLMinutes)*time.Minute,
			time.Duration(req.RefreshTTLDays)*24*time.Hour,
			rc.Scope,
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		// Persist rotation and update caches (if Redis available)
		if store != nil {
			oldTTL := 24 * time.Hour
			if rc.Claims.Expiry != nil {
				oldTTL = time.Until(rc.Claims.Expiry.Time())
				if oldTTL < 0 {
					oldTTL = 0
				}
			}
			aTTL := time.Duration(0)
			rTTL := time.Duration(0)
			if acClaims.Claims.Expiry != nil {
				aTTL = time.Until(acClaims.Claims.Expiry.Time())
			}
			if rfClaims.Claims.Expiry != nil {
				rTTL = time.Until(rfClaims.Claims.Expiry.Time())
			}
			_ = store.RotateRefreshAndSaveAccessAtomic(r.Context(),
				rc.RID, oldTTL,
				acClaims.Claims.ID, acClaims, aTTL,
				rfClaims.RID, rfClaims.FID, rfClaims, rTTL,
			)
			if aTTL > 0 {
				_ = store.CacheAccessClaims(r.Context(), acJWE, acClaims, aTTL)
			}
			if rTTL > 0 {
				_ = store.CacheRefreshClaims(r.Context(), rfJWE, rfClaims, rTTL)
			}
			// Update device mapping to new RID (keep device single-active on new refresh)
			if dstore != nil && rc.DeviceID != "" && rc.UID != "" && rTTL > 0 {
				_ = dstore.SetDeviceRID(r.Context(), rc.UID, rc.DeviceID, rfClaims.RID, rTTL)
			}
		}

		_ = json.NewEncoder(w).Encode(refreshPolicyResp{AccessJWE: acJWE, RefreshJWE: rfJWE})
	})

	// Logout route: revoke by refresh or access token/id
	type logoutReq struct {
		Type  string `json:"type"` // access|refresh|both
		Token string `json:"token,omitempty"`
		JTI   string `json:"jti,omitempty"`
		RID   string `json:"rid,omitempty"`
	}
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "redis not enabled"})
			return
		}
		var req logoutReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Type {
		case "access":
			jti := req.JTI
			if jti == "" && req.Token != "" {
				if ac, err := tokens.DecryptAndVerifyAccess(req.Token, encPriv, findSigKeyByKID, "", ""); err == nil {
					jti = ac.Claims.ID
				}
			}
			if jti == "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing jti or token"})
				return
			}
			_ = store.RevokeAccess(r.Context(), jti, 60*time.Minute)
		case "refresh":
			rid := req.RID
			if rid == "" && req.Token != "" {
				if rc, err := tokens.DecryptAndVerifyRefresh(req.Token, encPriv, findSigKeyByKID, "", ""); err == nil {
					rid = rc.RID
				}
			}
			if rid == "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing rid or token"})
				return
			}
			_ = store.RevokeRefresh(r.Context(), rid, 24*time.Hour)
		case "both":
			// Best-effort revoke both if present
			if req.Token != "" {
				if ac, err := tokens.DecryptAndVerifyAccess(req.Token, encPriv, findSigKeyByKID, "", ""); err == nil {
					_ = store.RevokeAccess(r.Context(), ac.Claims.ID, 60*time.Minute)
				}
				if rc, err := tokens.DecryptAndVerifyRefresh(req.Token, encPriv, findSigKeyByKID, "", ""); err == nil {
					_ = store.RevokeRefresh(r.Context(), rc.RID, 24*time.Hour)
				}
			} else {
				if req.JTI != "" {
					_ = store.RevokeAccess(r.Context(), req.JTI, 60*time.Minute)
				}
				if req.RID != "" {
					_ = store.RevokeRefresh(r.Context(), req.RID, 24*time.Hour)
				}
			}
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "type must be access|refresh|both"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	// Optional revoke endpoint
	type revokeReq struct {
		Type       string `json:"type"` // "access" | "refresh"
		Token      string `json:"token,omitempty"`
		JTI        string `json:"jti,omitempty"`
		RID        string `json:"rid,omitempty"`
		TTLMinutes int    `json:"ttl_minutes,omitempty"`
	}
	http.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		if store == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "redis not enabled"})
			return
		}
		var req revokeReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		ttl := time.Duration(req.TTLMinutes) * time.Minute
		if ttl <= 0 {
			ttl = 60 * time.Minute
		}
		switch req.Type {
		case "access":
			jti := req.JTI
			if jti == "" && req.Token != "" {
				if ac, err := tokens.DecryptAndVerifyAccess(req.Token, encPriv, findSigKeyByKID, "", ""); err == nil {
					jti = ac.Claims.ID
				}
			}
			if jti == "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing jti or token"})
				return
			}
			_ = store.RevokeAccess(r.Context(), jti, ttl)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		case "refresh":
			rid := req.RID
			if rid == "" && req.Token != "" {
				if rc, err := tokens.DecryptAndVerifyRefresh(req.Token, encPriv, findSigKeyByKID, "", ""); err == nil {
					rid = rc.RID
				}
			}
			if rid == "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing rid or token"})
				return
			}
			_ = store.RevokeRefresh(r.Context(), rid, ttl)
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "type must be access or refresh"})
		}
	})

	log.Println("JWE demo server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
