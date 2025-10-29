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

		access, refresh, acClaims, rcClaims, err := tokens.IssueAccessAndRefreshJWEWithClaims(
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
		// Persist and warm caches if Redis is enabled
		if store != nil {
			ctx := r.Context()
			if acClaims.Claims.Expiry != nil {
				ttl := time.Until(acClaims.Claims.Expiry.Time())
				_ = store.SaveAccess(ctx, acClaims.Claims.ID, acClaims, ttl)
				_ = store.CacheAccessClaims(ctx, access, acClaims, ttl)
			}
			if rcClaims.Claims.Expiry != nil {
				ttl := time.Until(rcClaims.Claims.Expiry.Time())
				_ = store.SaveRefresh(ctx, rcClaims.RID, rcClaims.FID, rcClaims, ttl)
				_ = store.CacheRefreshClaims(ctx, refresh, rcClaims, ttl)
			}
		}
		_ = json.NewEncoder(w).Encode(issueResp{AccessJWE: access, RefreshJWE: refresh})
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
			// Revoke old refresh (tombstone for remaining TTL)
			if rc.Claims.Expiry != nil {
				_ = store.RevokeRefresh(r.Context(), rc.RID, time.Until(rc.Claims.Expiry.Time()))
			} else {
				_ = store.RevokeRefresh(r.Context(), rc.RID, 24*time.Hour)
			}
			if acClaims.Claims.Expiry != nil {
				ttl := time.Until(acClaims.Claims.Expiry.Time())
				_ = store.SaveAccess(r.Context(), acClaims.Claims.ID, acClaims, ttl)
				_ = store.CacheAccessClaims(r.Context(), acJWE, acClaims, ttl)
			}
			if rfClaims.Claims.Expiry != nil {
				ttl := time.Until(rfClaims.Claims.Expiry.Time())
				_ = store.SaveRefresh(r.Context(), rfClaims.RID, rfClaims.FID, rfClaims, ttl)
				_ = store.CacheRefreshClaims(r.Context(), rfJWE, rfClaims, ttl)
			}
		}
		_ = json.NewEncoder(w).Encode(refreshResp{AccessJWE: acJWE, RefreshJWE: rfJWE})
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
