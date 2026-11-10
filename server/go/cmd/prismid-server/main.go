package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

//go:embed static/prismid.bundle.js
var embeddedPrismBundleJS []byte

const (
	maxRequestBodyBytes   = 64 << 10 // 64 KiB
	DefaultBearerTokenTTL = 24 * time.Hour
	DefaultStepUpTokenTTL = 5 * time.Minute
)

type ipTokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*ipTokenBucket
}

func newIPRateLimiter(ratePerSec, burst float64) *ipRateLimiter {
	if ratePerSec <= 0 {
		return nil
	}
	if burst < 1 {
		burst = ratePerSec
	}
	return &ipRateLimiter{
		rate:    ratePerSec,
		burst:   burst,
		buckets: make(map[string]*ipTokenBucket),
	}
}

func (rl *ipRateLimiter) allow(ip string, now time.Time) bool {
	if rl == nil {
		return true
	}
	if ip == "" {
		ip = "unknown"
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, exists := rl.buckets[ip]; !exists && len(rl.buckets) >= 8192 {
		cutoff := now.Add(-5 * time.Minute)
		for k, b := range rl.buckets {
			if b.lastSeen.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		for len(rl.buckets) >= 8192 {
			for k := range rl.buckets {
				delete(rl.buckets, k)
				break
			}
		}
	}
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &ipTokenBucket{tokens: rl.burst - 1, lastSeen: now}
		return true
	}
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func main() {
	addr := flag.String("addr", ":8090", "HTTP listen address")
	hmacSecret := flag.String("secret", "", "HMAC secret key (or PRISMID_HMAC_SECRET env)")
	demoMode := flag.Bool("demo-mode", true, "Enable standalone lab playground UI and demo identity/IP simulation headers")
	trustProxy := flag.Bool("trust-proxy", false, "Trust X-Forwarded-For and X-Real-IP headers from reverse proxy")
	corsOrigin := flag.String("cors-origin", "", "Allowed CORS Origin (defaults to request origin only in -demo-mode)")
	rateLimit := flag.Float64("rate-limit", 60, "Per-IP API rate limit in requests/sec (0 to disable)")
	allowLegacyTokens := flag.Bool("allow-legacy-tokens", false, "Accept deprecated non-expiring <subject_id>.<hmac> bearer tokens")
	flag.Parse()

	secret := strings.TrimSpace(*hmacSecret)
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("PRISMID_HMAC_SECRET"))
	}
	if secret == "" {
		if !*demoMode {
			log.Fatalf("PRISMID_HMAC_SECRET (or -secret flag) is required when -demo-mode=false")
		}
		var randKey [32]byte
		if _, err := rand.Read(randKey[:]); err != nil {
			log.Fatalf("failed to generate ephemeral HMAC secret: %v", err)
		}
		secret = hex.EncodeToString(randKey[:])
		log.Printf("[WARN] Running in demo-mode with ephemeral per-process HMAC secret; pass -secret or PRISMID_HMAC_SECRET for persistent slice IDs")
	}

	verifier := prismid.NewVerifier(prismid.Config{
		HMACSecret:   []byte(secret),
		ChallengeTTL: 60 * time.Second,
		OnKeyRebindAudit: func(ev prismid.KeyRebindAuditEvent) {
			log.Printf("[AUDIT] key_rebind audit_id=%s outcome=%s subject_id=%s beacon_slice_id=%s new_key_slice_id=%s prev_present=%v ip=%s",
				ev.AuditID, ev.Outcome, ev.SubjectID, ev.BeaconSliceID, ev.NewDeviceKeySliceID, ev.PreviousKeyPresent, ev.ClientIP)
		},
	}, prismid.NewMemoryChallengeStore())
	riskGraph := prismid.NewRiskGraphWithClock(prismid.AuthoritativeConfidenceThreshold, time.Now)

	handler := newHTTPHandlerWithOptions(verifier, riskGraph, []byte(secret), *demoMode, *trustProxy, *corsOrigin, *rateLimit, *rateLimit*2, *allowLegacyTokens)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("PrismID standalone verification server v1.0.1 listening on %s (demo-mode=%v, trust-proxy=%v, rate-limit=%.0f/s)", *addr, *demoMode, *trustProxy, *rateLimit)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func newHTTPHandler(verifier *prismid.Verifier, riskGraph *prismid.RiskGraph, secret []byte, demoMode, trustProxy bool, corsOrigin string) http.Handler {
	return newHTTPHandlerWithRateLimit(verifier, riskGraph, secret, demoMode, trustProxy, corsOrigin, 300, 600)
}

func newHTTPHandlerWithRateLimit(verifier *prismid.Verifier, riskGraph *prismid.RiskGraph, secret []byte, demoMode, trustProxy bool, corsOrigin string, ratePerSec, burst float64) http.Handler {
	return newHTTPHandlerWithOptions(verifier, riskGraph, secret, demoMode, trustProxy, corsOrigin, ratePerSec, burst, false)
}

func newHTTPHandlerWithOptions(verifier *prismid.Verifier, riskGraph *prismid.RiskGraph, secret []byte, demoMode, trustProxy bool, corsOrigin string, ratePerSec, burst float64, allowLegacyTokens bool) http.Handler {
	allowProxyHeaders := trustProxy || demoMode
	limiter := newIPRateLimiter(ratePerSec, burst)
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "ok",
			"engine":    "prismid-go",
			"version":   "1.0.1",
			"demo_mode": demoMode,
		})
	})

	mux.HandleFunc("/prismid.bundle.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(embeddedPrismBundleJS)
	})

	mux.HandleFunc("/api/v1/risk/should-collect", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"should_collect": true,
		})
	})

	mux.HandleFunc("/api/v1/risk/challenge", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDWithLegacy(r, demoMode, secret, allowLegacyTokens)
		if authErr || (!demoMode && subjectID == "") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"accepted": false,
				"error":    "invalid or unverified bearer token; when -demo-mode=false, Authorization must be Bearer <subject_id>.<exp_unix>.<hmac_sha256_hex>",
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		ch, err := verifier.IssueChallenge(r.Context(), extractClientIP(r, allowProxyHeaders))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ch)
	})

	mux.HandleFunc("/api/v1/risk/identify", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDWithLegacy(r, demoMode, secret, allowLegacyTokens)
		if authErr || (!demoMode && subjectID == "") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"accepted": false,
				"error":    "invalid or unverified bearer token; when -demo-mode=false, Authorization must be Bearer <subject_id>.<exp_unix>.<hmac_sha256_hex>",
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var req prismid.IdentifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"accepted": false, "error": "invalid request body"})
			return
		}
		res, err := verifier.VerifyAndDerive(r.Context(), req, extractClientIP(r, allowProxyHeaders))
		if err != nil {
			status := http.StatusBadRequest
			if vErr, ok := err.(*prismid.VerificationError); ok {
				if vErr.Code == prismid.ErrCodeChallengeInvalid {
					status = http.StatusConflict
				}
				writeJSON(w, status, map[string]any{
					"accepted": false,
					"code":     vErr.Code,
					"message":  vErr.Detail,
				})
				return
			}
			writeJSON(w, status, map[string]any{"accepted": false, "message": err.Error()})
			return
		}

		if subjectID != "" {
			snap := riskGraph.RecordVerification(subjectID, time.Now().UTC(), res)
			writeJSON(w, http.StatusOK, map[string]any{
				"accepted":                     res.Accepted,
				"confidence":                   res.Confidence,
				"device_key_slice_id":          res.DeviceKeySliceID,
				"device_key_bound":             res.DeviceKeyBound,
				"device_key_attested":          res.DeviceKeyAttested,
				"device_key_recovery_required": res.DeviceKeyRecoveryRequired,
				"exact_slice_id":               res.ExactSliceID,
				"keychain_slice_id":            res.KeychainSliceID,
				"beacon_slice_id":              res.BeaconSliceID,
				"gpu_audio_slice_id":           res.GpuAudioSliceID,
				"sys_net_slice_id":             res.SysNetSliceID,
				"crowd_slice_id":               res.CrowdSliceID,
				"subnet_crowd_triggered":       res.SubnetCrowdTriggered,
				"ip_subnet":                    res.IPSubnet,
				"is_native":                    res.IsNative,
				"is_virtual_gpu":               res.IsVirtualGPU,
				"spoof_trap_triggered":         res.SpoofTrapTriggered,
				"spoof_flags":                  res.SpoofFlags,
				"privacy_signals":              res.PrivacySignals,
				"risk_status":                  snap.RiskStatus,
				"risk_pending":                 snap.RiskPending,
				"truncated":                    snap.Truncated,
				"burst_suspicion":              snap.BurstSuspicion,
				"log_odds_score":               snap.LogOddsScore,
				"evidence_chain":               snap.EvidenceChain,
				"component_snapshot":           snap,
			})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	// Audited TOFU device-key recovery endpoint (DeepSeek v1.0.1 P1 #1):
	// Requires:
	//  1. Authenticated subject bearer token.
	//  2. Independent expiring HMAC step-up token (`step_up_token` or `X-PrismID-StepUp-Token`) bound to `(subject_id, beacon_slice_id)`.
	//  3. Exclusive ownership of `beacon_slice_id` by `subject_id` in the risk graph (verified BEFORE nonce consumption).
	//  4. Single-use `challenge_nonce` + ECDSA P-256 signature over `"prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>"`.
	//  5. Structured audit event emission and zero leakage of previous device-key slice IDs.
	mux.HandleFunc("/api/v1/risk/rebind-key", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDWithLegacy(r, demoMode, secret, allowLegacyTokens)
		if authErr || subjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var req prismid.KeyRebindRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
			return
		}
		req.SubjectID = subjectID
		clientIP := extractClientIP(r, allowProxyHeaders)

		bcnSlice, err := verifier.DeriveBeaconSliceID(req.BeaconID)
		if err != nil {
			verifier.RecordDeniedRebindAudit(subjectID, "", clientIP, "denied_invalid_beacon")
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"accepted": false,
				"code":     prismid.ErrCodeRebindInvalidKeyProof,
				"error":    err.Error(),
			})
			return
		}

		stepUpTok := strings.TrimSpace(req.StepUpToken)
		if stepUpTok == "" {
			stepUpTok = strings.TrimSpace(r.Header.Get("X-PrismID-StepUp-Token"))
		}
		if !VerifyStepUpToken(stepUpTok, subjectID, bcnSlice, secret) {
			verifier.RecordDeniedRebindAudit(subjectID, bcnSlice, clientIP, "denied_invalid_stepup")
			writeJSON(w, http.StatusForbidden, map[string]any{
				"accepted": false,
				"code":     prismid.ErrCodeRebindForbidden,
				"error":    "valid step_up_token bound to subject_id and beacon_slice_id is required",
			})
			return
		}

		res, err := verifier.RebindDeviceKeyWithProof(r.Context(), req, riskGraph.SubjectOwnsBeaconExclusively, clientIP)
		if err != nil {
			status := http.StatusBadRequest
			if vErr, ok := err.(*prismid.VerificationError); ok {
				switch vErr.Code {
				case prismid.ErrCodeRebindForbidden:
					status = http.StatusForbidden
				case prismid.ErrCodeChallengeInvalid:
					status = http.StatusConflict
				}
				writeJSON(w, status, map[string]any{
					"accepted": false,
					"code":     vErr.Code,
					"error":    vErr.Detail,
				})
				return
			}
			writeJSON(w, status, map[string]any{"accepted": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	// Step-up authenticated spoof cooldown clearance endpoint (DeepSeek v1.0.1 P1 #2):
	// Allows an account that passed out-of-band MFA/Passkey step-up to clear single-account spoof
	// cooldown immediately while preserving permanent `HistoricalSpoof` (+1.5 log-odds) audit memory.
	mux.HandleFunc("/api/v1/risk/clear-spoof", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDWithLegacy(r, demoMode, secret, allowLegacyTokens)
		if authErr || subjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var body struct {
			StepUpToken string `json:"step_up_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		stepUpTok := strings.TrimSpace(body.StepUpToken)
		if stepUpTok == "" {
			stepUpTok = strings.TrimSpace(r.Header.Get("X-PrismID-StepUp-Token"))
		}
		if !VerifyStepUpToken(stepUpTok, subjectID, "clear_spoof", secret) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"accepted": false,
				"error":    "valid step_up_token for clear_spoof is required",
			})
			return
		}
		cleared := riskGraph.ClearSubjectSpoofAfterStepUp(subjectID, time.Now().UTC())
		writeJSON(w, http.StatusOK, map[string]any{
			"subject_id":         subjectID,
			"cleared":            cleared,
			"component_snapshot": riskGraph.EvaluateSubject(subjectID),
		})
	})

	// Explainability endpoint (DeepSeek #6): returns the full ComponentSnapshot, calibrated
	// LogOddsScore, SharedSliceIDs, and human-readable EvidenceChain for a subject.
	mux.HandleFunc("/api/v1/risk/explain", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDWithLegacy(r, demoMode, secret, allowLegacyTokens)
		if authErr || subjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		snap := riskGraph.EvaluateSubject(subjectID)
		writeJSON(w, http.StatusOK, snap)
	})

	// Privacy erasure endpoint (DeepSeek #6 GDPR/CCPA): removes all graph edges AND TOFU key bindings
	// for exclusively owned storage beacons of the subject.
	mux.HandleFunc("/api/v1/risk/subject", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, demoMode, corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDWithLegacy(r, demoMode, secret, allowLegacyTokens)
		if authErr || subjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		removed, beacons := riskGraph.RemoveSubjectAndCollectBeacons(subjectID)
		purgedBindings := verifier.ForgetBeacons(r.Context(), beacons...)
		writeJSON(w, http.StatusOK, map[string]any{
			"subject_id":          subjectID,
			"deleted":             removed,
			"purged_key_bindings": purgedBindings,
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		if !demoMode {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "demo console disabled"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(standaloneIndexHTML))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodOptions {
			clientIP := extractClientIP(r, allowProxyHeaders)
			if !limiter.allow(clientIP, time.Now()) {
				enableCORS(w, r, demoMode, corsOrigin)
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"accepted": false,
					"error":    "rate limit exceeded",
				})
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func extractClientIP(r *http.Request, allowProxyHeaders bool) string {
	if allowProxyHeaders {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func deriveBearerAuthKey(secret []byte) []byte {
	sum := sha256.Sum256(append([]byte("prismid-bearer-auth-v1:"), secret...))
	return sum[:]
}

func deriveStepUpAuthKey(secret []byte) []byte {
	sum := sha256.Sum256(append([]byte("prismid-stepup-auth-v1:"), secret...))
	return sum[:]
}

// SignStepUpTokenWithExpiry creates a short-lived domain-separated HMAC-SHA256 step-up token
// bound to a specific `(subjectID, target)` pair (e.g. `target = d_bcn_*` or `"clear_spoof"`).
func SignStepUpTokenWithExpiry(subjectID, target string, expiresAt time.Time, secret []byte) string {
	expStr := strconv.FormatInt(expiresAt.UTC().Unix(), 10)
	mac := hmac.New(sha256.New, deriveStepUpAuthKey(secret))
	mac.Write([]byte("prismid-stepup-v1|" + subjectID + "|" + target + "|" + expStr))
	return "stepup_v1." + expStr + "." + hex.EncodeToString(mac.Sum(nil))
}

// SignStepUpToken creates a 5-minute (`DefaultStepUpTokenTTL`) step-up token for `(subjectID, target)`.
func SignStepUpToken(subjectID, target string, secret []byte) string {
	return SignStepUpTokenWithExpiry(subjectID, target, time.Now().UTC().Add(DefaultStepUpTokenTTL), secret)
}

// VerifyStepUpToken validates a domain-separated step-up token's HMAC signature, expiration,
// subject binding, and action/beacon target binding.
func VerifyStepUpToken(token, expectedSubjectID, expectedTarget string, secret []byte) bool {
	trimmed := strings.TrimSpace(token)
	if !strings.HasPrefix(trimmed, "stepup_v1.") || expectedSubjectID == "" || expectedTarget == "" {
		return false
	}
	rest := trimmed[len("stepup_v1."):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot >= len(rest)-1 {
		return false
	}
	expStr := rest[:dot]
	sigHex := rest[dot+1:]
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().UTC().Unix() > expUnix {
		return false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, deriveStepUpAuthKey(secret))
	mac.Write([]byte("prismid-stepup-v1|" + expectedSubjectID + "|" + expectedTarget + "|" + expStr))
	return hmac.Equal(sigBytes, mac.Sum(nil))
}

// SignSubjectBearerTokenWithExpiry creates an expiring HMAC-SHA256 authenticated bearer token:
// `<subject_id>.<exp_unix_sec>.<hex(HMAC_SHA256(subkey, "prismid-auth-v2|" + subject_id + "|" + exp_unix_sec))>`.
func SignSubjectBearerTokenWithExpiry(subjectID string, expiresAt time.Time, secret []byte) string {
	expStr := strconv.FormatInt(expiresAt.UTC().Unix(), 10)
	mac := hmac.New(sha256.New, deriveBearerAuthKey(secret))
	mac.Write([]byte("prismid-auth-v2|" + subjectID + "|" + expStr))
	return subjectID + "." + expStr + "." + hex.EncodeToString(mac.Sum(nil))
}

// SignSubjectBearerToken creates an HMAC-SHA256 authenticated bearer token for a subject
// with a default 24-hour expiration TTL (`DefaultBearerTokenTTL`).
func SignSubjectBearerToken(subjectID string, secret []byte) string {
	return SignSubjectBearerTokenWithExpiry(subjectID, time.Now().UTC().Add(DefaultBearerTokenTTL), secret)
}

// extractVerifiedSubjectID extracts and authenticates the caller's subject identifier,
// rejecting legacy non-expiring `<subject_id>.<hmac>` tokens by default (DeepSeek v1.0.1 P2 #5).
func extractVerifiedSubjectID(r *http.Request, demoMode bool, hmacSecret []byte) (string, bool) {
	return extractVerifiedSubjectIDWithLegacy(r, demoMode, hmacSecret, false)
}

// extractVerifiedSubjectIDWithLegacy extracts and authenticates the caller's subject identifier.
//   - When demoMode=true: accepts ?subject_id= or Bearer tokens for interactive lab testing.
//   - When demoMode=false: ignores ?subject_id= and strictly requires Authorization to be a valid,
//     unexpired HMAC-SHA256 signed v2 token `Bearer <subject_id>.<exp_unix>.<hmac_sha256_hex>`.
//     Legacy static `<subject_id>.<hmac_sha256_hex>` tokens are rejected unless allowLegacyTokens=true.
func extractVerifiedSubjectIDWithLegacy(r *http.Request, demoMode bool, hmacSecret []byte, allowLegacyTokens bool) (string, bool) {
	if demoMode {
		if q := strings.TrimSpace(r.URL.Query().Get("subject_id")); q != "" {
			return q, false
		}
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		if demoMode {
			return "", false
		}
		return "", true
	}
	rawToken := strings.TrimSpace(auth[7:])
	if rawToken == "" {
		if demoMode {
			return "", false
		}
		return "", true
	}
	if lastDot := strings.LastIndexByte(rawToken, '.'); lastDot > 0 && lastDot < len(rawToken)-1 {
		prefix := rawToken[:lastDot]
		sigHex := rawToken[lastDot+1:]
		sigBytes, err := hex.DecodeString(sigHex)
		if err == nil {
			// Check v2 expiring token format: <subject_id>.<exp_unix>.<hmac>
			if expDot := strings.LastIndexByte(prefix, '.'); expDot > 0 && expDot < len(prefix)-1 {
				sid := prefix[:expDot]
				expStr := prefix[expDot+1:]
				if expUnix, parseErr := strconv.ParseInt(expStr, 10, 64); parseErr == nil {
					mac := hmac.New(sha256.New, deriveBearerAuthKey(hmacSecret))
					mac.Write([]byte("prismid-auth-v2|" + sid + "|" + expStr))
					if hmac.Equal(sigBytes, mac.Sum(nil)) {
						if time.Now().UTC().Unix() > expUnix {
							return "", true
						}
						return sid, false
					}
				}
			}
			// Legacy static HMAC format: <subject_id>.<hmac> (disabled by default in v1.0.1+)
			if allowLegacyTokens {
				mac := hmac.New(sha256.New, deriveBearerAuthKey(hmacSecret))
				mac.Write([]byte("prismid-auth|" + prefix))
				if hmac.Equal(sigBytes, mac.Sum(nil)) {
					return prefix, false
				}
			}
		}
	}
	if demoMode {
		return rawToken, false
	}
	return "", true
}

func enableCORS(w http.ResponseWriter, r *http.Request, demoMode bool, configuredOrigin string) {
	if configuredOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", configuredOrigin)
	} else if demoMode {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Forwarded-For, X-PrismID-StepUp-Token")
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

const standaloneIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>PrismID Standalone Verification &amp; Adversarial Lab</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0f172a; color: #e2e8f0; max-width: 1040px; margin: 32px auto; padding: 0 20px; line-height: 1.5; }
  h1 { color: #38bdf8; margin-bottom: 4px; }
  .subtitle { color: #94a3b8; margin-bottom: 24px; font-size: 14px; }
  .actions { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
  button { background: #0284c7; color: #fff; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 13px; }
  button:hover { background: #0369a1; }
  button.secondary { background: #334155; }
  button.secondary:hover { background: #475569; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .card { background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; }
  .card h3 { margin-top: 0; color: #7dd3fc; font-size: 15px; }
  pre { background: #090d16; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #a7f3d0; max-height: 420px; }
</style>
</head>
<body>
  <h1>PrismID Standalone Verification Console (Demo Lab)</h1>
  <div class="subtitle">Orthogonal Hardware Signal Collection, Dynamic WebGL Shader Challenge &amp; Cross-Thread Lie Detector</div>
  <div class="actions">
    <button id="btn-identify">1. Run Live Browser Identify (prismid-js)</button>
    <button id="btn-proxy" class="secondary">2. Simulate Residential Proxy Rotation + Canvas Noise</button>
    <button id="btn-replay" class="secondary">3. Simulate Nonce Replay Attack</button>
  </div>
  <div class="grid">
    <div class="card">
      <h3>Server Verification &amp; Orthogonal Spectral Slices</h3>
      <pre id="server-out">Click "Run Live Browser Identify" to execute full Challenge -> WebGL Shader -> AEAD -> Go Verify pipeline...</pre>
    </div>
    <div class="card">
      <h3>Client Probe Telemetry &amp; AEAD Envelope</h3>
      <pre id="client-out">Waiting for probe execution...</pre>
    </div>
  </div>
  <script type="module">
    import { createPrismClient, sealPayload } from '/prismid.bundle.js';
    const prism = createPrismClient({ baseUrl: '' });
    let lastWireReq = null;

    document.getElementById('btn-identify').onclick = async () => {
      const chRes = await fetch('/api/v1/risk/challenge', { method: 'POST' });
      const ch = await chRes.json();
      const { request, payload } = await prism.collectAndSeal(ch);
      lastWireReq = request;
      document.getElementById('client-out').textContent = JSON.stringify({
        wire_request_preview: { c: request.c, p_length: request.p.length, p_head: request.p.slice(0, 48) + '...' },
        decrypted_payload: payload,
      }, null, 2);

      const idRes = await fetch('/api/v1/risk/identify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      const verifyResult = await idRes.json();
      document.getElementById('server-out').textContent = JSON.stringify(verifyResult, null, 2);
    };

    document.getElementById('btn-proxy').onclick = async () => {
      const chRes = await fetch('/api/v1/risk/challenge', { method: 'POST' });
      const ch = await chRes.json();
      const { payload } = await prism.collectAndSeal(ch);
      payload.system.canvas_2d_hash = 'spoofed_canvas_' + Math.random().toString(16).slice(2);
      payload.system.fonts_bitmap_hash = 'spoofed_fonts_' + Math.random().toString(16).slice(2);
      payload.system.screen_spec = '3840x2160x24@2';
      const p = await sealPayload(ch.nonce, JSON.stringify(payload));
      const randomIp = '198.51.' + Math.floor(Math.random() * 250) + '.42';
      const idRes = await fetch('/api/v1/risk/identify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': randomIp },
        body: JSON.stringify({ c: ch.nonce, p }),
      });
      const verifyResult = await idRes.json();
      document.getElementById('server-out').textContent = JSON.stringify({
        simulated_proxy_ip: randomIp,
        note: 'Notice that gpu_audio_slice_id (d_gpu_*) remains 100% identical despite new IP & mutated Canvas/Fonts/Screen!',
        result: verifyResult,
      }, null, 2);
    };

    document.getElementById('btn-replay').onclick = async () => {
      if (!lastWireReq) {
        alert('Run step 1 first to capture a valid packet.');
        return;
      }
      const idRes = await fetch('/api/v1/risk/identify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lastWireReq),
      });
      const verifyResult = await idRes.json();
      document.getElementById('server-out').textContent = JSON.stringify(verifyResult, null, 2);
    };
  </script>
</body>
</html>`
