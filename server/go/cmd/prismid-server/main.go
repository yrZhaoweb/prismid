package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

//go:embed static/prismid.bundle.js
var embeddedPrismBundleJS []byte

const (
	serverVersion         = "1.1.0"
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

// replayAndRevocationGuard enforces single-use step-up token consumption (DeepSeek S2-10)
// and bearer/subject token revocation (DeepSeek S3-52), optionally backed by a cluster-wide
// DistributedReplayGuard (such as RedisStore) for multi-instance deployments.
type replayAndRevocationGuard struct {
	mu              sync.Mutex
	consumedStepUp  map[string]int64
	revokedTokenSHA map[[32]byte]int64
	revokedSubjects map[string]int64
	distributed     prismid.DistributedReplayGuard
}

func newReplayAndRevocationGuard() *replayAndRevocationGuard {
	return &replayAndRevocationGuard{
		consumedStepUp:  make(map[string]int64),
		revokedTokenSHA: make(map[[32]byte]int64),
		revokedSubjects: make(map[string]int64),
	}
}

func (g *replayAndRevocationGuard) attachDistributed(d prismid.DistributedReplayGuard) {
	if g == nil {
		return
	}
	if d != nil {
		if rv := reflect.ValueOf(d); rv.Kind() == reflect.Pointer && rv.IsNil() {
			d = nil
		}
	}
	g.mu.Lock()
	g.distributed = d
	g.mu.Unlock()
}

func (g *replayAndRevocationGuard) getDistributed() prismid.DistributedReplayGuard {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	d := g.distributed
	g.mu.Unlock()
	return d
}

func (g *replayAndRevocationGuard) consumeStepUpJTI(jti string, expUnix int64, nowUnix int64) bool {
	if jti == "" {
		return false
	}
	if dist := g.getDistributed(); dist != nil {
		ok, err := dist.ConsumeStepUpJTI(context.Background(), jti, expUnix, nowUnix)
		if err != nil || !ok {
			return false
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.consumedStepUp) >= 16384 {
		for k, exp := range g.consumedStepUp {
			if nowUnix > exp {
				delete(g.consumedStepUp, k)
			}
		}
		for len(g.consumedStepUp) >= 16384 {
			for k := range g.consumedStepUp {
				delete(g.consumedStepUp, k)
				break
			}
		}
	}
	if prevExp, used := g.consumedStepUp[jti]; used && nowUnix <= prevExp {
		return false
	}
	g.consumedStepUp[jti] = expUnix
	return true
}

func (g *replayAndRevocationGuard) revokeToken(rawToken string, expUnix int64) string {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rawToken))
	shaHex := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Unix()
	g.mu.Lock()
	if len(g.revokedTokenSHA) >= 16384 {
		for k, exp := range g.revokedTokenSHA {
			if now > exp {
				delete(g.revokedTokenSHA, k)
			}
		}
	}
	g.revokedTokenSHA[sum] = expUnix
	dist := g.distributed
	g.mu.Unlock()
	if dist != nil {
		_ = dist.RevokeTokenHash(context.Background(), shaHex, expUnix, now)
	}
	return shaHex
}

func (g *replayAndRevocationGuard) exportSnapshot(nowUnix int64) *prismid.ReplayGuardSnapshot {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	snap := &prismid.ReplayGuardSnapshot{
		ConsumedStepUp:  make(map[string]int64, len(g.consumedStepUp)),
		RevokedTokenSHA: make(map[string]int64, len(g.revokedTokenSHA)),
		RevokedSubjects: make(map[string]int64, len(g.revokedSubjects)),
	}
	for jti, exp := range g.consumedStepUp {
		if nowUnix <= exp {
			snap.ConsumedStepUp[jti] = exp
		}
	}
	for sum, exp := range g.revokedTokenSHA {
		if nowUnix <= exp {
			snap.RevokedTokenSHA[hex.EncodeToString(sum[:])] = exp
		}
	}
	for sid, until := range g.revokedSubjects {
		if nowUnix <= until {
			snap.RevokedSubjects[sid] = until
		}
	}
	return snap
}

func (g *replayAndRevocationGuard) importSnapshot(snap *prismid.ReplayGuardSnapshot, nowUnix int64) {
	if g == nil || snap == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for jti, exp := range snap.ConsumedStepUp {
		if jti != "" && nowUnix <= exp {
			g.consumedStepUp[jti] = exp
		}
	}
	for shaHex, exp := range snap.RevokedTokenSHA {
		if nowUnix > exp {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSpace(shaHex))
		if err == nil && len(raw) == 32 {
			var sum [32]byte
			copy(sum[:], raw)
			g.revokedTokenSHA[sum] = exp
		}
	}
	for sid, until := range snap.RevokedSubjects {
		if sid != "" && nowUnix <= until {
			g.revokedSubjects[sid] = until
		}
	}
}

func (g *replayAndRevocationGuard) revokeSubject(subjectID string, untilUnix int64) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return
	}
	now := time.Now().UTC().Unix()
	g.mu.Lock()
	if len(g.revokedSubjects) >= 16384 {
		for k, exp := range g.revokedSubjects {
			if now > exp {
				delete(g.revokedSubjects, k)
			}
		}
	}
	g.revokedSubjects[subjectID] = untilUnix
	dist := g.distributed
	g.mu.Unlock()
	if dist != nil {
		_ = dist.RevokeSubject(context.Background(), subjectID, untilUnix, now)
	}
}

func (g *replayAndRevocationGuard) isRevoked(rawToken, subjectID string, nowUnix int64) bool {
	if g == nil {
		return false
	}
	trimmedTok := strings.TrimSpace(rawToken)
	var sum [32]byte
	var shaHex string
	if trimmedTok != "" {
		sum = sha256.Sum256([]byte(trimmedTok))
		shaHex = hex.EncodeToString(sum[:])
	}
	g.mu.Lock()
	if trimmedTok != "" {
		if exp, ok := g.revokedTokenSHA[sum]; ok {
			if nowUnix <= exp {
				g.mu.Unlock()
				return true
			}
			delete(g.revokedTokenSHA, sum)
		}
	}
	if subjectID != "" {
		if until, ok := g.revokedSubjects[subjectID]; ok {
			if nowUnix <= until {
				g.mu.Unlock()
				return true
			}
			delete(g.revokedSubjects, subjectID)
		}
	}
	dist := g.distributed
	g.mu.Unlock()

	if dist != nil {
		if rev, err := dist.IsRevoked(context.Background(), shaHex, subjectID, nowUnix); err == nil && rev {
			return true
		}
	}
	return false
}

type serverHandlerConfig struct {
	hmacSecret        []byte
	authSecret        []byte
	authSecretPrev    []byte
	stepUpSecret      []byte
	stepUpSecretPrev  []byte
	adminSecret       []byte
	demoMode          bool
	trustProxy        bool
	trustedProxies    *prismid.TrustedProxyChecker
	shadowMode        bool
	enableMultiTenant bool
	metricsPublic     bool
	corsOrigin        string
	ratePerSec        float64
	burst             float64
	allowLegacyTokens bool
	stateStore        *prismid.FileStateStore
	memStore          *prismid.MemoryChallengeStore
	redisStore        *prismid.RedisStore
	replayGuard       *replayAndRevocationGuard
	metrics           *prismid.Metrics
}

func envOrFlag(flagVal, envKey string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv(envKey))
}

func envBoolOrFlag(flagVal bool, envKey string) bool {
	if flagVal {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envKey))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// validateStartupConfig fails closed on unsafe/incomplete production CLI/env combinations (DeepSeek P2-2).
func validateStartupConfig(demoMode bool, hmacSecret string, requireTurnstile bool, turnstileSecret string) error {
	if !demoMode && strings.TrimSpace(hmacSecret) == "" {
		return errors.New("PRISMID_HMAC_SECRET (or -secret flag) is required when -demo-mode=false")
	}
	if requireTurnstile && strings.TrimSpace(turnstileSecret) == "" {
		return errors.New("-require-turnstile=true requires -turnstile-secret or PRISMID_TURNSTILE_SECRET")
	}
	return nil
}

func buildCloudflareTurnstileVerifier(secret string) func(ctx context.Context, token, clientIP string) (bool, error) {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	return func(ctx context.Context, token, clientIP string) (bool, error) {
		form := url.Values{}
		form.Set("secret", secret)
		form.Set("response", token)
		if clientIP != "" {
			form.Set("remoteip", clientIP)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://challenges.cloudflare.com/turnstile/v0/siteverify", strings.NewReader(form.Encode()))
		if err != nil {
			return false, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := httpClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("turnstile verify request failed: %w", err)
		}
		defer resp.Body.Close()
		var out struct {
			Success bool `json:"success"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return false, fmt.Errorf("decode turnstile response: %w", err)
		}
		return out.Success, nil
	}
}

func main() {
	// S3-51: Safe production defaults — loopback listen address and demo-mode OFF by default!
	addr := flag.String("addr", "127.0.0.1:8090", "HTTP listen address")
	hmacSecret := flag.String("secret", "", "Primary slice HMAC secret (or PRISMID_HMAC_SECRET)")
	authSecretFlag := flag.String("auth-secret", "", "Independent Bearer auth HMAC secret (or PRISMID_AUTH_SECRET)")
	authSecretPrevFlag := flag.String("auth-secret-prev", "", "Previous Bearer auth HMAC secret during rotation (or PRISMID_AUTH_SECRET_PREV)")
	stepUpSecretFlag := flag.String("stepup-secret", "", "Independent Step-Up token HMAC secret (or PRISMID_STEPUP_SECRET)")
	stepUpSecretPrevFlag := flag.String("stepup-secret-prev", "", "Previous Step-Up token HMAC secret during rotation (or PRISMID_STEPUP_SECRET_PREV)")
	adminSecretFlag := flag.String("admin-secret", "", "Admin API secret for minting/revoking tokens (or PRISMID_ADMIN_SECRET)")
	turnstileSecretFlag := flag.String("turnstile-secret", "", "Cloudflare Turnstile secret key (or PRISMID_TURNSTILE_SECRET)")
	requireTurnstile := flag.Bool("require-turnstile", false, "Require valid Turnstile token on /api/v1/risk/identify")
	enforceChallengeIP := flag.Bool("enforce-challenge-ip", false, "Reject /identify if client /24 (/48) subnet differs from /challenge")
	hardAnchorPolicyStr := flag.String("hard-anchor-policy", string(prismid.HardAnchorPolicySharedStepUp), "Hard-anchor multi-account policy: shared_step_up, step_up_all, strict_1to1, or disabled")
	stateFileFlag := flag.String("state-file", "", "Optional WAL + background-compacted snapshot file path to persist RiskGraph & TOFU bindings (or PRISMID_STATE_FILE)")
	stateFlushInterval := flag.Duration("state-flush-interval", 30*time.Second, "Minimum interval between background state snapshot compactions when -state-file is enabled")
	auditLogFlag := flag.String("audit-log", "", "Optional append-only JSONL file path for durable security audit events (or PRISMID_AUDIT_LOG)")
	redisURLFlag := flag.String("redis-url", "", "Optional Redis URL (redis:// or rediss://) for horizontally scaled multi-instance ChallengeStore, RiskGraph & ReplayGuard (or PRISMID_REDIS_URL)")
	trustedProxyCIDRsFlag := flag.String("trusted-proxy-cidrs", "", "Comma-separated trusted reverse-proxy CIDRs/IPs for right-to-left X-Forwarded-For stripping & JA4/H2 headers (or PRISMID_TRUSTED_PROXY_CIDRS)")
	shadowModeFlag := flag.Bool("shadow-mode", false, "Shadow evaluation mode: compute full risk verdicts & metrics while returning risk_status=green to callers (or PRISMID_SHADOW_MODE=true)")
	enableMultiTenantFlag := flag.Bool("enable-multi-tenant", false, "Enable per-tenant slice & graph isolation via X-PrismID-Tenant-ID header (or PRISMID_ENABLE_MULTI_TENANT=true)")
	metricsPublicFlag := flag.Bool("metrics-public", false, "Allow unauthenticated GET /metrics scraping even when -admin-secret is configured (or PRISMID_METRICS_PUBLIC=true)")
	demoMode := flag.Bool("demo-mode", false, "Enable standalone lab playground UI and demo identity/IP simulation headers (NEVER enable in production)")
	trustProxy := flag.Bool("trust-proxy", false, "Trust X-Forwarded-For and X-Real-IP headers from reverse proxy (prefer -trusted-proxy-cidrs in production)")
	corsOrigin := flag.String("cors-origin", "", "Allowed CORS Origin (defaults to request origin only in -demo-mode)")
	rateLimit := flag.Float64("rate-limit", 60, "Per-IP API rate limit in requests/sec (0 to disable)")
	allowLegacyTokens := flag.Bool("allow-legacy-tokens", false, "Accept deprecated non-expiring <subject_id>.<hmac> bearer tokens")
	flag.Parse()

	hardPolicy, err := prismid.ParseHardAnchorPolicy(*hardAnchorPolicyStr)
	if err != nil {
		log.Fatalf("invalid -hard-anchor-policy: %v", err)
	}

	var trustedChecker *prismid.TrustedProxyChecker
	if rawCIDRs := envOrFlag(*trustedProxyCIDRsFlag, "PRISMID_TRUSTED_PROXY_CIDRS"); rawCIDRs != "" {
		tc, err := prismid.ParseTrustedProxyCIDRs(rawCIDRs)
		if err != nil {
			log.Fatalf("invalid -trusted-proxy-cidrs: %v", err)
		}
		trustedChecker = tc
	}

	shadowMode := envBoolOrFlag(*shadowModeFlag, "PRISMID_SHADOW_MODE")
	enableMultiTenant := envBoolOrFlag(*enableMultiTenantFlag, "PRISMID_ENABLE_MULTI_TENANT")
	metricsPublic := envBoolOrFlag(*metricsPublicFlag, "PRISMID_METRICS_PUBLIC")

	secret := envOrFlag(*hmacSecret, "PRISMID_HMAC_SECRET")
	tsSecret := envOrFlag(*turnstileSecretFlag, "PRISMID_TURNSTILE_SECRET")
	if err := validateStartupConfig(*demoMode, secret, *requireTurnstile, tsSecret); err != nil {
		log.Fatalf("invalid server configuration: %v", err)
	}
	if secret == "" {
		var randKey [32]byte
		if _, err := rand.Read(randKey[:]); err != nil {
			log.Fatalf("failed to generate ephemeral HMAC secret: %v", err)
		}
		secret = hex.EncodeToString(randKey[:])
		log.Printf("[WARN] Running in demo-mode with ephemeral per-process HMAC secret; pass -secret or PRISMID_HMAC_SECRET for persistent slice IDs")
	}

	var auditStore prismid.AuditStore
	if auditPath := envOrFlag(*auditLogFlag, "PRISMID_AUDIT_LOG"); auditPath != "" {
		fa, err := prismid.NewFileAuditStore(auditPath)
		if err != nil {
			log.Fatalf("failed to open audit log %q: %v", auditPath, err)
		}
		auditStore = fa
	}

	var redisStore *prismid.RedisStore
	if redisURL := envOrFlag(*redisURLFlag, "PRISMID_REDIS_URL"); redisURL != "" {
		rs, err := prismid.NewRedisStore(prismid.RedisOptions{URL: redisURL})
		if err != nil {
			log.Fatalf("failed to connect to Redis (%s): %v", redisURL, err)
		}
		redisStore = rs
	}

	memStore := prismid.NewMemoryChallengeStore()
	var activeStore prismid.ChallengeStore = memStore
	var graphBackend prismid.GraphBackend
	if redisStore != nil {
		activeStore = redisStore
		graphBackend = redisStore
	}
	riskGraph := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{
		MinConfidence:    prismid.AuthoritativeConfidenceThreshold,
		HardAnchorPolicy: hardPolicy,
		NowFunc:          time.Now,
		Store:            activeStore,
		Backend:          graphBackend,
	})
	guard := newReplayAndRevocationGuard()
	if redisStore != nil {
		guard.attachDistributed(redisStore)
	}

	var stateStore *prismid.FileStateStore
	if statePath := envOrFlag(*stateFileFlag, "PRISMID_STATE_FILE"); statePath != "" {
		fs, err := prismid.NewFileStateStore(statePath)
		if err != nil {
			log.Fatalf("failed to initialize state file %q: %v", statePath, err)
		}
		fs.SetErrorHandler(func(pErr error) {
			log.Printf("[ERROR] state persistence failed (%s): %v", statePath, pErr)
		})
		restoredGuard, hadState, err := fs.RestoreInto(context.Background(), riskGraph, memStore)
		if err != nil {
			log.Fatalf("failed to restore state file %q: %v", statePath, err)
		}
		riskGraph.SetHardAnchorPolicy(hardPolicy)
		if restoredGuard != nil {
			guard.importSnapshot(restoredGuard, time.Now().UTC().Unix())
		}
		if hadState {
			log.Printf("Restored persisted RiskGraph (%d subjects), TOFU bindings, and replay guard from %s", riskGraph.Stats().ActiveSubjects, statePath)
		}
		fs.StartBackgroundWorker(
			riskGraph,
			memStore,
			func() *prismid.ReplayGuardSnapshot {
				return guard.exportSnapshot(time.Now().UTC().Unix())
			},
			250*time.Millisecond,
			*stateFlushInterval,
		)
		stateStore = fs
	}

	vCfg := prismid.Config{
		HMACSecret:         []byte(secret),
		ChallengeTTL:       60 * time.Second,
		EnforceChallengeIP: *enforceChallengeIP,
		RequireTurnstile:   *requireTurnstile,
		AuditStore:         auditStore,
		OnKeyRebindAudit: func(ev prismid.KeyRebindAuditEvent) {
			log.Printf("[AUDIT] action=%s audit_id=%s outcome=%s subject_id=%s beacon_slice_id=%s new_key_slice_id=%s prev_present=%v retired_prev=%v ip=%s",
				ev.Action, ev.AuditID, ev.Outcome, ev.SubjectID, ev.BeaconSliceID, ev.NewDeviceKeySliceID, ev.PreviousKeyPresent, ev.RetiredPreviousKey, ev.ClientIP)
		},
	}
	if tsSecret != "" {
		vCfg.TurnstileVerifier = buildCloudflareTurnstileVerifier(tsSecret)
	}

	verifier := prismid.NewVerifier(vCfg, activeStore)
	verifier.BindRiskGraph(riskGraph)

	hCfg := serverHandlerConfig{
		hmacSecret:        []byte(secret),
		authSecret:        []byte(envOrFlag(*authSecretFlag, "PRISMID_AUTH_SECRET")),
		authSecretPrev:    []byte(envOrFlag(*authSecretPrevFlag, "PRISMID_AUTH_SECRET_PREV")),
		stepUpSecret:      []byte(envOrFlag(*stepUpSecretFlag, "PRISMID_STEPUP_SECRET")),
		stepUpSecretPrev:  []byte(envOrFlag(*stepUpSecretPrevFlag, "PRISMID_STEPUP_SECRET_PREV")),
		adminSecret:       []byte(envOrFlag(*adminSecretFlag, "PRISMID_ADMIN_SECRET")),
		demoMode:          *demoMode,
		trustProxy:        *trustProxy,
		trustedProxies:    trustedChecker,
		shadowMode:        shadowMode,
		enableMultiTenant: enableMultiTenant,
		metricsPublic:     metricsPublic,
		corsOrigin:        *corsOrigin,
		ratePerSec:        *rateLimit,
		burst:             *rateLimit * 2,
		allowLegacyTokens: *allowLegacyTokens,
		stateStore:        stateStore,
		memStore:          memStore,
		redisStore:        redisStore,
		replayGuard:       guard,
		metrics:           prismid.NewMetrics(),
	}

	handler := newHTTPHandlerWithConfig(verifier, riskGraph, hCfg)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if stateStore != nil {
			if err := stateStore.FlushAndClose(ctx, riskGraph, memStore, guard.exportSnapshot(time.Now().UTC().Unix())); err != nil {
				log.Printf("[ERROR] failed to flush state on shutdown: %v", err)
			}
		}
		if redisStore != nil {
			_ = redisStore.Close()
		}
	}()

	log.Printf("PrismID standalone verification server v%s listening on %s (demo-mode=%v, shadow-mode=%v, multi-tenant=%v, redis=%v, policy=%s, rate-limit=%.0f/s)",
		serverVersion, *addr, *demoMode, shadowMode, enableMultiTenant, redisStore != nil, hardPolicy, *rateLimit)
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
	return newHTTPHandlerWithConfig(verifier, riskGraph, serverHandlerConfig{
		hmacSecret:        secret,
		demoMode:          demoMode,
		trustProxy:        trustProxy,
		corsOrigin:        corsOrigin,
		ratePerSec:        ratePerSec,
		burst:             burst,
		allowLegacyTokens: allowLegacyTokens,
	})
}

func isValidTenantID(tid string) bool {
	if len(tid) == 0 || len(tid) > 64 {
		return false
	}
	for i := 0; i < len(tid); i++ {
		c := tid[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func scopeTenantSubjectID(tenantID, rawSubjectID string) (string, bool) {
	if tenantID == "" || rawSubjectID == "" {
		return rawSubjectID, true
	}
	expectedPrefix := "t:" + tenantID + ":"
	if strings.HasPrefix(rawSubjectID, expectedPrefix) {
		return rawSubjectID, true
	}
	if strings.HasPrefix(rawSubjectID, "t:") {
		// Bearer token was minted for a different explicit tenant namespace!
		return "", false
	}
	return expectedPrefix + rawSubjectID, true
}

func newHTTPHandlerWithConfig(verifier *prismid.Verifier, riskGraph *prismid.RiskGraph, cfg serverHandlerConfig) http.Handler {
	verifier.BindRiskGraph(riskGraph)
	if cfg.redisStore != nil {
		riskGraph.AttachBackend(cfg.redisStore)
	}
	authPrimary := cfg.authSecret
	if len(authPrimary) == 0 {
		authPrimary = cfg.hmacSecret
	}
	stepUpPrimary := cfg.stepUpSecret
	if len(stepUpPrimary) == 0 {
		stepUpPrimary = cfg.hmacSecret
	}

	allowProxyHeaders := cfg.trustProxy || cfg.demoMode
	limiter := newIPRateLimiter(cfg.ratePerSec, cfg.burst)
	guard := cfg.replayGuard
	if guard == nil {
		guard = newReplayAndRevocationGuard()
	}
	if cfg.redisStore != nil && guard.getDistributed() == nil {
		guard.attachDistributed(cfg.redisStore)
	}
	metrics := cfg.metrics
	if metrics == nil {
		metrics = prismid.NewMetrics()
	}

	resolveClientIP := func(r *http.Request) string {
		return prismid.ExtractRealClientIP(r, cfg.trustedProxies, allowProxyHeaders)
	}
	resolveTransportSignals := func(r *http.Request) prismid.TransportSignals {
		return prismid.ExtractTrustedTransportSignals(r, cfg.trustedProxies, allowProxyHeaders)
	}
	resolveTenant := func(w http.ResponseWriter, r *http.Request) (string, *prismid.Verifier, bool) {
		if !cfg.enableMultiTenant {
			return "", verifier, true
		}
		tid := strings.TrimSpace(r.Header.Get("X-PrismID-Tenant-ID"))
		if tid == "" {
			return "", verifier, true
		}
		if !isValidTenantID(tid) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"accepted": false,
				"error":    "invalid X-PrismID-Tenant-ID header (expected 1..64 alphanumeric, '_' or '-' chars)",
			})
			return "", nil, false
		}
		return tid, verifier.WithTenant(tid), true
	}

	appendWAL := func(rec prismid.StateWALRecord, syncImmediate bool) {
		if cfg.stateStore != nil {
			_ = cfg.stateStore.AppendWAL(rec, syncImmediate)
		}
	}

	// Admin endpoints for standalone deployments (S2-25, S3-52, S1-5): protected by X-PrismID-Admin-Secret.
	requireAdmin := func(w http.ResponseWriter, r *http.Request) bool {
		if len(cfg.adminSecret) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "admin API disabled; configure -admin-secret or PRISMID_ADMIN_SECRET"})
			return false
		}
		provided := strings.TrimSpace(r.Header.Get("X-PrismID-Admin-Secret"))
		if provided == "" {
			auth := strings.TrimSpace(r.Header.Get("Authorization"))
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				provided = strings.TrimSpace(auth[7:])
			}
		}
		if len(provided) == 0 || subtle.ConstantTimeCompare([]byte(provided), cfg.adminSecret) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid admin secret"})
			return false
		}
		return true
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		stats := riskGraph.Stats()
		writeJSON(w, http.StatusOK, map[string]any{
			"status":             "ok",
			"engine":             "prismid-go",
			"version":            serverVersion,
			"demo_mode":          cfg.demoMode,
			"shadow_mode":        cfg.shadowMode,
			"multi_tenant":       cfg.enableMultiTenant,
			"redis_enabled":      cfg.redisStore != nil,
			"hard_anchor_policy": stats.HardAnchorPolicy,
			"active_subjects":    stats.ActiveSubjects,
			"persist_errors":     cfg.stateStore.PersistErrors(),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if len(cfg.adminSecret) > 0 && !cfg.metricsPublic {
			if !requireAdmin(w, r) {
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(metrics.RenderPrometheus(riskGraph, cfg.stateStore.PersistErrors())))
	})

	mux.HandleFunc("/prismid.bundle.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(embeddedPrismBundleJS)
	})

	mux.HandleFunc("/api/v1/risk/should-collect", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"should_collect": true,
		})
	})

	mux.HandleFunc("/api/v1/risk/challenge", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		tid, scopedVerifier, tenantOK := resolveTenant(w, r)
		if !tenantOK {
			return
		}
		subjectID, authErr := extractVerifiedSubjectIDMultiKey(r, cfg.demoMode, authPrimary, cfg.authSecretPrev, cfg.allowLegacyTokens, guard)
		if authErr || (!cfg.demoMode && subjectID == "") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"accepted": false,
				"error":    "invalid, expired, or revoked bearer token",
			})
			return
		}
		if _, okScope := scopeTenantSubjectID(tid, subjectID); !okScope {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"accepted": false,
				"error":    "bearer token tenant mismatch",
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		ch, err := scopedVerifier.IssueChallenge(r.Context(), resolveClientIP(r))
		if err != nil {
			var vErr *prismid.VerificationError
			if errors.As(err, &vErr) && vErr.Code == prismid.ErrCodeChallengeRateLimited {
				metrics.RecordChallengeRateLimited()
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"accepted": false,
					"code":     vErr.Code,
					"error":    vErr.Detail,
				})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		metrics.RecordChallengeIssued()
		writeJSON(w, http.StatusOK, ch)
	})

	mux.HandleFunc("/api/v1/risk/identify", func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		tid, scopedVerifier, tenantOK := resolveTenant(w, r)
		if !tenantOK {
			return
		}
		rawSubjectID, authErr := extractVerifiedSubjectIDMultiKey(r, cfg.demoMode, authPrimary, cfg.authSecretPrev, cfg.allowLegacyTokens, guard)
		if authErr || (!cfg.demoMode && rawSubjectID == "") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"accepted": false,
				"error":    "invalid, expired, or revoked bearer token",
			})
			return
		}
		graphSubjectID, okScope := scopeTenantSubjectID(tid, rawSubjectID)
		if !okScope {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"accepted": false,
				"error":    "bearer token tenant mismatch",
			})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var req prismid.IdentifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			metrics.RecordIdentifyRejection("INVALID_JSON", time.Since(startedAt))
			writeJSON(w, http.StatusBadRequest, map[string]any{"accepted": false, "error": "invalid request body"})
			return
		}
		clientIP := resolveClientIP(r)
		transportSig := resolveTransportSignals(r)
		res, err := scopedVerifier.VerifyAndDeriveWithTransport(r.Context(), req, clientIP, transportSig)
		if err != nil {
			status := http.StatusBadRequest
			if vErr, ok := err.(*prismid.VerificationError); ok {
				metrics.RecordIdentifyRejection(vErr.Code, time.Since(startedAt))
				switch vErr.Code {
				case prismid.ErrCodeChallengeInvalid:
					status = http.StatusConflict
				case prismid.ErrCodeTurnstileFailed, prismid.ErrCodeChallengeIPMismatch:
					status = http.StatusForbidden
				}
				writeJSON(w, status, map[string]any{
					"accepted": false,
					"code":     vErr.Code,
					"message":  vErr.Detail,
				})
				return
			}
			metrics.RecordIdentifyRejection("VERIFY_ERROR", time.Since(startedAt))
			writeJSON(w, status, map[string]any{"accepted": false, "message": err.Error()})
			return
		}

		if graphSubjectID != "" {
			ownerRecorded := scopedVerifier.RecordVerifiedBeaconOwner(r.Context(), graphSubjectID, res)
			nowUTC := time.Now().UTC()
			snap := riskGraph.RecordVerification(graphSubjectID, nowUTC, res)
			metrics.RecordIdentifyVerdict(string(snap.RiskStatus), cfg.shadowMode, res.SpoofTrapTriggered, res.DeviceKeyRecoveryRequired, time.Since(startedAt))
			appendWAL(prismid.StateWALRecord{
				Op:            prismid.WALOpIdentify,
				At:            nowUTC,
				SubjectID:     graphSubjectID,
				OwnerRecorded: ownerRecorded,
				VerifyResult:  res,
			}, false)

			effectiveRiskStatus := snap.RiskStatus
			effectiveRiskPending := snap.RiskPending
			resp := map[string]any{
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
				"truncated":                    snap.Truncated,
				"burst_suspicion":              snap.BurstSuspicion,
				"log_odds_score":               snap.LogOddsScore,
				"evidence_chain":               snap.EvidenceChain,
				"component_snapshot":           snap,
			}
			if cfg.shadowMode {
				resp["shadow_mode"] = true
				resp["shadow_risk_status"] = snap.RiskStatus
				resp["shadow_risk_pending"] = snap.RiskPending
				effectiveRiskStatus = prismid.RiskStatusGreen
				effectiveRiskPending = false
			}
			resp["risk_status"] = effectiveRiskStatus
			resp["risk_pending"] = effectiveRiskPending
			writeJSON(w, http.StatusOK, resp)
			return
		}
		metrics.RecordIdentifyVerdict("anonymous", cfg.shadowMode, res.SpoofTrapTriggered, res.DeviceKeyRecoveryRequired, time.Since(startedAt))
		writeJSON(w, http.StatusOK, res)
	})

	// Audited TOFU device-key recovery & rotation endpoint (S1-1, S1-3, S2-10, S2-11, S2-12):
	// Supports two cryptographic authorization paths:
	//  Path A (Loss Recovery): Single-use `step_up_token` bound to `(subject_id, beacon_slice_id)`.
	//  Path B (Key Rotation):  `previous_device_key` ECDSA signature proving possession of the currently bound device key + `<new_pub_key>`.
	mux.HandleFunc("/api/v1/risk/rebind-key", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		tid, scopedVerifier, tenantOK := resolveTenant(w, r)
		if !tenantOK {
			return
		}
		rawSubjectID, authErr := extractVerifiedSubjectIDMultiKey(r, cfg.demoMode, authPrimary, cfg.authSecretPrev, cfg.allowLegacyTokens, guard)
		if authErr || rawSubjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		graphSubjectID, okScope := scopeTenantSubjectID(tid, rawSubjectID)
		if !okScope {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "bearer token tenant mismatch"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var req prismid.KeyRebindRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
			return
		}
		req.SubjectID = rawSubjectID
		req.GraphSubjectID = graphSubjectID
		clientIP := resolveClientIP(r)

		bcnSlice, err := scopedVerifier.DeriveBeaconSliceID(req.BeaconID)
		if err != nil {
			metrics.RecordRebindOutcome("denied")
			scopedVerifier.RecordDeniedRebindAudit(graphSubjectID, "", clientIP, "denied_invalid_beacon")
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"accepted": false,
				"code":     prismid.ErrCodeRebindInvalidKeyProof,
				"error":    err.Error(),
			})
			return
		}

		// Verify ownership FIRST before consuming any single-use step-up token or challenge nonce:
		ownerCheck := scopedVerifier.BeaconOwnerCheck(riskGraph)
		if !ownerCheck(graphSubjectID, bcnSlice) {
			metrics.RecordRebindOutcome("denied")
			scopedVerifier.RecordDeniedRebindAudit(graphSubjectID, bcnSlice, clientIP, "denied_not_owner")
			writeJSON(w, http.StatusForbidden, map[string]any{
				"accepted": false,
				"code":     prismid.ErrCodeRebindForbidden,
				"error":    "beacon is not owned by authenticated subject",
			})
			return
		}

		// Dual-path authorization (S2-10 single-use step-up OR S2-12 5-segment bound previous-key continuity proof):
		authorizedByPrevKey := scopedVerifier.HasValidPreviousKeyProof(r.Context(), req)
		if !authorizedByPrevKey {
			stepUpTok := strings.TrimSpace(req.StepUpToken)
			if stepUpTok == "" {
				stepUpTok = strings.TrimSpace(r.Header.Get("X-PrismID-StepUp-Token"))
			}
			stepUpOK := verifyAndConsumeStepUpToken(stepUpTok, graphSubjectID, bcnSlice, stepUpPrimary, cfg.stepUpSecretPrev, guard, cfg.stateStore)
			if !stepUpOK && graphSubjectID != rawSubjectID {
				// Also accept step-up token minted for rawSubjectID because target `bcnSlice` is already tenant-HMAC-isolated:
				stepUpOK = verifyAndConsumeStepUpToken(stepUpTok, rawSubjectID, bcnSlice, stepUpPrimary, cfg.stepUpSecretPrev, guard, cfg.stateStore)
			}
			if !stepUpOK {
				metrics.RecordRebindOutcome("denied")
				scopedVerifier.RecordDeniedRebindAudit(graphSubjectID, bcnSlice, clientIP, "denied_invalid_stepup")
				writeJSON(w, http.StatusForbidden, map[string]any{
					"accepted": false,
					"code":     prismid.ErrCodeRebindForbidden,
					"error":    "valid single-use step_up_token (or previous_device_key proof) bound to subject_id and beacon_slice_id is required",
				})
				return
			}
		}

		res, err := scopedVerifier.RebindDeviceKeyWithProof(r.Context(), req, ownerCheck, clientIP)
		if err != nil {
			metrics.RecordRebindOutcome("denied")
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
		if authorizedByPrevKey {
			metrics.RecordRebindOutcome("rotation")
		} else {
			metrics.RecordRebindOutcome("step_up")
		}
		appendWAL(prismid.StateWALRecord{
			Op:            prismid.WALOpRebind,
			At:            time.Now().UTC(),
			SubjectID:     graphSubjectID,
			BeaconSliceID: res.BeaconSliceID,
			KeySliceID:    res.DeviceKeySliceID,
		}, true)
		writeJSON(w, http.StatusOK, res)
	})

	// Audited step-up spoof cooldown clearance endpoint (S2-10 single-use + S2-20 audit):
	mux.HandleFunc("/api/v1/risk/clear-spoof", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		tid, scopedVerifier, tenantOK := resolveTenant(w, r)
		if !tenantOK {
			return
		}
		rawSubjectID, authErr := extractVerifiedSubjectIDMultiKey(r, cfg.demoMode, authPrimary, cfg.authSecretPrev, cfg.allowLegacyTokens, guard)
		if authErr || rawSubjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		graphSubjectID, okScope := scopeTenantSubjectID(tid, rawSubjectID)
		if !okScope {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "bearer token tenant mismatch"})
			return
		}
		clientIP := resolveClientIP(r)
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var body struct {
			StepUpToken string `json:"step_up_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		stepUpTok := strings.TrimSpace(body.StepUpToken)
		if stepUpTok == "" {
			stepUpTok = strings.TrimSpace(r.Header.Get("X-PrismID-StepUp-Token"))
		}
		if !verifyAndConsumeStepUpToken(stepUpTok, graphSubjectID, "clear_spoof", stepUpPrimary, cfg.stepUpSecretPrev, guard, cfg.stateStore) {
			metrics.RecordClearSpoof(false)
			scopedVerifier.RecordClearSpoofAudit(graphSubjectID, clientIP, "denied_invalid_stepup")
			writeJSON(w, http.StatusForbidden, map[string]any{
				"accepted": false,
				"error":    "valid single-use step_up_token for clear_spoof is required",
			})
			return
		}
		clearedAt := time.Now().UTC()
		cleared := scopedVerifier.ClearSubjectSpoofAudited(riskGraph, graphSubjectID, clientIP, clearedAt)
		metrics.RecordClearSpoof(true)
		if cleared {
			appendWAL(prismid.StateWALRecord{
				Op:        prismid.WALOpClearSpoof,
				At:        clearedAt,
				SubjectID: graphSubjectID,
			}, true)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"subject_id":         rawSubjectID,
			"cleared":            cleared,
			"component_snapshot": riskGraph.EvaluateSubject(graphSubjectID),
		})
	})

	mux.HandleFunc("/api/v1/risk/explain", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		tid, _, tenantOK := resolveTenant(w, r)
		if !tenantOK {
			return
		}
		rawSubjectID, authErr := extractVerifiedSubjectIDMultiKey(r, cfg.demoMode, authPrimary, cfg.authSecretPrev, cfg.allowLegacyTokens, guard)
		if authErr || rawSubjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		graphSubjectID, okScope := scopeTenantSubjectID(tid, rawSubjectID)
		if !okScope {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "bearer token tenant mismatch"})
			return
		}
		snap := riskGraph.EvaluateSubject(graphSubjectID)
		writeJSON(w, http.StatusOK, snap)
	})

	// Complete GDPR/CCPA erasure endpoint (S2-21): purges graph edges, persistent ownership, AND TOFU bindings.
	mux.HandleFunc("/api/v1/risk/subject", func(w http.ResponseWriter, r *http.Request) {
		enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		tid, scopedVerifier, tenantOK := resolveTenant(w, r)
		if !tenantOK {
			return
		}
		rawSubjectID, authErr := extractVerifiedSubjectIDMultiKey(r, cfg.demoMode, authPrimary, cfg.authSecretPrev, cfg.allowLegacyTokens, guard)
		if authErr || rawSubjectID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "verified subject identity required"})
			return
		}
		graphSubjectID, okScope := scopeTenantSubjectID(tid, rawSubjectID)
		if !okScope {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "bearer token tenant mismatch"})
			return
		}
		removed, purgedBindings := scopedVerifier.EraseSubject(r.Context(), riskGraph, graphSubjectID, resolveClientIP(r))
		if removed || purgedBindings > 0 {
			metrics.RecordSubjectErased()
			appendWAL(prismid.StateWALRecord{
				Op:        prismid.WALOpEraseSubject,
				At:        time.Now().UTC(),
				SubjectID: graphSubjectID,
			}, true)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"subject_id":          rawSubjectID,
			"deleted":             removed,
			"purged_key_bindings": purgedBindings,
		})
	})

	mux.HandleFunc("/api/v1/risk/admin/mint-bearer", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var body struct {
			SubjectID  string `json:"subject_id"`
			TenantID   string `json:"tenant_id"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SubjectID) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_id is required"})
			return
		}
		sid := strings.TrimSpace(body.SubjectID)
		if cfg.enableMultiTenant {
			tid := strings.TrimSpace(body.TenantID)
			if tid == "" {
				tid = strings.TrimSpace(r.Header.Get("X-PrismID-Tenant-ID"))
			}
			if tid != "" {
				if !isValidTenantID(tid) {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid tenant_id"})
					return
				}
				scopedSID, okScope := scopeTenantSubjectID(tid, sid)
				if !okScope {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_id conflicts with tenant_id"})
					return
				}
				sid = scopedSID
			}
		}
		ttl := DefaultBearerTokenTTL
		if body.TTLSeconds > 0 && body.TTLSeconds <= 30*86400 {
			ttl = time.Duration(body.TTLSeconds) * time.Second
		}
		exp := time.Now().UTC().Add(ttl)
		tok := SignSubjectBearerTokenWithExpiry(sid, exp, authPrimary)
		writeJSON(w, http.StatusOK, map[string]any{
			"subject_id": sid,
			"token":      tok,
			"expires_at": exp.Unix(),
		})
	})

	mux.HandleFunc("/api/v1/risk/admin/mint-step-up", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var body struct {
			SubjectID  string `json:"subject_id"`
			TenantID   string `json:"tenant_id"`
			Target     string `json:"target"`
			BeaconID   string `json:"beacon_id"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SubjectID) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_id is required"})
			return
		}
		scopedVerifier := verifier
		sid := strings.TrimSpace(body.SubjectID)
		if cfg.enableMultiTenant {
			tid := strings.TrimSpace(body.TenantID)
			if tid == "" {
				tid = strings.TrimSpace(r.Header.Get("X-PrismID-Tenant-ID"))
			}
			if tid != "" {
				if !isValidTenantID(tid) {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid tenant_id"})
					return
				}
				scopedVerifier = verifier.WithTenant(tid)
				scopedSID, okScope := scopeTenantSubjectID(tid, sid)
				if !okScope {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_id conflicts with tenant_id"})
					return
				}
				sid = scopedSID
			}
		}
		target := strings.TrimSpace(body.Target)
		if target == "" && strings.TrimSpace(body.BeaconID) != "" {
			target = strings.TrimSpace(body.BeaconID)
		}
		if target != "clear_spoof" && !strings.HasPrefix(target, "d_bcn_") {
			derived, err := scopedVerifier.DeriveBeaconSliceID(target)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "target must be 'clear_spoof', a d_bcn_* slice ID, or a 32-char hex beacon_id"})
				return
			}
			target = derived
		}
		ttl := DefaultStepUpTokenTTL
		if body.TTLSeconds > 0 && body.TTLSeconds <= 3600 {
			ttl = time.Duration(body.TTLSeconds) * time.Second
		}
		exp := time.Now().UTC().Add(ttl)
		tok := SignStepUpTokenWithExpiry(sid, target, exp, stepUpPrimary)
		writeJSON(w, http.StatusOK, map[string]any{
			"subject_id":    sid,
			"target":        target,
			"step_up_token": tok,
			"expires_at":    exp.Unix(),
			"single_use":    true,
		})
	})

	mux.HandleFunc("/api/v1/risk/admin/revoke-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		var body struct {
			Token      string `json:"token"`
			SubjectID  string `json:"subject_id"`
			TTLSeconds int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
			return
		}
		ttl := DefaultBearerTokenTTL
		if body.TTLSeconds > 0 && body.TTLSeconds <= 30*86400 {
			ttl = time.Duration(body.TTLSeconds) * time.Second
		}
		until := time.Now().UTC().Add(ttl).Unix()
		var tokSHA string
		if strings.TrimSpace(body.Token) != "" {
			tokSHA = guard.revokeToken(body.Token, until)
		}
		revSub := strings.TrimSpace(body.SubjectID)
		if revSub != "" {
			guard.revokeSubject(revSub, until)
		}
		if tokSHA != "" || revSub != "" {
			appendWAL(prismid.StateWALRecord{
				Op:          prismid.WALOpRevokeToken,
				At:          time.Now().UTC(),
				SubjectID:   revSub,
				TokenSHAHex: tokSHA,
				ExpUnix:     until,
			}, true)
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "until_unix": until})
	})

	mux.HandleFunc("/api/v1/risk/admin/prune-graph", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		prunedAt := time.Now().UTC()
		pruned := riskGraph.PruneExpired(prunedAt)
		if cfg.stateStore != nil {
			if err := cfg.stateStore.Compact(r.Context(), riskGraph, cfg.memStore, guard.exportSnapshot(prunedAt.Unix())); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"pruned_subjects": pruned,
					"error":           "state compaction failed: " + err.Error(),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"pruned_subjects": pruned,
			"stats":           riskGraph.Stats(),
		})
	})

	mux.HandleFunc("/api/v1/risk/admin/flush-state", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		if !requireAdmin(w, r) {
			return
		}
		if cfg.stateStore == nil {
			writeJSON(w, http.StatusOK, map[string]any{"flushed": false, "reason": "no state_file configured"})
			return
		}
		if err := cfg.stateStore.Compact(r.Context(), riskGraph, cfg.memStore, guard.exportSnapshot(time.Now().UTC().Unix())); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"flushed":        false,
				"persist_errors": cfg.stateStore.PersistErrors(),
				"error":          err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"flushed":        true,
			"persist_errors": cfg.stateStore.PersistErrors(),
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		if !cfg.demoMode {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "demo console disabled"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(standaloneIndexHTML))
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodOptions {
			clientIP := resolveClientIP(r)
			if !limiter.allow(clientIP, time.Now()) {
				metrics.RecordHTTP429()
				enableCORS(w, r, cfg.demoMode, cfg.corsOrigin)
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

func canonicalStepUpPayloadV2(subjectID, target, jtiHex, expStr string) []byte {
	// S2-22: Length-prefixed encoding eliminates delimiter ambiguity even when subjectID contains '|' or '.'.
	return []byte(fmt.Sprintf("prismid-stepup-v2|%d:%s|%d:%s|%s|%s", len(subjectID), subjectID, len(target), target, jtiHex, expStr))
}

// SignStepUpTokenWithExpiry creates a short-lived, single-use, length-prefixed HMAC-SHA256 step-up
// token bound to `(subjectID, target)` with a 128-bit random JTI (`stepup_v2.<jti>.<exp>.<hmac>`).
func SignStepUpTokenWithExpiry(subjectID, target string, expiresAt time.Time, secret []byte) string {
	var jtiBytes [16]byte
	_, _ = rand.Read(jtiBytes[:])
	jtiHex := hex.EncodeToString(jtiBytes[:])
	expStr := strconv.FormatInt(expiresAt.UTC().Unix(), 10)
	mac := hmac.New(sha256.New, deriveStepUpAuthKey(secret))
	mac.Write(canonicalStepUpPayloadV2(subjectID, target, jtiHex, expStr))
	return "stepup_v2." + jtiHex + "." + expStr + "." + hex.EncodeToString(mac.Sum(nil))
}

// SignStepUpToken creates a 5-minute (`DefaultStepUpTokenTTL`) single-use step-up token for `(subjectID, target)`.
func SignStepUpToken(subjectID, target string, secret []byte) string {
	return SignStepUpTokenWithExpiry(subjectID, target, time.Now().UTC().Add(DefaultStepUpTokenTTL), secret)
}

func parseAndVerifyStepUpToken(token, expectedSubjectID, expectedTarget string, secret []byte, nowUnix int64) (jti string, expUnix int64, ok bool) {
	trimmed := strings.TrimSpace(token)
	if !strings.HasPrefix(trimmed, "stepup_v2.") || expectedSubjectID == "" || expectedTarget == "" || len(secret) == 0 {
		return "", 0, false
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 4 {
		return "", 0, false
	}
	jtiHex, expStr, sigHex := parts[1], parts[2], parts[3]
	if len(jtiHex) < 16 {
		return "", 0, false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || nowUnix > exp {
		return "", 0, false
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return "", 0, false
	}
	mac := hmac.New(sha256.New, deriveStepUpAuthKey(secret))
	mac.Write(canonicalStepUpPayloadV2(expectedSubjectID, expectedTarget, jtiHex, expStr))
	if !hmac.Equal(sigBytes, mac.Sum(nil)) {
		return "", 0, false
	}
	return jtiHex, exp, true
}

// VerifyStepUpToken validates a step-up token's HMAC signature, expiration, and length-prefixed `(subjectID, target)` binding.
func VerifyStepUpToken(token, expectedSubjectID, expectedTarget string, secret []byte) bool {
	_, _, ok := parseAndVerifyStepUpToken(token, expectedSubjectID, expectedTarget, secret, time.Now().UTC().Unix())
	return ok
}

func verifyAndConsumeStepUpToken(token, expectedSubjectID, expectedTarget string, primarySecret, prevSecret []byte, guard *replayAndRevocationGuard, stateStore *prismid.FileStateStore) bool {
	nowUnix := time.Now().UTC().Unix()
	jti, expUnix, ok := parseAndVerifyStepUpToken(token, expectedSubjectID, expectedTarget, primarySecret, nowUnix)
	if !ok && len(prevSecret) > 0 {
		jti, expUnix, ok = parseAndVerifyStepUpToken(token, expectedSubjectID, expectedTarget, prevSecret, nowUnix)
	}
	if !ok {
		return false
	}
	if guard != nil && !guard.consumeStepUpJTI(jti, expUnix, nowUnix) {
		return false
	}
	if stateStore != nil {
		_ = stateStore.AppendWAL(prismid.StateWALRecord{
			Op:      prismid.WALOpConsumeStepUp,
			At:      time.Unix(nowUnix, 0).UTC(),
			JTI:     jti,
			ExpUnix: expUnix,
		}, true)
	}
	return true
}

func canonicalBearerPayloadV2(subjectID, expStr string) []byte {
	return []byte(fmt.Sprintf("prismid-auth-v2|%d:%s|%s", len(subjectID), subjectID, expStr))
}

// SignSubjectBearerTokenWithExpiry creates an expiring, length-prefixed HMAC-SHA256 bearer token:
// `<subject_id>.<exp_unix_sec>.<hex(HMAC_SHA256)>`.
func SignSubjectBearerTokenWithExpiry(subjectID string, expiresAt time.Time, secret []byte) string {
	expStr := strconv.FormatInt(expiresAt.UTC().Unix(), 10)
	mac := hmac.New(sha256.New, deriveBearerAuthKey(secret))
	mac.Write(canonicalBearerPayloadV2(subjectID, expStr))
	return subjectID + "." + expStr + "." + hex.EncodeToString(mac.Sum(nil))
}

// SignSubjectBearerToken creates an HMAC-SHA256 authenticated bearer token for a subject (24h TTL).
func SignSubjectBearerToken(subjectID string, secret []byte) string {
	return SignSubjectBearerTokenWithExpiry(subjectID, time.Now().UTC().Add(DefaultBearerTokenTTL), secret)
}

func extractVerifiedSubjectID(r *http.Request, demoMode bool, hmacSecret []byte) (string, bool) {
	return extractVerifiedSubjectIDWithLegacy(r, demoMode, hmacSecret, false)
}

func extractVerifiedSubjectIDWithLegacy(r *http.Request, demoMode bool, hmacSecret []byte, allowLegacyTokens bool) (string, bool) {
	return extractVerifiedSubjectIDMultiKey(r, demoMode, hmacSecret, nil, allowLegacyTokens, nil)
}

func verifyBearerV2WithSecret(sid, expStr string, sigBytes, secret []byte) bool {
	if len(secret) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, deriveBearerAuthKey(secret))
	mac.Write(canonicalBearerPayloadV2(sid, expStr))
	return hmac.Equal(sigBytes, mac.Sum(nil))
}

func extractVerifiedSubjectIDMultiKey(r *http.Request, demoMode bool, primarySecret, prevSecret []byte, allowLegacyTokens bool, guard *replayAndRevocationGuard) (string, bool) {
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
	nowUnix := time.Now().UTC().Unix()
	if lastDot := strings.LastIndexByte(rawToken, '.'); lastDot > 0 && lastDot < len(rawToken)-1 {
		prefix := rawToken[:lastDot]
		sigHex := rawToken[lastDot+1:]
		sigBytes, err := hex.DecodeString(sigHex)
		if err == nil {
			if expDot := strings.LastIndexByte(prefix, '.'); expDot > 0 && expDot < len(prefix)-1 {
				sid := prefix[:expDot]
				expStr := prefix[expDot+1:]
				if expUnix, parseErr := strconv.ParseInt(expStr, 10, 64); parseErr == nil {
					if verifyBearerV2WithSecret(sid, expStr, sigBytes, primarySecret) ||
						verifyBearerV2WithSecret(sid, expStr, sigBytes, prevSecret) {
						if nowUnix > expUnix || guard.isRevoked(rawToken, sid, nowUnix) {
							return "", true
						}
						return sid, false
					}
				}
			}
			if allowLegacyTokens {
				mac := hmac.New(sha256.New, deriveBearerAuthKey(primarySecret))
				mac.Write([]byte("prismid-auth|" + prefix))
				if hmac.Equal(sigBytes, mac.Sum(nil)) {
					if guard.isRevoked(rawToken, prefix, nowUnix) {
						return "", true
					}
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
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Forwarded-For, X-PrismID-StepUp-Token, X-PrismID-Admin-Secret, X-PrismID-Tenant-ID")
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
        note: 'Notice that gpu_audio_slice_id (d_gpu_*) remains identical despite new IP & mutated Canvas/Fonts/Screen!',
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
