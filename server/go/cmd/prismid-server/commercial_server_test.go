package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

func buildSignedIdentifyWire(
	t *testing.T,
	ch *prismid.Challenge,
	beaconHex string,
	priv *ecdsa.PrivateKey,
	userAgent string,
) []byte {
	t.Helper()
	avail := true
	p := prismid.ProbePayload{
		Nonce:    ch.Nonce,
		BeaconID: beaconHex,
		WebGL: prismid.WebGLProbeData{
			WebGLAvailable:    &avail,
			GPUVendor:         "Apple",
			GPURenderer:       "Apple M3 Pro",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23",
			StaticWebGLFpHash: "m3pro-static-hash",
			SpotPixels:        prismid.ComputeAllExpectedSpotPixels(ch.SamplePoints, ch.RenderSeed),
		},
		AudioCompressorHash: "m3pro-audio-hash",
		AudioCopyHash:       "m3pro-audio-hash",
		System: prismid.SystemProbeData{
			UserAgent:         userAgent,
			Platform:          "MacIntel",
			CPUCores:          12,
			DeviceMemory:      8,
			CanvasControlRGBA: []int{0, 0, 0, 0, 17, 136, 221, 255},
		},
		Lies: prismid.LieProbeData{
			WorkerUnavailable:   true,
			MathEngineSignature: "v8",
		},
	}
	sigMsg := strings.Join([]string{"prismid-v2-sig", ch.Nonce, beaconHex, "m3pro-static-hash", "m3pro-audio-hash"}, "|")
	dig := sha256.Sum256([]byte(sigMsg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, dig[:])
	if err != nil {
		t.Fatal(err)
	}
	var rawSig [64]byte
	r.FillBytes(rawSig[:32])
	s.FillBytes(rawSig[32:])
	p.DeviceKey = &prismid.DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)),
		Signature: hex.EncodeToString(rawSig[:]),
	}
	rawPayload, _ := json.Marshal(p)
	sealed, err := prismid.SealPayload(ch.Nonce, nil, rawPayload)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(prismid.IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealed})
	return wire
}

func TestCommercialServer_TrustedProxyJA4ShadowModeMultiTenantAndMetrics(t *testing.T) {
	hmacSecret := []byte("commercial-server-hmac-32-bytes!")
	authSecret := []byte("commercial-server-auth-32-bytes!")
	stepUpSecret := []byte("commercial-server-stepup-32-byte")
	adminSecret := []byte("commercial-server-admin-32-bytes")

	trustedChecker, err := prismid.ParseTrustedProxyCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxyCIDRs: %v", err)
	}

	store := prismid.NewMemoryChallengeStore()
	v := prismid.NewVerifier(prismid.Config{HMACSecret: hmacSecret}, store)
	g := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{Store: store})
	metrics := prismid.NewMetrics()

	handler := newHTTPHandlerWithConfig(v, g, serverHandlerConfig{
		hmacSecret:        hmacSecret,
		authSecret:        authSecret,
		stepUpSecret:      stepUpSecret,
		adminSecret:       adminSecret,
		trustedProxies:    trustedChecker,
		shadowMode:        true,
		enableMultiTenant: true,
		metricsPublic:     false,
		ratePerSec:        1000,
		burst:             2000,
		memStore:          store,
		metrics:           metrics,
	})

	chromeUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	aliceTok := SignSubjectBearerToken("alice", authSecret)
	bcnHex := "11223344556677889900aabbccddeeff"
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	issueChallengeHTTP := func(tenantID, remoteAddr, xff string) *prismid.Challenge {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("Authorization", "Bearer "+aliceTok)
		if tenantID != "" {
			req.Header.Set("X-PrismID-Tenant-ID", tenantID)
		}
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("challenge failed: %d %s", rec.Code, rec.Body.String())
		}
		var ch prismid.Challenge
		if err := json.Unmarshal(rec.Body.Bytes(), &ch); err != nil {
			t.Fatal(err)
		}
		return &ch
	}

	// 1. Invalid X-PrismID-Tenant-ID is rejected with 400 Bad Request:
	badTenantReq := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
	badTenantReq.Header.Set("Authorization", "Bearer "+aliceTok)
	badTenantReq.Header.Set("X-PrismID-Tenant-ID", "evil/tenant;drop")
	badTenantRec := httptest.NewRecorder()
	handler.ServeHTTP(badTenantRec, badTenantReq)
	if badTenantRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid tenant ID, got %d", badTenantRec.Code)
	}

	// 2. Untrusted direct peer (`198.51.100.200:54321`) tries to forge X-Forwarded-For AND X-TLS-JA4:
	//    Both forged headers MUST be ignored!
	chAcme := issueChallengeHTTP("acme", "198.51.100.200:54321", "8.8.8.8")
	wireAcme := buildSignedIdentifyWire(t, chAcme, bcnHex, key1, chromeUA)
	idUntrustedReq := httptest.NewRequest(http.MethodPost, "/api/v1/risk/identify", bytes.NewReader(wireAcme))
	idUntrustedReq.RemoteAddr = "198.51.100.200:54321"
	idUntrustedReq.Header.Set("Authorization", "Bearer "+aliceTok)
	idUntrustedReq.Header.Set("X-PrismID-Tenant-ID", "acme")
	idUntrustedReq.Header.Set("X-Forwarded-For", "8.8.8.8")
	idUntrustedReq.Header.Set("X-TLS-JA4", "t12d040300_forged_ja4_123456")
	idUntrustedRec := httptest.NewRecorder()
	handler.ServeHTTP(idUntrustedRec, idUntrustedReq)
	if idUntrustedRec.Code != http.StatusOK {
		t.Fatalf("acme identify failed: %d %s", idUntrustedRec.Code, idUntrustedRec.Body.String())
	}
	var acmeResp map[string]any
	_ = json.Unmarshal(idUntrustedRec.Body.Bytes(), &acmeResp)
	if acmeResp["ip_subnet"] != "198.51.100.0/24" {
		t.Fatalf("untrusted peer forged XFF! got ip_subnet=%v", acmeResp["ip_subnet"])
	}
	if acmeResp["spoof_trap_triggered"] != false {
		t.Fatalf("untrusted peer forged X-TLS-JA4! got spoof_trap_triggered=%v", acmeResp["spoof_trap_triggered"])
	}

	// 3. Trusted ingress (`10.0.1.9:443`) forwards `X-Forwarded-For: 1.1.1.1, 203.0.113.77, 10.0.1.2`
	//    and `X-TLS-JA4: t12d040300_aabbccddeeff_112233445566` (Python TLS 1.2 spoofing Chrome 126) under tenant `globex`:
	//    - Right-to-left hop strip extracts `203.0.113.77` (`203.0.113.0/24`), ignoring client-prepended `1.1.1.1`!
	//    - Multi-tenant isolation produces a DIFFERENT `beacon_slice_id` from `acme`!
	//    - Shadow Mode computes `shadow_risk_status == "red"` while returning `risk_status == "green"`!
	chGlobex := issueChallengeHTTP("globex", "10.0.1.9:443", "1.1.1.1, 203.0.113.77, 10.0.1.2")
	wireGlobex := buildSignedIdentifyWire(t, chGlobex, bcnHex, key1, chromeUA)
	idTrustedReq := httptest.NewRequest(http.MethodPost, "/api/v1/risk/identify", bytes.NewReader(wireGlobex))
	idTrustedReq.RemoteAddr = "10.0.1.9:443"
	idTrustedReq.Header.Set("Authorization", "Bearer "+aliceTok)
	idTrustedReq.Header.Set("X-PrismID-Tenant-ID", "globex")
	idTrustedReq.Header.Set("X-Forwarded-For", "1.1.1.1, 203.0.113.77, 10.0.1.2")
	idTrustedReq.Header.Set("X-TLS-JA4", "t12d040300_aabbccddeeff_112233445566")
	idTrustedRec := httptest.NewRecorder()
	handler.ServeHTTP(idTrustedRec, idTrustedReq)
	if idTrustedRec.Code != http.StatusOK {
		t.Fatalf("globex identify failed: %d %s", idTrustedRec.Code, idTrustedRec.Body.String())
	}
	var globexResp map[string]any
	_ = json.Unmarshal(idTrustedRec.Body.Bytes(), &globexResp)
	if globexResp["ip_subnet"] != "203.0.113.0/24" {
		t.Fatalf("expected right-to-left XFF extraction 203.0.113.0/24, got %v", globexResp["ip_subnet"])
	}
	if globexResp["beacon_slice_id"] == acmeResp["beacon_slice_id"] {
		t.Fatalf("multi-tenant isolation failed: acme and globex derived identical beacon_slice_id %v", globexResp["beacon_slice_id"])
	}
	if globexResp["spoof_trap_triggered"] != true ||
		globexResp["shadow_mode"] != true ||
		globexResp["shadow_risk_status"] != "red" ||
		globexResp["risk_status"] != "green" ||
		globexResp["risk_pending"] != false {
		t.Fatalf("expected shadow mode to expose shadow_risk_status=red while returning risk_status=green, got %+v", globexResp)
	}

	// 4. Multi-tenant 5-segment bound key rotation (`key1` -> `key2`) inside tenant `acme`:
	chRot := issueChallengeHTTP("acme", "198.51.100.200:54321", "")
	newProof := signRebindServerTest(t, key2, "prismid-v2-rebind", chRot.Nonce, "alice", bcnHex)
	prevProof := signRebindServerTest(t, key1, "prismid-v2-rebind-prev", chRot.Nonce, "alice", bcnHex, newProof.PubKey)
	rbBody, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce:    chRot.Nonce,
		BeaconID:          bcnHex,
		DeviceKey:         newProof,
		PreviousDeviceKey: prevProof,
	})
	rbReq := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(rbBody))
	rbReq.RemoteAddr = "198.51.100.200:54321"
	rbReq.Header.Set("Authorization", "Bearer "+aliceTok)
	rbReq.Header.Set("X-PrismID-Tenant-ID", "acme")
	rbRec := httptest.NewRecorder()
	handler.ServeHTTP(rbRec, rbReq)
	if rbRec.Code != http.StatusOK {
		t.Fatalf("tenant acme key rotation failed: %d %s", rbRec.Code, rbRec.Body.String())
	}

	// Cross-tenant bearer token mismatch (`t:acme:alice` sent with `X-PrismID-Tenant-ID: globex`) -> 403 Forbidden!
	explicitAcmeTok := SignSubjectBearerToken("t:acme:alice", authSecret)
	crossReq := httptest.NewRequest(http.MethodGet, "/api/v1/risk/explain", nil)
	crossReq.Header.Set("Authorization", "Bearer "+explicitAcmeTok)
	crossReq.Header.Set("X-PrismID-Tenant-ID", "globex")
	crossRec := httptest.NewRecorder()
	handler.ServeHTTP(crossRec, crossReq)
	if crossRec.Code != http.StatusForbidden {
		t.Fatalf("expected cross-tenant explicit token to be rejected with 403, got %d", crossRec.Code)
	}

	// 5. Prometheus `/metrics`: requires admin secret when `metricsPublic=false`, and renders counters!
	unauthMetricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	unauthMetricsRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthMetricsRec, unauthMetricsReq)
	if unauthMetricsRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated /metrics to return 401, got %d", unauthMetricsRec.Code)
	}

	authMetricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	authMetricsReq.Header.Set("X-PrismID-Admin-Secret", string(adminSecret))
	authMetricsRec := httptest.NewRecorder()
	handler.ServeHTTP(authMetricsRec, authMetricsReq)
	if authMetricsRec.Code != http.StatusOK {
		t.Fatalf("authenticated /metrics failed: %d", authMetricsRec.Code)
	}
	promOut := authMetricsRec.Body.String()
	for _, want := range []string{
		`prismid_identify_verdicts_total{risk_status="green",shadow="true"} 1`,
		`prismid_identify_verdicts_total{risk_status="red",shadow="true"} 1`,
		`prismid_rebind_requests_total{mode="rotation"} 1`,
		"prismid_spoof_traps_triggered_total 1",
	} {
		if !strings.Contains(promOut, want) {
			t.Fatalf("expected /metrics to contain %q, got:\n%s", want, promOut)
		}
	}
}

type mockDistributedGuard struct {
	mu      sync.Mutex
	jtis    map[string]int64
	tokSHAs map[string]int64
	subs    map[string]int64
}

func newMockDistributedGuard() *mockDistributedGuard {
	return &mockDistributedGuard{
		jtis:    make(map[string]int64),
		tokSHAs: make(map[string]int64),
		subs:    make(map[string]int64),
	}
}

func (m *mockDistributedGuard) ConsumeStepUpJTI(_ context.Context, jti string, expUnix, nowUnix int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.jtis[jti]; ok && nowUnix <= exp {
		return false, nil
	}
	m.jtis[jti] = expUnix
	return true, nil
}

func (m *mockDistributedGuard) RevokeTokenHash(_ context.Context, tokenSHAHex string, untilUnix, _ int64) error {
	m.mu.Lock()
	m.tokSHAs[tokenSHAHex] = untilUnix
	m.mu.Unlock()
	return nil
}

func (m *mockDistributedGuard) RevokeSubject(_ context.Context, subjectID string, untilUnix, _ int64) error {
	m.mu.Lock()
	m.subs[subjectID] = untilUnix
	m.mu.Unlock()
	return nil
}

func (m *mockDistributedGuard) IsRevoked(_ context.Context, tokenSHAHex, subjectID string, nowUnix int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.tokSHAs[tokenSHAHex]; ok && nowUnix <= exp {
		return true, nil
	}
	if exp, ok := m.subs[subjectID]; ok && nowUnix <= exp {
		return true, nil
	}
	return false, nil
}

func TestCommercialServer_LoadBalancedDistributedReplayAndRevocation(t *testing.T) {
	hmacSecret := []byte("lb-cluster-hmac-secret-32-bytes!")
	authSecret := []byte("lb-cluster-auth-secret-32-bytes!")
	stepUpSecret := []byte("lb-cluster-stepup-secret-32-byte")
	adminSecret := []byte("lb-cluster-admin-secret-32-bytes")

	sharedDist := newMockDistributedGuard()

	makeReplica := func() http.Handler {
		st := prismid.NewMemoryChallengeStore()
		v := prismid.NewVerifier(prismid.Config{HMACSecret: hmacSecret}, st)
		g := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{Store: st})
		rg := newReplayAndRevocationGuard()
		rg.attachDistributed(sharedDist)
		return newHTTPHandlerWithConfig(v, g, serverHandlerConfig{
			hmacSecret:   hmacSecret,
			authSecret:   authSecret,
			stepUpSecret: stepUpSecret,
			adminSecret:  adminSecret,
			ratePerSec:   1000,
			burst:        2000,
			memStore:     st,
			replayGuard:  rg,
		})
	}

	node1 := makeReplica()
	node2 := makeReplica()

	bobTok := SignSubjectBearerToken("bob", authSecret)
	clearTok := SignStepUpToken("bob", "clear_spoof", stepUpSecret)
	clearBody, _ := json.Marshal(map[string]string{"step_up_token": clearTok})

	// 1. Consume `clearTok` on Node 1 -> 200 OK; replay on Node 2 -> 403 Forbidden!
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/risk/clear-spoof", bytes.NewReader(clearBody))
	r1.Header.Set("Authorization", "Bearer "+bobTok)
	w1 := httptest.NewRecorder()
	node1.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected Node 1 clear-spoof 200, got %d: %s", w1.Code, w1.Body.String())
	}

	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/risk/clear-spoof", bytes.NewReader(clearBody))
	r2.Header.Set("Authorization", "Bearer "+bobTok)
	w2 := httptest.NewRecorder()
	node2.ServeHTTP(w2, r2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected cross-replica step-up token replay on Node 2 to return 403, got %d", w2.Code)
	}

	// 2. Revoke `bobTok` on Node 1 -> immediate 401 Unauthorized on Node 2!
	revBody, _ := json.Marshal(map[string]string{"token": bobTok})
	rRev := httptest.NewRequest(http.MethodPost, "/api/v1/risk/admin/revoke-token", bytes.NewReader(revBody))
	rRev.Header.Set("X-PrismID-Admin-Secret", string(adminSecret))
	wRev := httptest.NewRecorder()
	node1.ServeHTTP(wRev, rRev)
	if wRev.Code != http.StatusOK {
		t.Fatalf("Node 1 revoke-token failed: %d", wRev.Code)
	}

	rExplain2 := httptest.NewRequest(http.MethodGet, "/api/v1/risk/explain", nil)
	rExplain2.Header.Set("Authorization", "Bearer "+bobTok)
	wExplain2 := httptest.NewRecorder()
	node2.ServeHTTP(wExplain2, rExplain2)
	if wExplain2.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked token to return 401 on Node 2 immediately, got %d", wExplain2.Code)
	}
}
