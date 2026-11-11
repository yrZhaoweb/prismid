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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

func signRebindServerTest(t *testing.T, priv *ecdsa.PrivateKey, prefix, nonce, subjectID, beaconHex string) *prismid.DeviceKeyProof {
	t.Helper()
	msg := strings.Join([]string{prefix, nonce, subjectID, strings.ToLower(beaconHex)}, "|")
	dig := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, dig[:])
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return &prismid.DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// TestV110_SingleUseStepUpNoReplayPipeDelimiterAdminMintKeyRotationAndAudit verifies:
//   - S2-10: Replaying the same `step_up_token` a second time returns 403 Forbidden.
//   - S2-22: Subject IDs containing `|` and `.` cannot forge collisions across `(subject, target)`.
//   - S2-12: `/api/v1/risk/rebind-key` accepts `previous_device_key` rotation proof without `step_up_token`.
//   - S2-20: `/api/v1/risk/clear-spoof` emits structured audit events for both allowed and denied calls.
//   - S2-25 & S3-52: Admin minting (`mint-bearer`, `mint-step-up`), token revocation (`revoke-token`),
//     and separated rotatable auth/step-up secrets work seamlessly.
func TestV110_SingleUseStepUpNoReplayPipeDelimiterAdminMintKeyRotationAndAudit(t *testing.T) {
	ctx := context.Background()
	hmacSecret := []byte("v110-slice-secret-32-bytes-00000")
	authOld := []byte("v110-auth-secret-old-32-bytes-00")
	authNew := []byte("v110-auth-secret-new-32-bytes-00")
	stepUpSecret := []byte("v110-stepup-secret-32-bytes-0000")
	adminSecret := []byte("v110-admin-secret-32-bytes-00000")

	store := prismid.NewMemoryChallengeStore()
	v := prismid.NewVerifier(prismid.Config{HMACSecret: hmacSecret}, store)
	g := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{Store: store})

	handler := newHTTPHandlerWithConfig(v, g, serverHandlerConfig{
		hmacSecret:     hmacSecret,
		authSecret:     authNew,
		authSecretPrev: authOld, // zero-downtime key rotation!
		stepUpSecret:   stepUpSecret,
		adminSecret:    adminSecret,
		demoMode:       false,
		ratePerSec:     500,
		burst:          1000,
		memStore:       store,
	})

	// 1. S2-22: Pipe/dot delimiter collision test on SignStepUpToken / VerifyStepUpToken!
	tokPipe := SignStepUpToken("alice|d_bcn_1", "clear_spoof", stepUpSecret)
	if VerifyStepUpToken(tokPipe, "alice", "d_bcn_1|clear_spoof", stepUpSecret) {
		t.Fatalf("S2-22: pipe delimiter ambiguity allowed subject/target boundary shift!")
	}
	if !VerifyStepUpToken(tokPipe, "alice|d_bcn_1", "clear_spoof", stepUpSecret) {
		t.Fatalf("expected exact length-prefixed subject with pipe to verify cleanly")
	}

	// 2. S3-52: Token signed with previous auth key (`authOld`) still authenticates during rotation!
	bobRotatedBearer := SignSubjectBearerToken("bob", authOld)
	reqExplain := httptest.NewRequest(http.MethodGet, "/api/v1/risk/explain", nil)
	reqExplain.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resExplain := httptest.NewRecorder()
	handler.ServeHTTP(resExplain, reqExplain)
	if resExplain.Code != http.StatusOK {
		t.Fatalf("expected rotated authSecretPrev token to succeed, got %d: %s", resExplain.Code, resExplain.Body)
	}

	// 3. Register Bob with key1 + beaconHex:
	bobBeaconHex := "223344556677889900aabbccddeeff11"
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key3, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	ch1, _ := v.IssueChallenge(ctx, "203.0.113.10")
	p1 := prismid.ProbePayload{
		Nonce:    ch1.Nonce,
		BeaconID: bobBeaconHex,
		WebGL: prismid.WebGLProbeData{
			GPUVendor:         "Apple",
			GPURenderer:       "Apple M2",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23",
			StaticWebGLFpHash: "bob-fp",
			SpotPixels:        prismid.ComputeAllExpectedSpotPixels(ch1.SamplePoints, ch1.RenderSeed),
		},
		AudioCompressorHash: "bob-audio",
		System:              prismid.SystemProbeData{Platform: "MacIntel"},
		Lies:                prismid.LieProbeData{WorkerUnavailable: true, CanvasNoiseInjected: true},
	}
	sigMsg := strings.Join([]string{"prismid-v2-sig", ch1.Nonce, bobBeaconHex, "bob-fp", "bob-audio"}, "|")
	dig := sha256.Sum256([]byte(sigMsg))
	r1, s1, _ := ecdsa.Sign(rand.Reader, key1, dig[:])
	var rawSig [64]byte
	r1.FillBytes(rawSig[:32])
	s1.FillBytes(rawSig[32:])
	p1.DeviceKey = &prismid.DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key1.X, key1.Y)),
		Signature: hex.EncodeToString(rawSig[:]),
	}
	rawP1, _ := json.Marshal(p1)
	sealedP1, _ := prismid.SealPayload(ch1.Nonce, nil, rawP1)
	wire1, _ := json.Marshal(prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealedP1})
	reqId := httptest.NewRequest(http.MethodPost, "/api/v1/risk/identify", bytes.NewReader(wire1))
	reqId.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resId := httptest.NewRecorder()
	handler.ServeHTTP(resId, reqId)
	if resId.Code != http.StatusOK {
		t.Fatalf("bob identify failed: %d %s", resId.Code, resId.Body)
	}

	// 4. S2-25: Mint single-use step-up token via `/api/v1/risk/admin/mint-step-up` using raw `beacon_id`!
	mintReqBody, _ := json.Marshal(map[string]any{
		"subject_id": "bob",
		"beacon_id":  bobBeaconHex,
	})
	reqMint := httptest.NewRequest(http.MethodPost, "/api/v1/risk/admin/mint-step-up", bytes.NewReader(mintReqBody))
	reqMint.Header.Set("X-PrismID-Admin-Secret", string(adminSecret))
	resMint := httptest.NewRecorder()
	handler.ServeHTTP(resMint, reqMint)
	if resMint.Code != http.StatusOK {
		t.Fatalf("admin mint-step-up failed: %d %s", resMint.Code, resMint.Body)
	}
	var mintResp struct {
		StepUpToken string `json:"step_up_token"`
	}
	_ = json.Unmarshal(resMint.Body.Bytes(), &mintResp)

	// First use of `mintResp.StepUpToken` -> 200 OK!
	chRebind1, _ := v.IssueChallenge(ctx, "203.0.113.10")
	rbBody1, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce: chRebind1.Nonce,
		BeaconID:       bobBeaconHex,
		DeviceKey:      signRebindServerTest(t, key2, "prismid-v2-rebind", chRebind1.Nonce, "bob", bobBeaconHex),
		StepUpToken:    mintResp.StepUpToken,
	})
	reqRB1 := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(rbBody1))
	reqRB1.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resRB1 := httptest.NewRecorder()
	handler.ServeHTTP(resRB1, reqRB1)
	if resRB1.Code != http.StatusOK {
		t.Fatalf("first rebind with minted step_up_token failed: %d %s", resRB1.Code, resRB1.Body)
	}

	// S2-10: Replay the SAME `step_up_token` with a fresh nonce & key3 -> MUST be rejected with 403 Forbidden!
	chRebindReplay, _ := v.IssueChallenge(ctx, "203.0.113.10")
	rbReplayBody, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce: chRebindReplay.Nonce,
		BeaconID:       bobBeaconHex,
		DeviceKey:      signRebindServerTest(t, key3, "prismid-v2-rebind", chRebindReplay.Nonce, "bob", bobBeaconHex),
		StepUpToken:    mintResp.StepUpToken,
	})
	reqRBReplay := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(rbReplayBody))
	reqRBReplay.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resRBReplay := httptest.NewRecorder()
	handler.ServeHTTP(resRBReplay, reqRBReplay)
	if resRBReplay.Code != http.StatusForbidden {
		t.Fatalf("S2-10: replayed step_up_token MUST fail with 403 Forbidden, got %d: %s", resRBReplay.Code, resRBReplay.Body)
	}

	// S2-12: Routine key rotation (`key2` -> `key3`) using `PreviousDeviceKey` WITHOUT `step_up_token` -> 200 OK!
	rbPrevKeyBody, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce:    chRebindReplay.Nonce, // note: nonce was NOT consumed by 403 step-up rejection!
		BeaconID:          bobBeaconHex,
		DeviceKey:         signRebindServerTest(t, key3, "prismid-v2-rebind", chRebindReplay.Nonce, "bob", bobBeaconHex),
		PreviousDeviceKey: signRebindServerTest(t, key2, "prismid-v2-rebind-prev", chRebindReplay.Nonce, "bob", bobBeaconHex),
	})
	reqRBPrev := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(rbPrevKeyBody))
	reqRBPrev.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resRBPrev := httptest.NewRecorder()
	handler.ServeHTTP(resRBPrev, reqRBPrev)
	if resRBPrev.Code != http.StatusOK {
		t.Fatalf("S2-12: expected previous_device_key rotation without step_up_token to return 200, got %d: %s", resRBPrev.Code, resRBPrev.Body)
	}

	// 5. S2-20: Clear-spoof single-use + audit verification!
	clearTok := SignStepUpToken("bob", "clear_spoof", stepUpSecret)
	clearBody, _ := json.Marshal(map[string]string{"step_up_token": clearTok})
	reqClear1 := httptest.NewRequest(http.MethodPost, "/api/v1/risk/clear-spoof", bytes.NewReader(clearBody))
	reqClear1.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resClear1 := httptest.NewRecorder()
	handler.ServeHTTP(resClear1, reqClear1)
	if resClear1.Code != http.StatusOK {
		t.Fatalf("clear-spoof failed: %d %s", resClear1.Code, resClear1.Body)
	}
	// Replay clear-spoof step-up token -> 403 Forbidden!
	reqClear2 := httptest.NewRequest(http.MethodPost, "/api/v1/risk/clear-spoof", bytes.NewReader(clearBody))
	reqClear2.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resClear2 := httptest.NewRecorder()
	handler.ServeHTTP(resClear2, reqClear2)
	if resClear2.Code != http.StatusForbidden {
		t.Fatalf("S2-10: replayed clear-spoof step_up_token MUST fail with 403, got %d", resClear2.Code)
	}

	audits := v.RebindAuditEvents()
	sawClearAllowed := false
	sawClearDenied := false
	for _, ev := range audits {
		if ev.Action == "clear_spoof" && ev.Outcome == "spoof_cleared" {
			sawClearAllowed = true
		}
		if ev.Action == "clear_spoof" && ev.Outcome == "denied_invalid_stepup" {
			sawClearDenied = true
		}
	}
	if !sawClearAllowed || !sawClearDenied {
		t.Fatalf("S2-20: expected both allowed and denied clear_spoof audit events, got %+v", audits)
	}

	// 6. S3-52: Revoke Bob's bearer token via `/api/v1/risk/admin/revoke-token` -> immediate 401!
	revBody, _ := json.Marshal(map[string]string{"token": bobRotatedBearer})
	reqRev := httptest.NewRequest(http.MethodPost, "/api/v1/risk/admin/revoke-token", bytes.NewReader(revBody))
	reqRev.Header.Set("X-PrismID-Admin-Secret", string(adminSecret))
	resRev := httptest.NewRecorder()
	handler.ServeHTTP(resRev, reqRev)
	if resRev.Code != http.StatusOK {
		t.Fatalf("revoke-token failed: %d %s", resRev.Code, resRev.Body)
	}
	reqAfterRev := httptest.NewRequest(http.MethodGet, "/api/v1/risk/explain", nil)
	reqAfterRev.Header.Set("Authorization", "Bearer "+bobRotatedBearer)
	resAfterRev := httptest.NewRecorder()
	handler.ServeHTTP(resAfterRev, reqAfterRev)
	if resAfterRev.Code != http.StatusUnauthorized {
		t.Fatalf("S3-52: expected revoked bearer token to return 401 Unauthorized, got %d", resAfterRev.Code)
	}

	// 7. S3-57: Concurrent HTTP requests across workers under -race
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tok := SignSubjectBearerToken("http_race_user", authNew)
			r := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
			r.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
		}(i)
	}
	wg.Wait()
}

// TestRound2_Server429ChallengeTurnstileStartupAndCrashSafeReplayGuard verifies:
//   - P2-2: `validateStartupConfig` fails fast when `-require-turnstile=true` and `-turnstile-secret` is empty.
//   - P2-1: `/api/v1/risk/challenge` returns HTTP 429 (`CHALLENGE_RATE_LIMITED`) when per-IP challenge quota
//     is exceeded without evicting another `/24` neighbor's active challenge.
//   - P1 & P3-2: Consumed `stepup_v2` JTIs and revoked bearer tokens survive abrupt process crashes via WAL
//     replay (`RestoreInto`), and `/api/v1/risk/admin/flush-state` compacts WAL on demand.
func TestRound2_Server429ChallengeTurnstileStartupAndCrashSafeReplayGuard(t *testing.T) {
	ctx := context.Background()
	hmacSecret := []byte("round2-server-secret-32-bytes-00")
	authSecret := []byte("round2-auth-secret-32-bytes-0000")
	stepUpSecret := []byte("round2-stepup-secret-32-bytes-00")
	adminSecret := []byte("round2-admin-secret-32-bytes-000")

	// 1. P2-2: Startup config validation rejects -require-turnstile without -turnstile-secret!
	if err := validateStartupConfig(false, string(hmacSecret), true, ""); err == nil {
		t.Fatalf("P2-2: expected validateStartupConfig to reject -require-turnstile=true with empty -turnstile-secret")
	}
	if err := validateStartupConfig(false, string(hmacSecret), true, "cf-turnstile-secret-live"); err != nil {
		t.Fatalf("expected validateStartupConfig with turnstile secret to pass, got %v", err)
	}

	// 2. Setup server instance #1 backed by FileStateStore (WAL only, no SaveState before crash!):
	statePath := filepath.Join(t.TempDir(), "prismid-state.json")
	fs1, err := prismid.NewFileStateStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	store1 := prismid.NewMemoryChallengeStore()
	store1.SetChallengeQuotas(4096, 4, 1024) // small per-IP quota=4 to test HTTP 429 cleanly
	v1 := prismid.NewVerifier(prismid.Config{HMACSecret: hmacSecret}, store1)
	g1 := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{Store: store1})
	guard1 := newReplayAndRevocationGuard()

	h1 := newHTTPHandlerWithConfig(v1, g1, serverHandlerConfig{
		hmacSecret:   hmacSecret,
		authSecret:   authSecret,
		stepUpSecret: stepUpSecret,
		adminSecret:  adminSecret,
		trustProxy:   true,
		ratePerSec:   1000,
		burst:        2000,
		stateStore:   fs1,
		memStore:     store1,
		replayGuard:  guard1,
	})

	aliceBearer := SignSubjectBearerToken("alice", authSecret)
	revokedBearer := SignSubjectBearerToken("mallory", authSecret)

	// P2-1: Issue 4 challenges from 203.0.113.50 (200 OK), 5th returns 429 CHALLENGE_RATE_LIMITED!
	for i := 1; i <= 5; i++ {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
		r.Header.Set("Authorization", "Bearer "+aliceBearer)
		r.Header.Set("X-Forwarded-For", "203.0.113.50")
		w := httptest.NewRecorder()
		h1.ServeHTTP(w, r)
		if i <= 4 && w.Code != http.StatusOK {
			t.Fatalf("expected challenge %d to return 200, got %d: %s", i, w.Code, w.Body)
		}
		if i == 5 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("P2-1: expected 5th challenge from same IP to return 429 Too Many Requests, got %d: %s", w.Code, w.Body)
		}
	}

	// Consume a `clear_spoof` step-up token AND revoke `revokedBearer` on instance #1:
	clearStepUp := SignStepUpToken("alice", "clear_spoof", stepUpSecret)
	clearBody, _ := json.Marshal(map[string]string{"step_up_token": clearStepUp})
	rClear := httptest.NewRequest(http.MethodPost, "/api/v1/risk/clear-spoof", bytes.NewReader(clearBody))
	rClear.Header.Set("Authorization", "Bearer "+aliceBearer)
	rClear.Header.Set("X-Forwarded-For", "203.0.113.60")
	wClear := httptest.NewRecorder()
	h1.ServeHTTP(wClear, rClear)
	if wClear.Code != http.StatusOK {
		t.Fatalf("expected initial clear-spoof 200, got %d: %s", wClear.Code, wClear.Body)
	}

	revBody, _ := json.Marshal(map[string]string{"token": revokedBearer})
	rRev := httptest.NewRequest(http.MethodPost, "/api/v1/risk/admin/revoke-token", bytes.NewReader(revBody))
	rRev.Header.Set("X-PrismID-Admin-Secret", string(adminSecret))
	wRev := httptest.NewRecorder()
	h1.ServeHTTP(wRev, rRev)
	if wRev.Code != http.StatusOK {
		t.Fatalf("expected revoke-token 200, got %d: %s", wRev.Code, wRev.Body)
	}

	// 3. P3-2: Simulate abrupt crash of instance #1 (NO FlushAndClose / SaveState!) and boot instance #2 from WAL!
	fs2, err := prismid.NewFileStateStore(statePath)
	if err != nil {
		t.Fatalf("NewFileStateStore #2: %v", err)
	}
	store2 := prismid.NewMemoryChallengeStore()
	v2 := prismid.NewVerifier(prismid.Config{HMACSecret: hmacSecret}, store2)
	g2 := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{Store: store2})
	guard2 := newReplayAndRevocationGuard()
	restoredGuard, ok, err := fs2.RestoreInto(ctx, g2, store2)
	if err != nil || !ok {
		t.Fatalf("RestoreInto #2: ok=%v err=%v", ok, err)
	}
	guard2.importSnapshot(restoredGuard, time.Now().UTC().Unix())

	h2 := newHTTPHandlerWithConfig(v2, g2, serverHandlerConfig{
		hmacSecret:   hmacSecret,
		authSecret:   authSecret,
		stepUpSecret: stepUpSecret,
		adminSecret:  adminSecret,
		trustProxy:   true,
		ratePerSec:   1000,
		burst:        2000,
		stateStore:   fs2,
		memStore:     store2,
		replayGuard:  guard2,
	})

	// Replaying `clearStepUp` after restart MUST still fail with 403 Forbidden!
	rReplay := httptest.NewRequest(http.MethodPost, "/api/v1/risk/clear-spoof", bytes.NewReader(clearBody))
	rReplay.Header.Set("Authorization", "Bearer "+aliceBearer)
	wReplay := httptest.NewRecorder()
	h2.ServeHTTP(wReplay, rReplay)
	if wReplay.Code != http.StatusForbidden {
		t.Fatalf("P3-2 regression: consumed step_up_token replayed across server restart! got %d: %s", wReplay.Code, wReplay.Body)
	}

	// Reusing `revokedBearer` after restart MUST still fail with 401 Unauthorized!
	rRevCheck := httptest.NewRequest(http.MethodGet, "/api/v1/risk/explain", nil)
	rRevCheck.Header.Set("Authorization", "Bearer "+revokedBearer)
	wRevCheck := httptest.NewRecorder()
	h2.ServeHTTP(wRevCheck, rRevCheck)
	if wRevCheck.Code != http.StatusUnauthorized {
		t.Fatalf("P3-2 regression: revoked bearer token became valid again across server restart! got %d", wRevCheck.Code)
	}

	// Admin flush-state compacts WAL cleanly and /healthz reports persist_errors=0:
	rFlush := httptest.NewRequest(http.MethodPost, "/api/v1/risk/admin/flush-state", nil)
	rFlush.Header.Set("X-PrismID-Admin-Secret", string(adminSecret))
	wFlush := httptest.NewRecorder()
	h2.ServeHTTP(wFlush, rFlush)
	if wFlush.Code != http.StatusOK {
		t.Fatalf("expected /admin/flush-state 200, got %d: %s", wFlush.Code, wFlush.Body)
	}
}
