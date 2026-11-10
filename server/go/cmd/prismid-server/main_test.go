package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

// TestRereview_R4_BearerAuthenticationInNonDemoMode verifies GPT v0.4.0 Re-Review Finding R4:
//   - When demoMode=false, ?subject_id= is ignored.
//   - When demoMode=false, an unverified `Authorization: Bearer chosen-victim` is rejected (authErr=true -> 401).
//   - When demoMode=false, an HMAC-signed `Authorization: Bearer <sid>.<hmac_hex>` succeeds.
func TestRereview_R4_BearerAuthenticationInNonDemoMode(t *testing.T) {
	secret := []byte("production-hmac-secret-32-bytes-00")

	// 1. Unverified Bearer string in demoMode=false MUST fail with authErr=true:
	reqForged := httptest.NewRequest("POST", "/api/v1/risk/identify?subject_id=query-victim", nil)
	reqForged.Header.Set("Authorization", "Bearer chosen-victim")
	sid, authErr := extractVerifiedSubjectID(reqForged, false, secret)
	if !authErr || sid != "" {
		t.Fatalf("expected unverified Bearer in demoMode=false to fail with authErr=true, got sid=%q authErr=%v", sid, authErr)
	}

	// 2. Query string alone in demoMode=false is ignored (stateless mode, authErr=false, sid=""):
	reqQueryOnly := httptest.NewRequest("POST", "/api/v1/risk/identify?subject_id=query-victim", nil)
	sid, authErr = extractVerifiedSubjectID(reqQueryOnly, false, secret)
	if authErr || sid != "" {
		t.Fatalf("expected query-only request in demoMode=false to ignore subject_id without authErr, got sid=%q authErr=%v", sid, authErr)
	}

	// 3. Properly HMAC-signed Bearer token in demoMode=false succeeds:
	signedToken := SignSubjectBearerToken("verified_user_42", secret)
	reqSigned := httptest.NewRequest("POST", "/api/v1/risk/identify", nil)
	reqSigned.Header.Set("Authorization", "Bearer "+signedToken)
	sid, authErr = extractVerifiedSubjectID(reqSigned, false, secret)
	if authErr || sid != "verified_user_42" {
		t.Fatalf("expected signed Bearer token to authenticate verified_user_42, got sid=%q authErr=%v", sid, authErr)
	}
}

func TestReviewFix_UnauthorizedIdentifyCannotConsumeOrBind(t *testing.T) {
	ctx := context.Background()
	secret := []byte("review-auth-state-secret")
	store := prismid.NewMemoryChallengeStore()
	v := prismid.NewVerifier(prismid.Config{HMACSecret: secret}, store)
	g := prismid.NewRiskGraph(.6)
	handler := newHTTPHandler(v, g, secret, false, false, "")
	ch, err := v.IssueChallenge(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := prismid.ProbePayload{Nonce: ch.Nonce, BeaconID: "1234567890abcdef1234567890abcdef",
		WebGL: prismid.WebGLProbeData{GPUVendor: "Apple", GPURenderer: "Apple M1 Pro",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23",
			StaticWebGLFpHash: "review", SpotPixels: prismid.ComputeAllExpectedSpotPixels(ch.SamplePoints, ch.RenderSeed)},
		AudioCompressorHash: "review-audio", System: prismid.SystemProbeData{Platform: "MacIntel"},
		Lies: prismid.LieProbeData{WorkerUnavailable: true}}
	transcript := strings.Join([]string{"prismid-v2-sig", ch.Nonce, payload.BeaconID, "review", "review-audio"}, "|")
	digest := sha256.Sum256([]byte(transcript))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	payload.DeviceKey = &prismid.DeviceKeyProof{Alg: "ecdsa-p256",
		PubKey: hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)), Signature: hex.EncodeToString(sig)}
	raw, _ := json.Marshal(payload)
	sealed, err := prismid.SealPayload(ch.Nonce, nil, raw)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(prismid.IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealed})
	for _, auth := range []string{"Bearer invalid-token", ""} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/risk/identify", bytes.NewReader(wire))
		req.Header.Set("Authorization", auth)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: status=%d body=%s", auth, res.Code, res.Body)
		}
	}
	// A read without a key is accepted only while this beacon is still unbound.
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("bcn|" + payload.BeaconID))
	beaconSlice := "d_bcn_" + hex.EncodeToString(mac.Sum(nil)[:16])
	if unbound, err := store.CheckOrBindBeaconDeviceKey(ctx, beaconSlice, ""); err != nil || !unbound {
		t.Fatalf("401 wrote a device-key binding: unbound=%v err=%v", unbound, err)
	}
	// Using the same nonce with valid authentication must still succeed (not 409).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/risk/identify", bytes.NewReader(wire))
	req.Header.Set("Authorization", "Bearer "+SignSubjectBearerToken("owner", secret))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("401 consumed nonce: %d %s", res.Code, res.Body)
	}
	var body struct {
		DeviceKeyAttested bool   `json:"device_key_attested"`
		RiskStatus        string `json:"risk_status"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.DeviceKeyAttested || body.RiskStatus != prismid.RiskStatusGreen {
		t.Fatalf("unexpected valid result: %s", res.Body)
	}
	for _, auth := range []string{"Bearer invalid-token", ""} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
		req.Header.Set("Authorization", auth)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated challenge status=%d", res.Code)
		}
	}
}

func TestV101_ExpiringBearerTokenRebindKeyAndRateLimit(t *testing.T) {
	ctx := context.Background()
	secret := []byte("v101-server-test-secret-32-bytes")
	store := prismid.NewMemoryChallengeStore()
	v := prismid.NewVerifier(prismid.Config{HMACSecret: secret}, store)
	g := prismid.NewRiskGraph(0.6)
	handler := newHTTPHandlerWithRateLimit(v, g, secret, false, false, "", 1, 3)

	// 1a. Legacy non-expiring static HMAC token (<subject_id>.<hmac>) MUST be rejected with 401 by default (DeepSeek v1.0.1 P2 #5)
	legacyMac := hmac.New(sha256.New, deriveBearerAuthKey(secret))
	legacyMac.Write([]byte("prismid-auth|alice"))
	legacyTok := "alice." + hex.EncodeToString(legacyMac.Sum(nil))
	reqLegacy := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
	reqLegacy.RemoteAddr = "198.51.100.11:12345"
	reqLegacy.Header.Set("Authorization", "Bearer "+legacyTok)
	resLegacy := httptest.NewRecorder()
	handler.ServeHTTP(resLegacy, reqLegacy)
	if resLegacy.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for deprecated static Bearer token, got %d: %s", resLegacy.Code, resLegacy.Body)
	}

	// 1b. Expired v2 Bearer token MUST be rejected with 401
	expiredTok := SignSubjectBearerTokenWithExpiry("alice", time.Now().UTC().Add(-1*time.Minute), secret)
	reqExp := httptest.NewRequest(http.MethodPost, "/api/v1/risk/challenge", nil)
	reqExp.RemoteAddr = "198.51.100.12:12345"
	reqExp.Header.Set("Authorization", "Bearer "+expiredTok)
	resExp := httptest.NewRecorder()
	handler.ServeHTTP(resExp, reqExp)
	if resExp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired Bearer token, got %d: %s", resExp.Code, resExp.Body)
	}

	// 2. Hardened POST /api/v1/risk/rebind-key (DeepSeek v1.0.1 P1 #1):
	// First register Bob cleanly with keyBob1 and raw beacon bobBeaconHex so Bob owns bobBeaconSlice in the graph.
	bobBeaconHex := "11223344556677889900aabbccddeeff"
	keyBob1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyBob2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyAlice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	chBob1, _ := v.IssueChallenge(ctx, "203.0.113.20")
	bobPayload1 := prismid.ProbePayload{
		Nonce:    chBob1.Nonce,
		BeaconID: bobBeaconHex,
		WebGL: prismid.WebGLProbeData{
			GPUVendor:         "Apple",
			GPURenderer:       "Apple M2",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23",
			StaticWebGLFpHash: "bob-fp",
			SpotPixels:        prismid.ComputeAllExpectedSpotPixels(chBob1.SamplePoints, chBob1.RenderSeed),
		},
		AudioCompressorHash: "bob-audio",
		System:              prismid.SystemProbeData{Platform: "MacIntel"},
		Lies:                prismid.LieProbeData{WorkerUnavailable: true},
	}
	sigTranscript1 := strings.Join([]string{"prismid-v2-sig", chBob1.Nonce, bobBeaconHex, "bob-fp", "bob-audio"}, "|")
	dig1 := sha256.Sum256([]byte(sigTranscript1))
	r1, s1, _ := ecdsa.Sign(rand.Reader, keyBob1, dig1[:])
	var rawSig1 [64]byte
	r1.FillBytes(rawSig1[:32])
	s1.FillBytes(rawSig1[32:])
	bobPayload1.DeviceKey = &prismid.DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), keyBob1.X, keyBob1.Y)),
		Signature: hex.EncodeToString(rawSig1[:]),
	}
	rawBob1, _ := json.Marshal(bobPayload1)
	sealedBob1, _ := prismid.SealPayload(chBob1.Nonce, nil, rawBob1)
	wireBob1, _ := json.Marshal(prismid.IdentifyRequest{ChallengeNonce: chBob1.Nonce, SealedPayload: sealedBob1})
	bobTok := SignSubjectBearerToken("bob", secret)
	reqBobId := httptest.NewRequest(http.MethodPost, "/api/v1/risk/identify", bytes.NewReader(wireBob1))
	reqBobId.RemoteAddr = "203.0.113.20:5000"
	reqBobId.Header.Set("Authorization", "Bearer "+bobTok)
	resBobId := httptest.NewRecorder()
	handler.ServeHTTP(resBobId, reqBobId)
	if resBobId.Code != http.StatusOK {
		t.Fatalf("bob initial identify failed: %d %s", resBobId.Code, resBobId.Body)
	}
	bobBeaconSlice, _ := v.DeriveBeaconSliceID(bobBeaconHex)

	signRebindHTTP := func(priv *ecdsa.PrivateKey, nonce, subjectID, beaconHex string) *prismid.DeviceKeyProof {
		msg := strings.Join([]string{"prismid-v2-rebind", nonce, subjectID, strings.ToLower(beaconHex)}, "|")
		dig := sha256.Sum256([]byte(msg))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, dig[:])
		var sig [64]byte
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return &prismid.DeviceKeyProof{
			Alg:       "ecdsa-p256",
			PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)),
			Signature: hex.EncodeToString(sig[:]),
		}
	}

	// 2a. Cross-account attack: Alice's bearer token + Bob's beacon MUST be rejected with 403 Forbidden
	// (even if Alice somehow holds a step-up token for her own subject) and MUST NOT leak previous_device_key_slice_id!
	chAtk, _ := v.IssueChallenge(ctx, "198.51.100.50")
	aliceTok := SignSubjectBearerToken("alice", secret)
	aliceStepUp := SignStepUpToken("alice", bobBeaconSlice, secret)
	atkBody, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce: chAtk.Nonce,
		BeaconID:       bobBeaconHex,
		DeviceKey:      signRebindHTTP(keyAlice, chAtk.Nonce, "alice", bobBeaconHex),
		StepUpToken:    aliceStepUp,
	})
	reqAtk := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(atkBody))
	reqAtk.RemoteAddr = "198.51.100.50:9999"
	reqAtk.Header.Set("Authorization", "Bearer "+aliceTok)
	resAtk := httptest.NewRecorder()
	handler.ServeHTTP(resAtk, reqAtk)
	if resAtk.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when alice attempts to rebind bob's beacon, got %d: %s", resAtk.Code, resAtk.Body)
	}
	if strings.Contains(resAtk.Body.String(), "previous_device_key_slice_id") {
		t.Fatalf("rebind response leaked previous_device_key_slice_id: %s", resAtk.Body.String())
	}

	// 2b. Owner (Bob) WITHOUT step_up_token -> 403 Forbidden (and chRebindBob nonce is NOT consumed!)
	chRebindBob, _ := v.IssueChallenge(ctx, "203.0.113.21")
	noStepBody, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce: chRebindBob.Nonce,
		BeaconID:       bobBeaconHex,
		DeviceKey:      signRebindHTTP(keyBob2, chRebindBob.Nonce, "bob", bobBeaconHex),
	})
	reqNoStep := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(noStepBody))
	reqNoStep.RemoteAddr = "203.0.113.21:5001"
	reqNoStep.Header.Set("Authorization", "Bearer "+bobTok)
	resNoStep := httptest.NewRecorder()
	handler.ServeHTTP(resNoStep, reqNoStep)
	if resNoStep.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden without step_up_token, got %d: %s", resNoStep.Code, resNoStep.Body)
	}

	// 2c. Owner (Bob) WITH valid step_up_token + challenge_nonce + ECDSA P-256 PoP -> 200 OK!
	bobStepUp := SignStepUpToken("bob", bobBeaconSlice, secret)
	validRebindBody, _ := json.Marshal(prismid.KeyRebindRequest{
		ChallengeNonce: chRebindBob.Nonce,
		BeaconID:       bobBeaconHex,
		DeviceKey:      signRebindHTTP(keyBob2, chRebindBob.Nonce, "bob", bobBeaconHex),
		StepUpToken:    bobStepUp,
	})
	reqValidRebind := httptest.NewRequest(http.MethodPost, "/api/v1/risk/rebind-key", bytes.NewReader(validRebindBody))
	reqValidRebind.RemoteAddr = "203.0.113.21:5001"
	reqValidRebind.Header.Set("Authorization", "Bearer "+bobTok)
	resValidRebind := httptest.NewRecorder()
	handler.ServeHTTP(resValidRebind, reqValidRebind)
	if resValidRebind.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on owner step-up + PoP rebind, got %d: %s", resValidRebind.Code, resValidRebind.Body)
	}
	if strings.Contains(resValidRebind.Body.String(), "previous_device_key_slice_id") {
		t.Fatalf("200 rebind response must not expose previous_device_key_slice_id: %s", resValidRebind.Body.String())
	}

	// 2d. GDPR DELETE /api/v1/risk/subject purges BOTH graph edges AND TOFU key binding
	reqDelBob := httptest.NewRequest(http.MethodDelete, "/api/v1/risk/subject", nil)
	reqDelBob.RemoteAddr = "203.0.113.22:5002"
	reqDelBob.Header.Set("Authorization", "Bearer "+bobTok)
	resDelBob := httptest.NewRecorder()
	handler.ServeHTTP(resDelBob, reqDelBob)
	if resDelBob.Code != http.StatusOK || !strings.Contains(resDelBob.Body.String(), `"purged_key_bindings":1`) {
		t.Fatalf("expected DELETE /api/v1/risk/subject to purge 1 TOFU binding, got %d: %s", resDelBob.Code, resDelBob.Body.String())
	}

	// 3. Burst limit = 3 on fresh IP 198.51.100.10 -> 4th immediate request hits 429 Too Many Requests
	for i := 1; i <= 3; i++ {
		reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/risk/should-collect", nil)
		reqOK.RemoteAddr = "198.51.100.10:12345"
		resOK := httptest.NewRecorder()
		handler.ServeHTTP(resOK, reqOK)
		if resOK.Code != http.StatusOK {
			t.Fatalf("expected request %d within burst=3 to return 200, got %d", i, resOK.Code)
		}
	}

	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/risk/should-collect", nil)
	req4.RemoteAddr = "198.51.100.10:12345"
	res4 := httptest.NewRecorder()
	handler.ServeHTTP(res4, req4)
	if res4.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 4th burst request to return 429 Too Many Requests, got %d: %s", res4.Code, res4.Body)
	}
}
