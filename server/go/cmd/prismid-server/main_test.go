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
