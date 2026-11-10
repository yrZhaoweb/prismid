package main

import (
	"net/http/httptest"
	"testing"
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
