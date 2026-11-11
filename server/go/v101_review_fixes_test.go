package prismid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// TestDeepSeekV100_P1_SpoofDecayCleanVisitsAndTTL verifies DeepSeek v1.0.0 #1 + v1.0.1 #2:
//   - A single-account user who visits once with Canvas noise (Brave Shields / CanvasBlocker)
//     gets RiskStatus=red ("active_tampering_detected", Historical=false) on Visit 1.
//   - Anti-wash #1 (rapid burst): 5 scripted clean requests spaced 3 minutes apart (< 1h DefaultMinCleanStreakInterval)
//     DO NOT increment CleanStreak and DO NOT wash RiskStatus=red!
//   - Anti-wash #2 (cross-device): 5 clean visits from a DIFFERENT device/beacon (d_bcn_B != d_bcn_A)
//     even spaced >1h apart DO NOT wash Device A's spoof edge!
//   - Legitimate recovery: When the SAME hard anchor (d_bcn_A) visits cleanly across 3 sessions spaced >= 1h apart:
//   - Clean streak 1–2: RiskStatus=yellow + RiskPending=true ("historical_tampering_cooldown", Historical=true).
//   - Clean streak 3+: RiskStatus=green + RiskPending=false ("historical_tampering_decayed", Historical=true,
//     LogOdds=HistoricalSpoofLogOdds=1.5, keeping LogOddsScore=-0.5 rather than spotless -2.0).
//   - Step-up clearance: ClearSubjectSpoofAfterStepUp immediately clears active spoof after MFA step-up.
//   - 24h TTL decay: A single spoofed observation decays after DefaultSpoofEdgeTTL (24h), retaining +1.5 HistoricalSpoof residual.
func TestDeepSeekV100_P1_SpoofDecayCleanVisitsAndTTL(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("v101-spoof-decay-secret-32-bytes")}, nil)
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	graph := NewRiskGraphWithClock(AuthoritativeConfidenceThreshold, func() time.Time { return now })

	ip := "198.51.100.42"
	bcnA := "aa00112233445566778899aabbccddee"
	bcnB := "ff00112233445566778899aabbccddee"

	// Visit 1: Active Canvas noise (Brave farbling) on Device A -> Red, active_tampering_detected, Historical=false
	ch1, _ := v.IssueChallenge(ctx, ip)
	p1 := buildValidPayload(ch1)
	p1.BeaconID = bcnA
	p1.System.Canvas2DHash = "brave_noisy_canvas_hash_v1"
	p1.System.CanvasControlRGBA = []int{0, 1, 0, 0, 17, 136, 221, 255}
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch1.Nonce,
		SealedPayload:  sealProbePayload(t, ch1.Nonce, p1),
	}, ip)
	if err != nil {
		t.Fatalf("Visit 1 verify: %v", err)
	}
	snap1 := graph.RecordVerification("brave_user", now, res1)
	if snap1.RiskStatus != RiskStatusRed {
		t.Fatalf("Visit 1 expected red, got %+v", snap1)
	}
	if len(snap1.EvidenceChain) == 0 || snap1.EvidenceChain[len(snap1.EvidenceChain)-1].Category != "active_tampering_detected" ||
		snap1.EvidenceChain[len(snap1.EvidenceChain)-1].Historical {
		t.Fatalf("Visit 1 expected non-historical active_tampering_detected, got %+v", snap1.EvidenceChain)
	}

	// Anti-Wash #1: 5 rapid scripted clean requests 3 minutes apart (< 1h) on Device A MUST stay RED!
	for burstIdx := 1; burstIdx <= 5; burstIdx++ {
		now = now.Add(3 * time.Minute)
		ch, _ := v.IssueChallenge(ctx, ip)
		p := buildValidPayload(ch)
		p.BeaconID = bcnA
		p.System.Canvas2DHash = "clean_unfarbled_canvas_hash"
		p.System.CanvasControlRGBA = []int{0, 0, 0, 0, 17, 136, 221, 255}
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		snapBurst := graph.RecordVerification("brave_user", now, res)
		if snapBurst.RiskStatus != RiskStatusRed {
			t.Fatalf("Rapid burst %d (<1h spacing) washed red into %s! snap=%+v", burstIdx, snapBurst.RiskStatus, snapBurst)
		}
	}

	// Anti-Wash #2: Clean visits from a SECOND device/beacon (bcnB != bcnA) even >1h apart MUST NOT wash Device A's spoof!
	for otherDevIdx := 1; otherDevIdx <= 3; otherDevIdx++ {
		now = now.Add(65 * time.Minute)
		ch, _ := v.IssueChallenge(ctx, "203.0.113.88")
		p := buildValidPayload(ch)
		p.BeaconID = bcnB
		p.System.Canvas2DHash = "other_clean_device_canvas"
		p.System.CanvasControlRGBA = []int{0, 0, 0, 0, 17, 136, 221, 255}
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, "203.0.113.88")
		snapOther := graph.RecordVerification("brave_user", now, res)
		if snapOther.RiskStatus != RiskStatusRed {
			t.Fatalf("Cross-device clean visit %d (bcnB != bcnA) washed Device A's red into %s! snap=%+v", otherDevIdx, snapOther.RiskStatus, snapOther)
		}
	}

	// Legitimate Recovery: Device A (bcnA) disables Brave Shields and visits cleanly across 4 sessions spaced >= 1h apart:
	for cleanIdx := 1; cleanIdx <= 4; cleanIdx++ {
		now = now.Add(65 * time.Minute)
		ch, _ := v.IssueChallenge(ctx, ip)
		p := buildValidPayload(ch)
		p.BeaconID = bcnA
		p.System.Canvas2DHash = "clean_unfarbled_canvas_hash"
		p.System.CanvasControlRGBA = []int{0, 0, 0, 0, 17, 136, 221, 255}
		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
			ChallengeNonce: ch.Nonce,
			SealedPayload:  sealProbePayload(t, ch.Nonce, p),
		}, ip)
		if err != nil {
			t.Fatalf("Clean visit %d verify: %v", cleanIdx, err)
		}
		if res.SpoofTrapTriggered {
			t.Fatalf("Clean visit %d must have SpoofTrapTriggered=false, got %+v", cleanIdx, res)
		}
		snap := graph.RecordVerification("brave_user", now, res)
		for _, ev := range snap.EvidenceChain {
			if ev.Category == "active_tampering_detected" {
				t.Fatalf("Clean visit %d still emitted active_tampering_detected: %+v", cleanIdx, snap.EvidenceChain)
			}
		}
		if cleanIdx < DefaultCleanObservationsToClearSpoof {
			if snap.RiskStatus != RiskStatusYellow || !snap.RiskPending {
				t.Fatalf("Clean visit %d expected yellow+pending cooldown, got %+v", cleanIdx, snap)
			}
			foundCooldown := false
			for _, ev := range snap.EvidenceChain {
				if ev.Category == "historical_tampering_cooldown" && ev.Historical && ev.ObservedAt != "" {
					foundCooldown = true
				}
			}
			if !foundCooldown {
				t.Fatalf("Clean visit %d expected historical_tampering_cooldown with Historical=true & ObservedAt, got %+v", cleanIdx, snap.EvidenceChain)
			}
		} else {
			if snap.RiskStatus != RiskStatusGreen || snap.RiskPending {
				t.Fatalf("Clean visit %d expected recovery to green (pending=false), got %+v", cleanIdx, snap)
			}
			// Must retain permanent +1.5 HistoricalSpoof residual (LogOddsScore = -0.5, NOT spotless -2.0)
			if snap.LogOddsScore <= -1.9 {
				t.Fatalf("Clean visit %d erased historical spoof residual back to spotless baseline: LogOddsScore=%.2f", cleanIdx, snap.LogOddsScore)
			}
			foundDecayed := false
			for _, ev := range snap.EvidenceChain {
				if ev.Category == "historical_tampering_decayed" && ev.Historical && ev.LogOdds == HistoricalSpoofLogOdds && ev.ObservedAt != "" {
					foundDecayed = true
				}
			}
			if !foundDecayed {
				t.Fatalf("Clean visit %d expected historical_tampering_decayed with LogOdds=%.2f, got %+v", cleanIdx, HistoricalSpoofLogOdds, snap.EvidenceChain)
			}
		}
	}

	// Verify Step-Up MFA immediate spoof clearance:
	chStep, _ := v.IssueChallenge(ctx, "198.51.101.77")
	pStep := buildValidPayload(chStep)
	pStep.BeaconID = "ee00112233445566778899aabbccddee"
	pStep.System.CanvasControlRGBA = []int{0, 1, 0, 0, 17, 136, 221, 255}
	resStep, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chStep.Nonce, SealedPayload: sealProbePayload(t, chStep.Nonce, pStep)}, "198.51.101.77")
	if snap := graph.RecordVerification("stepup_user", now, resStep); snap.RiskStatus != RiskStatusRed {
		t.Fatalf("expected initial red for stepup_user, got %+v", snap)
	}
	if !graph.ClearSubjectSpoofAfterStepUp("stepup_user", now.Add(1*time.Minute)) {
		t.Fatalf("expected ClearSubjectSpoofAfterStepUp to clear active spoof")
	}
	snapStepCleared := graph.EvaluateSubject("stepup_user")
	if snapStepCleared.RiskStatus != RiskStatusGreen || snapStepCleared.LogOddsScore != -2.0+HistoricalSpoofLogOdds {
		t.Fatalf("expected stepup_user green with -0.5 residual LogOddsScore, got %+v", snapStepCleared)
	}

	// Verify 24h TTL time-based decay even without 3 clean visits:
	chTTL, _ := v.IssueChallenge(ctx, "198.51.102.99")
	pTTL := buildValidPayload(chTTL)
	pTTL.BeaconID = "bb00112233445566778899aabbccddee"
	pTTL.System.CanvasControlRGBA = []int{0, 1, 0, 0, 17, 136, 221, 255}
	resTTL, _ := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chTTL.Nonce,
		SealedPayload:  sealProbePayload(t, chTTL.Nonce, pTTL),
	}, "198.51.102.99")
	snapTTL1 := graph.RecordVerification("transient_glitch_user", now, resTTL)
	if snapTTL1.RiskStatus != RiskStatusRed {
		t.Fatalf("expected initial red, got %+v", snapTTL1)
	}
	now = now.Add(25 * time.Hour)
	snapTTLAfter := graph.EvaluateSubject("transient_glitch_user")
	if snapTTLAfter.RiskStatus != RiskStatusGreen || snapTTLAfter.RiskPending || snapTTLAfter.LogOddsScore != -2.0+HistoricalSpoofLogOdds {
		t.Fatalf("expected spoofed single account to decay to green (-0.5 log-odds) after >24h TTL via EvaluateSubject, got %+v", snapTTLAfter)
	}
}

// TestDeepSeekV100_P1_Safari16WorkerWebGLUnavailableNotFlaggedRed verifies DeepSeek v1.0.0 Finding #2:
//   - When WorkerGlobalScope runs normally (WorkerUnavailable=false, UA/Platform/CPUCores populated)
//     while OffscreenCanvas WebGL is unavailable (WorkerStaticWebGLFpHash="", WorkerGPURenderer=""),
//     the verifier MUST NOT flag worker_partial_telemetry_stripped / worker_lie_detected / red!
//   - Instead it records "worker_webgl_unavailable" in PrivacySignals and keeps RiskStatus=green.
//   - Meanwhile, if main-thread UA/Platform/Cores disagree with Worker on Safari 16, it is STILL caught!
func TestDeepSeekV100_P1_Safari16WorkerWebGLUnavailableNotFlaggedRed(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("v101-safari16-worker-secret-32b!")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)

	ch, _ := v.IssueChallenge(ctx, "203.0.113.16")
	p := buildValidPayload(ch)
	p.BeaconID = "cc00112233445566778899aabbccddee"
	p.System.Platform = "MacIntel"
	p.System.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
	p.System.CPUCores = 8
	p.System.DeviceMemory = 0 // Safari/WebKit does not expose navigator.deviceMemory
	p.Lies.MathEngineSignature = "jsc"
	p.Lies.WorkerUnavailable = false
	p.Lies.WorkerWebGLAvailable = nil // Legacy/Safari 16 payload or explicit false
	p.Lies.WorkerUserAgent = p.System.UserAgent
	p.Lies.WorkerPlatform = "MacIntel"
	p.Lies.WorkerCPUCores = 8
	p.Lies.WorkerTimezone = p.System.Timezone
	p.Lies.WorkerGPURenderer = ""
	p.Lies.WorkerStaticWebGLFpHash = ""

	res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealProbePayload(t, ch.Nonce, p),
	}, "203.0.113.16")
	if err != nil {
		t.Fatalf("Safari 16 verify failed: %v", err)
	}
	if res.SpoofTrapTriggered {
		t.Fatalf("Safari 16 with unavailable OffscreenCanvas WebGL falsely flagged as spoof: flags=%v", res.SpoofFlags)
	}
	hasSignal := false
	for _, s := range res.PrivacySignals {
		if s == "worker_webgl_unavailable" {
			hasSignal = true
		}
	}
	if !hasSignal {
		t.Fatalf("expected worker_webgl_unavailable in PrivacySignals, got %v", res.PrivacySignals)
	}
	snap := graph.RecordVerification("safari16_user", time.Now().UTC(), res)
	if snap.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected Safari 16 user to be green, got %+v", snap)
	}

	// Verify main-thread UA spoofing on Safari 16 IS still caught via Worker UA mismatch:
	chLie, _ := v.IssueChallenge(ctx, "203.0.113.16")
	pLie := p
	pLie.Nonce = chLie.Nonce
	pLie.WebGL.SpotPixels = ComputeAllExpectedSpotPixels(chLie.SamplePoints, chLie.RenderSeed)
	pLie.System.UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
	resLie, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chLie.Nonce,
		SealedPayload:  sealProbePayload(t, chLie.Nonce, pLie),
	}, "203.0.113.16")
	if err != nil || !resLie.SpoofTrapTriggered {
		t.Fatalf("expected main-thread UA spoofing on Safari 16 to trigger worker_lie_detected, got res=%+v err=%v", resLie, err)
	}
}

// TestDeepSeekV100_P2_TOFURebindAndObservationTimeSoftPruning verifies DeepSeek v1.0.0 Findings #4 & #6:
//   - RebindDeviceKey updates a bound beacon to a replacement ECDSA P-256 key after step-up auth.
//   - Soft-slice TTL uses edge ObservedAt (not SubjectCreatedAt) and prunes expired soft edges.
func TestDeepSeekV100_P2_TOFURebindAndObservationTimeSoftPruning(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("v101-tofu-rebind-secret-32-bytes")}, nil)
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	graph := NewRiskGraphWithClock(AuthoritativeConfidenceThreshold, func() time.Time { return now })

	signPayload := func(priv *ecdsa.PrivateKey, p *ProbePayload) {
		pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		msg := strings.Join([]string{
			"prismid-v2-sig",
			p.Nonce,
			strings.ToLower(p.BeaconID),
			strings.ToLower(p.WebGL.StaticWebGLFpHash),
			strings.ToLower(p.AudioCompressorHash),
		}, "|")
		digest := sha256.Sum256([]byte(msg))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
		var sig [64]byte
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		p.DeviceKey = &DeviceKeyProof{
			Alg:       "ecdsa-p256",
			PubKey:    base64.RawURLEncoding.EncodeToString(pubBytes),
			Signature: base64.RawURLEncoding.EncodeToString(sig[:]),
		}
	}

	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bcn := "dd00112233445566778899aabbccddee"

	// 1. Bind key1 on day 0 (with subnet 198.51.10.1)
	ch1, _ := v.IssueChallenge(ctx, "198.51.10.1")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = bcn
	signPayload(key1, &p1)
	res1, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "198.51.10.1")
	snap1 := graph.RecordVerification("long_lived_user", now, res1)
	if snap1.RiskStatus != RiskStatusGreen || !res1.DeviceKeyBound {
		t.Fatalf("expected green bound visit 1, got res=%+v snap=%+v", res1, snap1)
	}
	oldSysSlice := res1.SysNetSliceID

	// 2. IndexedDB wiped -> client generates key2 -> recovery required before step-up rebind
	now = now.Add(8 * 24 * time.Hour) // 8 days later (> DefaultSoftEdgeTTL = 7d)
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.55")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = bcn
	signPayload(key2, &p2)
	res2, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "203.0.113.55")
	if !res2.DeviceKeyRecoveryRequired || res2.DeviceKeySliceID == "" {
		t.Fatalf("expected DeviceKeyRecoveryRequired=true with candidate new key2 slice, got %+v", res2)
	}

	// 3. Security check (DeepSeek v1.0.1 P1 #1): Alice attempting to rebind Bob's ("long_lived_user") beacon
	// MUST fail with ErrCodeRebindForbidden BEFORE consuming challenge_nonce, emit denied_not_owner audit,
	// and keep long_lived_user's key1 binding intact!
	chRebind, _ := v.IssueChallenge(ctx, "203.0.113.55")
	signRebind := func(priv *ecdsa.PrivateKey, nonce, subjectID, beaconID string) *DeviceKeyProof {
		pubBytes := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
		msg := strings.Join([]string{"prismid-v2-rebind", nonce, subjectID, strings.ToLower(beaconID)}, "|")
		digest := sha256.Sum256([]byte(msg))
		r, s, _ := ecdsa.Sign(rand.Reader, priv, digest[:])
		var sig [64]byte
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return &DeviceKeyProof{
			Alg:       "ecdsa-p256",
			PubKey:    base64.RawURLEncoding.EncodeToString(pubBytes),
			Signature: base64.RawURLEncoding.EncodeToString(sig[:]),
		}
	}

	_, err := v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chRebind.Nonce,
		SubjectID:      "attacker_alice",
		BeaconID:       bcn,
		DeviceKey:      signRebind(key2, chRebind.Nonce, "attacker_alice", bcn),
	}, graph.SubjectOwnsBeaconExclusively, "198.51.100.66")
	if vErr, ok := err.(*VerificationError); !ok || vErr.Code != ErrCodeRebindForbidden {
		t.Fatalf("expected REBIND_FORBIDDEN for cross-subject rebind attempt, got %v", err)
	}

	// Owner with forged signature (signed by key1 claiming key2 or wrong transcript) MUST fail with REBIND_INVALID_KEY_PROOF:
	chBadSig, _ := v.IssueChallenge(ctx, "203.0.113.55")
	badProof := signRebind(key1, chBadSig.Nonce, "long_lived_user", bcn)
	badProof.PubKey = base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), key2.PublicKey.X, key2.PublicKey.Y))
	_, err = v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chBadSig.Nonce,
		SubjectID:      "long_lived_user",
		BeaconID:       bcn,
		DeviceKey:      badProof,
	}, graph.SubjectOwnsBeaconExclusively, "203.0.113.55")
	if vErr, ok := err.(*VerificationError); !ok || vErr.Code != ErrCodeRebindInvalidKeyProof {
		t.Fatalf("expected REBIND_INVALID_KEY_PROOF on mismatched public key / signature, got %v", err)
	}

	// Notice chRebind.Nonce was NOT consumed by attacker_alice's 403 attempt! Legitimate owner rebinds using chRebind.Nonce + key2 PoP:
	rebindRes, err := v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chRebind.Nonce,
		SubjectID:      "long_lived_user",
		BeaconID:       bcn,
		DeviceKey:      signRebind(key2, chRebind.Nonce, "long_lived_user", bcn),
	}, graph.SubjectOwnsBeaconExclusively, "203.0.113.55")
	if err != nil || rebindRes == nil || !rebindRes.Rebound || rebindRes.DeviceKeySliceID != res2.DeviceKeySliceID {
		t.Fatalf("RebindDeviceKeyWithProof failed: res=%+v err=%v", rebindRes, err)
	}
	audits := v.RebindAuditEvents()
	if len(audits) != 3 || audits[0].Outcome != "denied_not_owner" || audits[1].Outcome != "denied_invalid_pop" || audits[2].Outcome != "rebound" {
		t.Fatalf("unexpected key-rebind audit log: %+v", audits)
	}

	// 4. Subsequent visit with key2 on new subnet 203.0.113.55 succeeds -> green, AND old 8-day-old d_sys_* soft slice was pruned!
	ch3, _ := v.IssueChallenge(ctx, "203.0.113.55")
	p3 := buildValidPayload(ch3)
	p3.BeaconID = bcn
	signPayload(key2, &p3)
	res3, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch3.Nonce, SealedPayload: sealProbePayload(t, ch3.Nonce, p3)}, "203.0.113.55")
	if res3.DeviceKeyRecoveryRequired || !res3.DeviceKeyBound {
		t.Fatalf("expected rebound key2 to verify cleanly, got %+v", res3)
	}
	snap3 := graph.RecordVerification("long_lived_user", now, res3)
	if snap3.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected green after key2 rebind, got %+v", snap3)
	}
	for _, sl := range snap3.SliceIDs {
		if sl == oldSysSlice {
			t.Fatalf("expected 8-day-old soft slice %s (> 7d DefaultSoftEdgeTTL) to be pruned, still in %v", oldSysSlice, snap3.SliceIDs)
		}
	}

	// 5. GDPR erasure removes BOTH graph edges AND TOFU key bindings (DeepSeek v1.0.1 P3 #6):
	removed, beacons := graph.RemoveSubjectAndCollectBeacons("long_lived_user")
	if !removed || len(beacons) != 1 || beacons[0] != res1.BeaconSliceID {
		t.Fatalf("expected RemoveSubjectAndCollectBeacons to return %s, got removed=%v beacons=%v", res1.BeaconSliceID, removed, beacons)
	}
	if purged := v.ForgetBeacons(ctx, beacons...); purged != 1 {
		t.Fatalf("expected ForgetBeacons to purge 1 TOFU binding, got %d", purged)
	}
	// After GDPR purge, visiting with original key1 re-binds cleanly via fresh TOFU without recovery_required!
	ch4, _ := v.IssueChallenge(ctx, "203.0.113.55")
	p4 := buildValidPayload(ch4)
	p4.BeaconID = bcn
	signPayload(key1, &p4)
	res4, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch4.Nonce, SealedPayload: sealProbePayload(t, ch4.Nonce, p4)}, "203.0.113.55")
	if res4.DeviceKeyRecoveryRequired || !res4.DeviceKeyBound {
		t.Fatalf("expected post-GDPR visit to bind freshly without stale TOFU state, got %+v", res4)
	}
}
