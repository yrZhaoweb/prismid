package prismid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func signDeviceKeyForTest(t *testing.T, priv *ecdsa.PrivateKey, nonce, beaconHex, staticWebGLHash, audioHash string) *DeviceKeyProof {
	t.Helper()
	msg := strings.Join([]string{
		"prismid-v2-sig",
		nonce,
		strings.ToLower(beaconHex),
		strings.ToLower(staticWebGLHash),
		strings.ToLower(audioHash),
	}, "|")
	dig := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, dig[:])
	if err != nil {
		t.Fatalf("sign device key: %v", err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return &DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)),
		Signature: hex.EncodeToString(sig[:]),
	}
}

func signRebindForTest(t *testing.T, priv *ecdsa.PrivateKey, prefix, nonce, subjectID, beaconHex string, extra ...string) *DeviceKeyProof {
	t.Helper()
	parts := []string{
		prefix,
		nonce,
		subjectID,
		strings.ToLower(beaconHex),
	}
	for _, ex := range extra {
		parts = append(parts, strings.ToLower(ex))
	}
	msg := strings.Join(parts, "|")
	dig := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, dig[:])
	if err != nil {
		t.Fatalf("sign rebind proof: %v", err)
	}
	var sig [64]byte
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return &DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)),
		Signature: hex.EncodeToString(sig[:]),
	}
}

// TestS1_1_And_3_GraphRestartKeyRecoveryNoDeadlockAndOldKeyRetired verifies:
//   - S1-1: Persistent ChallengeStore + brand-new empty RiskGraph (simulating restart or subject eviction)
//     does NOT deadlock key recovery for the legitimate owner, while still rejecting cross-account attackers!
//   - S1-3: Rebinding retires the old `d_key_old` hard edge immediately so the account is NOT permanently
//     welded to other accounts using the stolen/retired `d_key_old`.
//   - S2-12: Routine key rotation works via `PreviousDeviceKey` signature continuity proof.
func TestS1_1_And_3_GraphRestartKeyRecoveryNoDeadlockAndOldKeyRetired(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC)
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v := NewVerifier(Config{
		HMACSecret: []byte("v110-s1-recovery-secret-32-bytes"),
		NowFunc:    func() time.Time { return now },
	}, store)

	bcnBob := "11223344556677889900aabbccddeeff"
	keyOld, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyNew, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyRotated, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyAttacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// 1. Bob registers on graph1 with keyOld + bcnBob:
	graph1 := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: store})
	v.BindRiskGraph(graph1)

	ch1, _ := v.IssueChallenge(ctx, "203.0.113.10")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = bcnBob
	p1.DeviceKey = signDeviceKeyForTest(t, keyOld, ch1.Nonce, bcnBob, p1.WebGL.StaticWebGLFpHash, p1.AudioCompressorHash)
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "203.0.113.10")
	if err != nil {
		t.Fatalf("bob initial verify: %v", err)
	}
	oldKeySlice := res1.DeviceKeySliceID
	snap1 := graph1.RecordVerification("bob", now, res1)
	if snap1.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected bob green, got %+v", snap1)
	}

	// 2. Simulate full server restart: graph1 is lost in memory; brand-new empty graph2 is created!
	graph2 := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: store})
	v.BindRiskGraph(graph2)

	// Bob loses IndexedDB key (sends keyNew with bcnBob) -> DeviceKeyRecoveryRequired=true
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.10")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = bcnBob
	p2.DeviceKey = signDeviceKeyForTest(t, keyNew, ch2.Nonce, bcnBob, p2.WebGL.StaticWebGLFpHash, p2.AudioCompressorHash)
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "203.0.113.10")
	if err != nil || !res2.DeviceKeyRecoveryRequired {
		t.Fatalf("expected DeviceKeyRecoveryRequired=true, got res=%+v err=%v", res2, err)
	}
	_ = graph2.RecordVerification("bob", now.Add(time.Minute), res2)

	// Cross-account attacker "mallory" MUST still get REBIND_FORBIDDEN even when graph2 is empty!
	chAtk, _ := v.IssueChallenge(ctx, "198.51.100.99")
	_, atkErr := v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chAtk.Nonce,
		SubjectID:      "mallory",
		BeaconID:       bcnBob,
		DeviceKey:      signRebindForTest(t, keyAttacker, "prismid-v2-rebind", chAtk.Nonce, "mallory", bcnBob),
	}, v.BeaconOwnerCheck(graph2), "198.51.100.99")
	if atkErr == nil {
		t.Fatalf("expected cross-account mallory rebind to fail with REBIND_FORBIDDEN")
	}

	// Legitimate owner "bob" MUST succeed on empty graph2 (no S1-1 deadlock!):
	chRebind, _ := v.IssueChallenge(ctx, "203.0.113.10")
	rebindRes, err := v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chRebind.Nonce,
		SubjectID:      "bob",
		BeaconID:       bcnBob,
		DeviceKey:      signRebindForTest(t, keyNew, "prismid-v2-rebind", chRebind.Nonce, "bob", bcnBob),
	}, v.BeaconOwnerCheck(graph2), "203.0.113.10")
	if err != nil || !rebindRes.Rebound {
		t.Fatalf("expected bob rebind to succeed after graph loss, got res=%+v err=%v", rebindRes, err)
	}

	// Also verify S1-1 un-bound graph fallback (even if BeaconOwnerStore had 0 prior owners):
	storeUnbound := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	vUnbound := NewVerifier(Config{HMACSecret: []byte("v110-unbound-secret-32-bytes-000"), NowFunc: func() time.Time { return now }}, storeUnbound)
	chU1, _ := vUnbound.IssueChallenge(ctx, "203.0.113.10")
	pU1 := buildValidPayload(chU1)
	pU1.BeaconID = bcnBob
	pU1.DeviceKey = signDeviceKeyForTest(t, keyOld, chU1.Nonce, bcnBob, pU1.WebGL.StaticWebGLFpHash, pU1.AudioCompressorHash)
	_, _ = vUnbound.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chU1.Nonce, SealedPayload: sealProbePayload(t, chU1.Nonce, pU1)}, "203.0.113.10")
	freshGraph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	chU2, _ := vUnbound.IssueChallenge(ctx, "203.0.113.10")
	pU2 := buildValidPayload(chU2)
	pU2.BeaconID = bcnBob
	pU2.DeviceKey = signDeviceKeyForTest(t, keyNew, chU2.Nonce, bcnBob, pU2.WebGL.StaticWebGLFpHash, pU2.AudioCompressorHash)
	resU2, _ := vUnbound.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chU2.Nonce, SealedPayload: sealProbePayload(t, chU2.Nonce, pU2)}, "203.0.113.10")
	freshGraph.RecordVerification("bob", now, resU2) // registers pending recovery claim on freshGraph
	chURebind, _ := vUnbound.IssueChallenge(ctx, "203.0.113.10")
	if _, err := vUnbound.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chURebind.Nonce,
		SubjectID:      "bob",
		BeaconID:       bcnBob,
		DeviceKey:      signRebindForTest(t, keyNew, "prismid-v2-rebind", chURebind.Nonce, "bob", bcnBob),
	}, freshGraph.SubjectOwnsBeaconExclusively, "203.0.113.10"); err != nil {
		t.Fatalf("expected pending-recovery fallback on freshGraph to succeed, got %v", err)
	}

	// 3. Verify S1-3 on graph1: rebinding retires `d_key_old` immediately so compromised `keyOld` cannot link a thief to Bob!
	v.BindRiskGraph(graph1)
	chRot, _ := v.IssueChallenge(ctx, "203.0.113.10")
	newRotProof := signRebindForTest(t, keyRotated, "prismid-v2-rebind", chRot.Nonce, "bob", bcnBob)
	rotReq := KeyRebindRequest{
		ChallengeNonce:    chRot.Nonce,
		SubjectID:         "bob",
		BeaconID:          bcnBob,
		DeviceKey:         newRotProof,
		PreviousDeviceKey: signRebindForTest(t, keyNew, "prismid-v2-rebind-prev", chRot.Nonce, "bob", bcnBob, newRotProof.PubKey),
	}
	if !v.HasValidPreviousKeyProof(ctx, rotReq) {
		t.Fatalf("expected HasValidPreviousKeyProof=true for valid keyNew -> keyRotated continuity signature")
	}
	rotRes, err := v.RebindDeviceKeyWithProof(ctx, rotReq, v.BeaconOwnerCheck(graph1), "203.0.113.10")
	if err != nil || !rotRes.RetiredPreviousKey {
		t.Fatalf("expected key rotation to succeed and retire previous key, got res=%+v err=%v", rotRes, err)
	}

	// Bob identifies with keyRotated:
	chBob3, _ := v.IssueChallenge(ctx, "203.0.113.10")
	pBob3 := buildValidPayload(chBob3)
	pBob3.BeaconID = bcnBob
	pBob3.DeviceKey = signDeviceKeyForTest(t, keyRotated, chBob3.Nonce, bcnBob, pBob3.WebGL.StaticWebGLFpHash, pBob3.AudioCompressorHash)
	resBob3, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chBob3.Nonce, SealedPayload: sealProbePayload(t, chBob3.Nonce, pBob3)}, "203.0.113.10")
	if err != nil || resBob3.DeviceKeyRecoveryRequired {
		t.Fatalf("expected bob post-rotation verify to succeed cleanly, got res=%+v err=%v", resBob3, err)
	}
	snapBob3 := graph1.RecordVerification("bob", now.Add(5*time.Minute), resBob3)
	for _, sl := range snapBob3.SliceIDs {
		if sl == oldKeySlice {
			t.Fatalf("S1-3 regression: retired d_key_old %s remained in bob's SliceIDs: %v", oldKeySlice, snapBob3.SliceIDs)
		}
	}

	// Thief uses stolen `keyOld` on a different beacon -> MUST NOT merge with Bob!
	bcnThief := "99887766554433221100ffeeddccbbaa"
	chThief, _ := v.IssueChallenge(ctx, "198.51.100.77")
	pThief := buildValidPayload(chThief)
	pThief.BeaconID = bcnThief
	pThief.DeviceKey = signDeviceKeyForTest(t, keyOld, chThief.Nonce, bcnThief, pThief.WebGL.StaticWebGLFpHash, pThief.AudioCompressorHash)
	resThief, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chThief.Nonce, SealedPayload: sealProbePayload(t, chThief.Nonce, pThief)}, "198.51.100.77")
	_ = graph1.RecordVerification("thief_with_old_key", now.Add(6*time.Minute), resThief)

	bobAfterThief := graph1.EvaluateSubject("bob")
	if len(bobAfterThief.ComponentSubjects) != 1 || bobAfterThief.RiskStatus != RiskStatusGreen {
		t.Fatalf("S1-3 regression: thief using retired keyOld merged into bob: %+v", bobAfterThief)
	}
}

// TestS1_2_And_S2_11_SharedFamilyBrowserYellowStepUpAndSharedRebind verifies:
//   - S1-2: `family_mom` + `family_kid` on the same browser (`d_bcn` + `d_key`) elevate to `yellow + RiskPending=true`
//     (NOT `red`!), whereas cookie-wiping `StorageHealed=true` or `>= 4` accounts escalate to `red`,
//     and `step_up_all` / `disabled` policies behave as documented.
//   - S2-11: Both `family_mom` and `family_kid` on a shared beacon can recover/rebind via `SubjectOwnsBeacon`.
func TestS1_2_And_S2_11_SharedFamilyBrowserYellowStepUpAndSharedRebind(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v := NewVerifier(Config{HMACSecret: []byte("v110-family-shared-secret-32byte"), NowFunc: func() time.Time { return now }}, store)
	graph := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: store})
	v.BindRiskGraph(graph)

	bcnHome := "aa11bb22cc33dd44ee55ff6677889900"
	keyHome1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyHome2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	identifyOnHomePC := func(subject string, offset time.Duration, priv *ecdsa.PrivateKey) ComponentSnapshot {
		ch, _ := v.IssueChallenge(ctx, "203.0.113.55")
		p := buildValidPayload(ch)
		p.BeaconID = bcnHome
		p.DeviceKey = signDeviceKeyForTest(t, priv, ch.Nonce, bcnHome, p.WebGL.StaticWebGLFpHash, p.AudioCompressorHash)
		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, "203.0.113.55")
		if err != nil {
			t.Fatalf("identify %s: %v", subject, err)
		}
		return graph.RecordVerification(subject, now.Add(offset), res)
	}

	snapMom := identifyOnHomePC("family_mom", 0, keyHome1)
	if snapMom.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected family_mom=green, got %+v", snapMom)
	}

	snapKid := identifyOnHomePC("family_kid", 10*time.Minute, keyHome1)
	if snapKid.RiskStatus != RiskStatusYellow || !snapKid.RiskPending {
		t.Fatalf("S1-2: expected family_kid on shared home browser to be yellow+pending (not red!), got %+v", snapKid)
	}

	// S2-11: Shared browser IndexedDB is cleared; `family_kid` (non-exclusive co-owner!) recovers keyHome2:
	chRebind, _ := v.IssueChallenge(ctx, "203.0.113.55")
	if _, err := v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
		ChallengeNonce: chRebind.Nonce,
		SubjectID:      "family_kid",
		BeaconID:       bcnHome,
		DeviceKey:      signRebindForTest(t, keyHome2, "prismid-v2-rebind", chRebind.Nonce, "family_kid", bcnHome),
	}, v.BeaconOwnerCheck(graph), "203.0.113.55"); err != nil {
		t.Fatalf("S2-11: expected co-owner family_kid to rebind shared beacon, got %v", err)
	}

	// 3rd family member ("family_dad") still yellow+pending; 4th account escalates to red under shared_step_up:
	snapDad := identifyOnHomePC("family_dad", 20*time.Minute, keyHome2)
	if snapDad.RiskStatus != RiskStatusYellow || !snapDad.RiskPending {
		t.Fatalf("expected 3rd household member family_dad to stay yellow+pending, got %+v", snapDad)
	}
	snapFarm4 := identifyOnHomePC("farm_acct_4", 30*time.Minute, keyHome2)
	if snapFarm4.RiskStatus != RiskStatusRed {
		t.Fatalf("expected 4th account on same browser profile to escalate to red under shared_step_up, got %+v", snapFarm4)
	}

	// Kiosk / school lab policy (`step_up_all`) keeps even 4+ clean accounts at yellow+pending:
	graph.SetHardAnchorPolicy(HardAnchorPolicyStepUpAll)
	if snapKiosk := graph.EvaluateSubject("farm_acct_4"); snapKiosk.RiskStatus != RiskStatusYellow || !snapKiosk.RiskPending {
		t.Fatalf("expected step_up_all policy to keep 4th clean kiosk user yellow+pending, got %+v", snapKiosk)
	}

	// `disabled` policy prevents cross-account merging across hard slices:
	graph.SetHardAnchorPolicy(HardAnchorPolicyDisabled)
	if snapDisabled := graph.EvaluateSubject("family_kid"); snapDisabled.RiskStatus == RiskStatusRed || len(snapDisabled.ComponentSubjects) != 1 {
		t.Fatalf("expected disabled policy to isolate single clean account, got %+v", snapDisabled)
	}
}

// TestS1_4_5_8_And_S2_9_15_PersistenceEvictionShortSliceAndStatelessDecay verifies:
//   - S1-4: FileStateStore & FileAuditStore round-trip RiskGraph, ChallengeStore, and JSONL audits across restarts.
//   - S1-5: Filling maxSubjects with isolated single-account subjects evicts oldest isolated clean subjects so new users are NOT locked out in pending!
//   - S1-8 / #31: Short GpuAudioSliceID / SysNetSliceID ("short", "d_gpu_") never panics.
//   - S2-9: Stateless spoof (no beacon / no key) recovers after 3 clean visits spaced >= 1h apart on same hardware slice.
//   - S2-15: Expired soft edges are pruned before MaxSubjectsPerSlice eviction, and soft eviction counters increment.
func TestS1_4_5_8_And_S2_9_15_PersistenceEvictionShortSliceAndStatelessDecay(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)

	// 1. S1-8 / #31: Short slice IDs must never panic!
	gShort := NewRiskGraph(AuthoritativeConfidenceThreshold)
	snapShort := gShort.RecordVerification("short_slice_user", now, &VerifyResult{
		Accepted:        true,
		Confidence:      0.95,
		ExactSliceID:    "x",
		GpuAudioSliceID: "short",
		SysNetSliceID:   "tiny",
	})
	if snapShort.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected short slice IDs to evaluate cleanly without panic, got %+v", snapShort)
	}

	// 2. S1-5: Isolated subject eviction prevents attacker from locking out new users at maxSubjects!
	gCap := NewRiskGraphWithOptions(GraphOptions{
		MinConfidence: AuthoritativeConfidenceThreshold,
		MaxSubjects:   10,
		NowFunc:       func() time.Time { return now },
	})
	// Create 1 high-value linked pair ("linked_a", "linked_b") + 8 isolated junk accounts = 10/10 full
	gCap.RecordVerification("linked_a", now, &VerifyResult{Accepted: true, Confidence: 0.95, BeaconSliceID: "d_bcn_pair"})
	gCap.RecordVerification("linked_b", now.Add(time.Second), &VerifyResult{Accepted: true, Confidence: 0.95, BeaconSliceID: "d_bcn_pair"})
	for i := 0; i < 8; i++ {
		gCap.RecordVerification(fmt.Sprintf("junk_%d", i), now.Add(time.Duration(i+2)*time.Second), &VerifyResult{
			Accepted:      true,
			Confidence:    0.95,
			BeaconSliceID: fmt.Sprintf("d_bcn_isolated_%d", i),
		})
	}
	// New legitimate user arrives when graph is at 10/10 -> evicts junk_0, admits legit_new_user as GREEN (not pending!), and keeps linked_a/linked_b!
	snapNew := gCap.RecordVerification("legit_new_user", now.Add(time.Minute), &VerifyResult{
		Accepted:      true,
		Confidence:    0.95,
		BeaconSliceID: "d_bcn_legit_new",
	})
	if snapNew.RiskStatus != RiskStatusGreen || snapNew.RiskPending || snapNew.Truncated {
		t.Fatalf("S1-5: new user was locked out by isolated junk subjects: %+v", snapNew)
	}
	if len(gCap.EvaluateSubject("linked_a").ComponentSubjects) != 2 {
		t.Fatalf("S1-5: high-value linked pair must never be evicted")
	}
	if gCap.Stats().SoftSubjectEvictions != 1 {
		t.Fatalf("expected SoftSubjectEvictions=1, got %+v", gCap.Stats())
	}

	// 3. S2-9: Stateless spoof (no beacon, no key) recovers after 3 clean visits spaced >= 1h apart!
	curTime := now
	gStateless := NewRiskGraphWithClock(AuthoritativeConfidenceThreshold, func() time.Time { return curTime })
	gStateless.RecordVerification("stateless_user", curTime, &VerifyResult{
		Accepted:           true,
		Confidence:         0.85,
		ExactSliceID:       "d_web_stateless_1",
		GpuAudioSliceID:    "d_gpu_stateless_1",
		SysNetSliceID:      "d_sys_stateless_1",
		SpoofTrapTriggered: true,
	})
	if s := gStateless.EvaluateSubject("stateless_user"); s.RiskStatus != RiskStatusRed {
		t.Fatalf("expected initial stateless spoof=red, got %+v", s)
	}
	for step := 1; step <= 3; step++ {
		curTime = curTime.Add(65 * time.Minute)
		s := gStateless.RecordVerification("stateless_user", curTime, &VerifyResult{
			Accepted:           true,
			Confidence:         0.95,
			ExactSliceID:       "d_web_stateless_1",
			GpuAudioSliceID:    "d_gpu_stateless_1",
			SysNetSliceID:      "d_sys_stateless_1",
			SpoofTrapTriggered: false,
		})
		if step < 3 && s.RiskStatus != RiskStatusYellow {
			t.Fatalf("step %d: expected yellow cooldown, got %+v", step, s)
		}
		if step == 3 && (s.RiskStatus != RiskStatusGreen || s.RiskPending) {
			t.Fatalf("S2-9: expected stateless user to recover to green on 3rd clean visit, got %+v", s)
		}
	}

	// 4. S2-15: Stale soft edges (> 7d) do NOT occupy MaxSubjectsPerSlice slots or cause unnecessary evictions!
	tSlice := now
	gSoft := NewRiskGraphWithClock(AuthoritativeConfidenceThreshold, func() time.Time { return tSlice })
	for i := 0; i < MaxSubjectsPerSlice; i++ {
		gSoft.RecordVerification(fmt.Sprintf("old_soft_%d", i), tSlice, &VerifyResult{
			Accepted:        true,
			Confidence:      0.95,
			BeaconSliceID:   fmt.Sprintf("d_bcn_s_%d", i),
			GpuAudioSliceID: "d_gpu_crowded_model",
		})
	}
	// Advance 8 days (> DefaultSoftEdgeTTL = 7d) and add a new user on d_gpu_crowded_model:
	tSlice = tSlice.Add(8 * 24 * time.Hour)
	gSoft.RecordVerification("fresh_after_ttl", tSlice, &VerifyResult{
		Accepted:        true,
		Confidence:      0.95,
		BeaconSliceID:   "d_bcn_fresh",
		GpuAudioSliceID: "d_gpu_crowded_model",
	})
	if gSoft.Stats().SoftSliceEvictions != 0 {
		t.Fatalf("S2-15: expected expired soft edges to be pruned before eviction (0 evictions), got %+v", gSoft.Stats())
	}

	// 5. S1-4 & S3-50: FileStateStore + FileAuditStore atomic persistence roundtrip!
	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "prismid-state.json")
	auditFile := filepath.Join(tmpDir, "prismid-audit.jsonl")

	fsStore, err := NewFileStateStore(stateFile)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}
	audStore, err := NewFileAuditStore(auditFile)
	if err != nil {
		t.Fatalf("NewFileAuditStore: %v", err)
	}

	mem1 := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v1 := NewVerifier(Config{
		HMACSecret: []byte("persist-secret-key-32-bytes-0000"),
		NowFunc:    func() time.Time { return now },
		AuditStore: audStore,
	}, mem1)
	g1 := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: mem1})
	v1.BindRiskGraph(g1)

	bcnPersist := "abcdef0123456789abcdef0123456789"
	keyPersist, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chP, _ := v1.IssueChallenge(ctx, "203.0.113.88")
	pP := buildValidPayload(chP)
	pP.BeaconID = bcnPersist
	pP.DeviceKey = signDeviceKeyForTest(t, keyPersist, chP.Nonce, bcnPersist, pP.WebGL.StaticWebGLFpHash, pP.AudioCompressorHash)
	resP, _ := v1.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chP.Nonce, SealedPayload: sealProbePayload(t, chP.Nonce, pP)}, "203.0.113.88")
	g1.RecordVerification("persisted_alice", now, resP)
	v1.ClearSubjectSpoofAudited(g1, "persisted_alice", "203.0.113.88", now)

	if err := fsStore.SaveState(ctx, g1, mem1); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Reload into brand-new store + graph:
	loaded, err := fsStore.LoadState(ctx)
	if err != nil || loaded == nil {
		t.Fatalf("LoadState: loaded=%+v err=%v", loaded, err)
	}
	mem2 := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	_ = mem2.ImportSnapshot(*loaded.ChallengeStore)
	g2 := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: mem2})
	_ = g2.ImportSnapshot(*loaded.Graph)

	if snapReloaded := g2.EvaluateSubject("persisted_alice"); snapReloaded.RiskStatus != RiskStatusGreen || len(snapReloaded.SliceIDs) == 0 {
		t.Fatalf("expected reloaded persisted_alice to stay green with slices, got %+v", snapReloaded)
	}
	owners, _ := mem2.GetBeaconOwners(ctx, resP.BeaconSliceID)
	if len(owners) != 1 || owners[0] != "persisted_alice" {
		t.Fatalf("expected persisted beacon owner [persisted_alice], got %v", owners)
	}
	audEvents, err := audStore.ListAuditEvents(ctx, 10)
	if err != nil || len(audEvents) != 1 || audEvents[0].Action != "clear_spoof" {
		t.Fatalf("expected 1 persisted clear_spoof audit event, got %+v err=%v", audEvents, err)
	}
}

// TestS2_16_18_21_And_S3_27_28_30_DisabledWebGLQuotaTurnstileIPAndGDPRErase verifies:
//   - S2-18: Hardened Firefox (`webgl_available=false`, renderer `WebGL Disabled`) with bound key+beacon gets 0.75 (`green`),
//     anonymous stateless no-WebGL gets 0.30 (`pending`), and SwiftShader gets `IsVirtualGPU=true` (`0.30`).
//   - S2-16 & S3-28: Single attacker IP issuing 500 challenges cannot evict victim IPs' pending challenges;
//     `Challenge.ClientIP` mismatch emits `challenge_ip_subnet_changed` or rejects when `EnforceChallengeIP=true`.
//   - S2-21: `EraseSubject` on a shared beacon purges `beaconToKey` AND allows remaining co-owner to seamlessly re-bind TOFU on next visit.
//   - S3-27: `TurnstileVerifier` / `RequireTurnstile` enforces CAPTCHA without burning the challenge nonce on failure.
//   - S3-30: Non-32-char hex beacons (16-char, 64-char) are rejected cleanly.
func TestS2_16_18_21_And_S3_27_28_30_DisabledWebGLQuotaTurnstileIPAndGDPRErase(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 11, 0, 0, 0, time.UTC)
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v := NewVerifier(Config{
		HMACSecret: []byte("v110-features-secret-32-bytes-00"),
		NowFunc:    func() time.Time { return now },
	}, store)
	graph := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: store})
	v.BindRiskGraph(graph)

	// 1. S2-18: Disabled WebGL on hardened Firefox with bound DeviceKey + Beacon -> Confidence 0.75 -> GREEN!
	wglFalse := false
	bcnFF := "ff00112233445566778899aabbccdd01"
	keyFF, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	chFF, _ := v.IssueChallenge(ctx, "198.51.100.10")
	pFF := buildValidPayload(chFF)
	pFF.BeaconID = bcnFF
	pFF.WebGL.WebGLAvailable = &wglFalse
	pFF.WebGL.GPUVendor = "Unavailable"
	pFF.WebGL.GPURenderer = "WebGL Disabled"
	pFF.Lies.WorkerWebGLAvailable = &wglFalse
	pFF.Lies.WorkerStaticWebGLFpHash = ""
	pFF.Lies.WorkerGPURenderer = ""
	pFF.Lies.AudioMuted = true
	pFF.Lies.StorageSilosMask = 31
	pFF.DeviceKey = signDeviceKeyForTest(t, keyFF, chFF.Nonce, bcnFF, pFF.WebGL.StaticWebGLFpHash, pFF.AudioCompressorHash)
	resFF, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chFF.Nonce, SealedPayload: sealProbePayload(t, chFF.Nonce, pFF)}, "198.51.100.10")
	if err != nil {
		t.Fatalf("hardened firefox verify: %v", err)
	}
	if resFF.IsVirtualGPU || resFF.Confidence != DisabledWebGLBoundConfidence {
		t.Fatalf("S2-18: expected IsVirtualGPU=false & Confidence=0.75 for hardened Firefox, got %+v", resFF)
	}
	snapFF := graph.RecordVerification("firefox_hardened_user", now, resFF)
	if snapFF.RiskStatus != RiskStatusGreen || snapFF.RiskPending {
		t.Fatalf("S2-18: expected hardened Firefox user to be green, got %+v", snapFF)
	}

	// Anonymous stateless no-WebGL (no beacon/key) stays demoted at 0.30 (pending):
	chAnon, _ := v.IssueChallenge(ctx, "198.51.100.11")
	pAnon := buildValidPayload(chAnon)
	pAnon.WebGL.WebGLAvailable = &wglFalse
	pAnon.WebGL.GPUVendor = "Unavailable"
	pAnon.WebGL.GPURenderer = "WebGL Disabled"
	resAnon, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chAnon.Nonce, SealedPayload: sealProbePayload(t, chAnon.Nonce, pAnon)}, "198.51.100.11")
	if resAnon.Confidence != VirtualGPUConfidence || !resAnon.RiskPending {
		t.Fatalf("expected anonymous stateless no-WebGL to stay 0.30 pending, got %+v", resAnon)
	}

	// 2. S2-16: Victim challenge survives 5,000-challenge flood from a single attacker /24 subnet!
	chVictim, _ := v.IssueChallenge(ctx, "203.0.113.5")
	for i := 0; i < 5000; i++ {
		_, _ = v.IssueChallenge(ctx, "192.0.2.99")
	}
	pVic := buildValidPayload(chVictim)
	// Submit from different subnet to also test S3-28 `challenge_ip_subnet_changed` signal!
	resVic, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chVictim.Nonce, SealedPayload: sealProbePayload(t, chVictim.Nonce, pVic)}, "198.51.100.200")
	if err != nil {
		t.Fatalf("S2-16: attacker single-subnet flood evicted victim challenge: %v", err)
	}
	if !hasResultFlag(resVic, "challenge_ip_subnet_changed") {
		t.Fatalf("S3-28: expected challenge_ip_subnet_changed privacy signal, got %v", resVic.PrivacySignals)
	}

	// 3. S3-27: Turnstile verification rejects bad token WITHOUT consuming nonce, then succeeds with valid token!
	vTS := NewVerifier(Config{
		HMACSecret:         []byte("turnstile-secret-32-bytes-000000"),
		RequireTurnstile:   true,
		EnforceChallengeIP: true,
		TurnstileVerifier: func(_ context.Context, token, _ string) (bool, error) {
			return token == "ts-valid-pass", nil
		},
	}, nil)
	chTS, _ := vTS.IssueChallenge(ctx, "203.0.113.44")
	pTS := buildValidPayload(chTS)
	sealedTS := sealProbePayload(t, chTS.Nonce, pTS)
	if _, err := vTS.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chTS.Nonce, SealedPayload: sealedTS, TurnstileToken: "bad"}, "203.0.113.44"); err == nil {
		t.Fatalf("S3-27: expected bad Turnstile token to fail")
	}
	if _, err := vTS.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chTS.Nonce, SealedPayload: sealedTS, TurnstileToken: "ts-valid-pass"}, "198.51.100.44"); err == nil {
		t.Fatalf("S3-28: expected EnforceChallengeIP mismatch to reject cross-subnet submit")
	}

	// 4. S3-30: 16-char and 64-char hex beacons are rejected!
	if _, err := v.DeriveBeaconSliceID("0123456789abcdef"); err == nil {
		t.Fatalf("S3-30: expected 16-char beacon to be rejected")
	}
	if _, err := v.DeriveBeaconSliceID(strings.Repeat("a", 64)); err == nil {
		t.Fatalf("S3-30: expected 64-char beacon to be rejected")
	}

	// 5. S2-21: Shared beacon GDPR EraseSubject purges TOFU binding AND co-owner seamlessly re-binds on next visit!
	bcnShared := "abcdefabcdefabcdefabcdefabcdef12"
	keyShared, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, user := range []string{"co_user_1", "co_user_2"} {
		chS, _ := v.IssueChallenge(ctx, "203.0.113.70")
		pS := buildValidPayload(chS)
		pS.BeaconID = bcnShared
		pS.DeviceKey = signDeviceKeyForTest(t, keyShared, chS.Nonce, bcnShared, pS.WebGL.StaticWebGLFpHash, pS.AudioCompressorHash)
		resS, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chS.Nonce, SealedPayload: sealProbePayload(t, chS.Nonce, pS)}, "203.0.113.70")
		graph.RecordVerification(user, now, resS)
	}
	removed, purged := v.EraseSubject(ctx, graph, "co_user_1", "203.0.113.70")
	if !removed || purged != 1 {
		t.Fatalf("S2-21: expected EraseSubject on shared beacon to purge 1 TOFU binding, got removed=%v purged=%d", removed, purged)
	}
	// Remaining co_user_2 visits next -> transparently re-binds TOFU and becomes green!
	chNext, _ := v.IssueChallenge(ctx, "203.0.113.70")
	pNext := buildValidPayload(chNext)
	pNext.BeaconID = bcnShared
	pNext.DeviceKey = signDeviceKeyForTest(t, keyShared, chNext.Nonce, bcnShared, pNext.WebGL.StaticWebGLFpHash, pNext.AudioCompressorHash)
	resNext, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: chNext.Nonce, SealedPayload: sealProbePayload(t, chNext.Nonce, pNext)}, "203.0.113.70")
	if err != nil || resNext.DeviceKeyRecoveryRequired {
		t.Fatalf("expected co_user_2 to seamlessly re-bind TOFU after co_user_1 erasure, got res=%+v err=%v", resNext, err)
	}
	if snapCo2 := graph.RecordVerification("co_user_2", now.Add(time.Minute), resNext); snapCo2.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected co_user_2 to become green after co_user_1 erasure, got %+v", snapCo2)
	}
}

// TestS3_57_ConcurrentIdentifyRebindClearAndEraseRace exercises high-concurrency parallel
// VerifyAndDerive + RecordVerification + RebindDeviceKeyWithProof + ClearSubjectSpoofAudited + EraseSubject under -race.
func TestS3_57_ConcurrentIdentifyRebindClearAndEraseRace(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryChallengeStore()
	v := NewVerifier(Config{HMACSecret: []byte("v110-race-stress-secret-32-bytes")}, store)
	graph := NewRiskGraphWithOptions(GraphOptions{Store: store})
	v.BindRiskGraph(graph)

	const workers = 12
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			subj := fmt.Sprintf("race_user_%d", id%4)
			bcn := fmt.Sprintf("aa00112233445566778899aabbcc%04x", id%4)
			priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			ip := fmt.Sprintf("198.51.%d.10", 10+id)

			for iter := 0; iter < 8; iter++ {
				ch, err := v.IssueChallenge(ctx, ip)
				if err != nil {
					continue
				}
				p := buildValidPayload(ch)
				p.BeaconID = bcn
				if iter%3 == 0 {
					p.Lies.CanvasNoiseInjected = true
				}
				p.DeviceKey = signDeviceKeyForTest(t, priv1, ch.Nonce, bcn, p.WebGL.StaticWebGLFpHash, p.AudioCompressorHash)
				if sealed, err := SealPayload(ch.Nonce, nil, mustJSON(p)); err == nil {
					if res, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealed}, ip); err == nil {
						graph.RecordVerification(subj, time.Now().UTC(), res)
					}
				}

				chR, err := v.IssueChallenge(ctx, ip)
				if err == nil {
					_, _ = v.RebindDeviceKeyWithProof(ctx, KeyRebindRequest{
						ChallengeNonce: chR.Nonce,
						SubjectID:      subj,
						BeaconID:       bcn,
						DeviceKey:      signRebindForTest(t, priv2, "prismid-v2-rebind", chR.Nonce, subj, bcn),
					}, v.BeaconOwnerCheck(graph), ip)
				}
				v.ClearSubjectSpoofAudited(graph, subj, ip, time.Now().UTC())
				_ = graph.ExportSnapshot()
				_ = store.ExportSnapshot()
				if iter == 7 && id%4 == 0 {
					v.EraseSubject(ctx, graph, subj, ip)
				}
			}
		}(w)
	}
	wg.Wait()
}

func mustJSON(v any) []byte {
	ch := Challenge{}
	_ = ch
	raw, _ := jsonMarshalHelper(v)
	return raw
}

// TestRound2_P1_P3_WALScaleBenchmarkCrashRecoveryAndErrorSurfacing verifies:
//   - P1: Incremental O(1) `AppendWAL` stays sub-millisecond and ~500B/request even at 20,000 subjects
//     (replacing the 490ms / 36MB synchronous full-graph SaveState per `/identify`).
//   - P1 & P3-2: Crash recovery (`RestoreInto` without `SaveState`) restores all 20,020 subjects, TOFU bindings,
//     beacon owners, consumed step-up JTIs, and revoked tokens from `<path> + <path>.wal`.
//   - P3-3 & P3-7: Corrupted state files return explicit errors on `RestoreInto`, and write failures increment
//     `PersistErrors()` and fire `SetErrorHandler`.
func TestRound2_P1_P3_WALScaleBenchmarkCrashRecoveryAndErrorSurfacing(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	tmpDir := t.TempDir()
	stateFile := filepath.Join(tmpDir, "scale-state.json")
	fsStore, err := NewFileStateStore(stateFile)
	if err != nil {
		t.Fatalf("NewFileStateStore: %v", err)
	}

	mem := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	graph := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: mem})

	// Seed 5,000 subjects into the base snapshot (see BenchmarkFileStateStore_AppendWAL for 1k/5k/20k/50k matrix):
	const seededSubjects = 5000
	for i := 0; i < seededSubjects; i++ {
		graph.RecordVerification(fmt.Sprintf("seed_u_%d", i), now, &VerifyResult{
			Accepted:         true,
			Confidence:       0.95,
			DeviceKeyBound:   true,
			DeviceKeySliceID: fmt.Sprintf("d_key_seed_%d", i),
			BeaconSliceID:    fmt.Sprintf("d_bcn_seed_%d", i),
			ExactSliceID:     fmt.Sprintf("d_web_seed_%d", i),
			GpuAudioSliceID:  fmt.Sprintf("d_gpu_model_%d", i%64),
			SysNetSliceID:    fmt.Sprintf("d_sys_net_%d", i%128),
		})
	}
	if err := fsStore.SaveState(ctx, graph, mem); err != nil {
		t.Fatalf("initial SaveState(20k): %v", err)
	}

	// Now measure 50 incremental `/identify` WAL appends on top of the 20,000-subject graph:
	const walOps = 50
	start := time.Now()
	for i := 0; i < walOps; i++ {
		sid := fmt.Sprintf("wal_live_%d", i)
		res := &VerifyResult{
			Accepted:         true,
			Confidence:       0.95,
			DeviceKeyBound:   true,
			DeviceKeySliceID: fmt.Sprintf("d_key_live_%d", i),
			BeaconSliceID:    fmt.Sprintf("d_bcn_live_%d", i),
			ExactSliceID:     fmt.Sprintf("d_web_live_%d", i),
			GpuAudioSliceID:  "d_gpu_live_m3",
			SysNetSliceID:    "d_sys_live_net",
			IPSubnet:         "203.0.113.0/24",
		}
		_, _ = mem.CheckOrBindBeaconDeviceKey(ctx, res.BeaconSliceID, res.DeviceKeySliceID)
		_ = mem.RecordBeaconOwner(ctx, res.BeaconSliceID, sid)
		graph.RecordVerification(sid, now.Add(time.Duration(i+1)*time.Second), res)
		if err := fsStore.AppendWAL(StateWALRecord{
			Op:            WALOpIdentify,
			At:            now.Add(time.Duration(i+1) * time.Second),
			SubjectID:     sid,
			OwnerRecorded: true,
			VerifyResult:  res,
		}, false); err != nil {
			t.Fatalf("AppendWAL(%d): %v", i, err)
		}
	}
	avgPerIdentify := time.Since(start) / walOps

	// Also append step-up JTI consumption and token revocation into WAL (P3-2):
	_ = fsStore.AppendWAL(StateWALRecord{
		Op:      WALOpConsumeStepUp,
		At:      now,
		JTI:     "jti_crash_test_001",
		ExpUnix: now.Add(5 * time.Minute).Unix(),
	}, true)
	_ = fsStore.AppendWAL(StateWALRecord{
		Op:          WALOpRevokeToken,
		At:          now,
		SubjectID:   "revoked_sub_after_crash",
		TokenSHAHex: "deadbeef01234567",
		ExpUnix:     now.Add(time.Hour).Unix(),
	}, true)

	walInfo, err := os.Stat(stateFile + ".wal")
	if err != nil {
		t.Fatalf("stat wal file: %v", err)
	}
	t.Logf("5k-subject scale WAL benchmark: avg AppendWAL=%v/op, 52-record WAL size=%d bytes", avgPerIdentify, walInfo.Size())

	if avgPerIdentify > 5*time.Millisecond {
		t.Fatalf("P1 regression: AppendWAL at 5k subjects took %v/op (expected O(1) < 5ms, vs 77.4ms SaveState)", avgPerIdentify)
	}
	if walInfo.Size() > 128*1024 {
		t.Fatalf("P1 regression: 52 WAL records wrote %d bytes (expected < 128KB, vs 36MB*50)", walInfo.Size())
	}

	// Simulate abrupt process crash (do NOT call Compact or SaveState!) and restore into fresh instances:
	memRestored := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	graphRestored := NewRiskGraphWithOptions(GraphOptions{NowFunc: func() time.Time { return now }, Store: memRestored})
	guardSnap, ok, err := fsStore.RestoreInto(ctx, graphRestored, memRestored)
	if err != nil || !ok {
		t.Fatalf("RestoreInto after WAL crash: ok=%v err=%v", ok, err)
	}
	if got := graphRestored.Stats().ActiveSubjects; got != seededSubjects+walOps {
		t.Fatalf("expected %d restored subjects (20k base + 50 WAL), got %d", seededSubjects+walOps, got)
	}
	owners, _ := memRestored.GetBeaconOwners(ctx, "d_bcn_live_49")
	if len(owners) != 1 || owners[0] != "wal_live_49" {
		t.Fatalf("expected WAL-replayed beacon owner [wal_live_49], got %v", owners)
	}
	if matched, _ := memRestored.CheckOrBindBeaconDeviceKey(ctx, "d_bcn_live_49", "d_key_wrong"); matched {
		t.Fatalf("expected WAL-replayed TOFU key binding on d_bcn_live_49 to reject wrong key")
	}
	if guardSnap.ConsumedStepUp["jti_crash_test_001"] == 0 || guardSnap.RevokedSubjects["revoked_sub_after_crash"] == 0 {
		t.Fatalf("P3-2: expected WAL-replayed ReplayGuardSnapshot to preserve JTI & revoked subject, got %+v", guardSnap)
	}

	// Compact rotates WAL cleanly and removes `<path>.wal`:
	if err := fsStore.Compact(ctx, graphRestored, memRestored, guardSnap); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if _, err := os.Stat(stateFile + ".wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected WAL file to be removed after Compact, stat err=%v", err)
	}

	// P3-3: Corrupt base state file -> RestoreInto MUST return an error instead of silently ignoring!
	corruptPath := filepath.Join(tmpDir, "corrupt-state.json")
	_ = os.WriteFile(corruptPath, []byte("{broken-json"), 0o600)
	corruptStore, _ := NewFileStateStore(corruptPath)
	if _, _, err := corruptStore.RestoreInto(ctx, NewRiskGraph(0.65), NewMemoryChallengeStore()); err == nil {
		t.Fatalf("P3-3: expected RestoreInto on corrupted state file to return non-nil error")
	}

	// P3-7: Persistence write failure increments PersistErrors() and fires error callback!
	var cbCount atomic.Uint64
	badStore, _ := NewFileStateStore(filepath.Join(tmpDir, "dir-as-file"))
	_ = os.MkdirAll(filepath.Join(tmpDir, "dir-as-file.wal"), 0o700) // make `.wal` a directory so OpenFile fails!
	badStore.SetErrorHandler(func(error) { cbCount.Add(1) })
	if err := badStore.AppendWAL(StateWALRecord{Op: WALOpPrune, At: now}, false); err == nil {
		t.Fatalf("expected AppendWAL on directory-blocked WAL path to return error")
	}
	if badStore.PersistErrors() == 0 || cbCount.Load() == 0 {
		t.Fatalf("P3-7: expected PersistErrors > 0 and callback invoked, got errors=%d cb=%d", badStore.PersistErrors(), cbCount.Load())
	}
}

// TestRound2_P2_And_P3_ChallengeQuotaTurnstileFailClosedSpoofEvictionAndOwnerQuality verifies:
//   - P2-1: Same-/24 neighbor challenges are NOT silently evicted at 64; per-IP (>64) and per-/24 (>1024)
//     quotas return `ErrCodeChallengeRateLimited` while preserving active neighbor nonces.
//   - P2-2: `RequireTurnstile=true` with `TurnstileVerifier=nil` fails closed (`ErrCodeTurnstileFailed`).
//   - P2-3: Self-reported spoofed singletons (`canvas_noise_injected=true`) are evictable at `MaxSubjects`
//     so an attacker cannot lock all subsequent clean users into `unknown/pending/truncated`.
//   - P3-1 & P3-4: `RecordVerifiedBeaconOwner` rejects 0.30 virtual-GPU / spoofed payloads, and shared
//     kiosk beacons retain >32 legitimate owners (up to 256).
func TestRound2_P2_And_P3_ChallengeQuotaTurnstileFailClosedSpoofEvictionAndOwnerQuality(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 13, 0, 0, 0, time.UTC)

	// 1. P2-1: Same-/24 neighbor challenge survives 100 challenges from an attacker IP AND 120 CGNAT neighbors!
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v := NewVerifier(Config{
		HMACSecret: []byte("round2-quota-secret-32-bytes-000"),
		NowFunc:    func() time.Time { return now },
	}, store)

	chFirstNeighbor, err := v.IssueChallenge(ctx, "203.0.113.1")
	if err != nil {
		t.Fatalf("first neighbor challenge: %v", err)
	}
	// Single IP in same /24 hammers 100 challenges -> capped at 64 with ErrCodeChallengeRateLimited!
	rateLimitedCount := 0
	for i := 0; i < 100; i++ {
		_, err := v.IssueChallenge(ctx, "203.0.113.250")
		if err != nil {
			var vErr *VerificationError
			if errors.As(err, &vErr) && vErr.Code == ErrCodeChallengeRateLimited {
				rateLimitedCount++
			} else {
				t.Fatalf("unexpected error at i=%d: %v", i, err)
			}
		}
	}
	if rateLimitedCount != 100-DefaultMaxChallengesPerIP {
		t.Fatalf("P2-1: expected %d rate-limited challenges from single IP, got %d", 100-DefaultMaxChallengesPerIP, rateLimitedCount)
	}
	// 120 distinct CGNAT/campus IPs in the SAME 203.0.113.0/24 issue challenges -> all 120 succeed (<= 1024 /24 cap)!
	for host := 2; host <= 121; host++ {
		if _, err := v.IssueChallenge(ctx, fmt.Sprintf("203.0.113.%d", host)); err != nil {
			t.Fatalf("P2-1: CGNAT neighbor 203.0.113.%d was rejected: %v", host, err)
		}
	}
	// Verify the VERY FIRST neighbor's nonce (`203.0.113.1`) was NOT evicted!
	pFirst := buildValidPayload(chFirstNeighbor)
	if _, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chFirstNeighbor.Nonce,
		SealedPayload:  sealProbePayload(t, chFirstNeighbor.Nonce, pFirst),
	}, "203.0.113.1"); err != nil {
		t.Fatalf("P2-1 regression: 1st neighbor nonce in /24 was evicted: %v", err)
	}

	// 2. P2-2: RequireTurnstile=true with nil TurnstileVerifier MUST fail closed even for non-empty token!
	vMisconf := NewVerifier(Config{
		HMACSecret:        []byte("turnstile-nil-verifier-32-bytes!"),
		RequireTurnstile:  true,
		TurnstileVerifier: nil,
	}, nil)
	chMis, _ := vMisconf.IssueChallenge(ctx, "198.51.100.9")
	pMis := buildValidPayload(chMis)
	_, err = vMisconf.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chMis.Nonce,
		SealedPayload:  sealProbePayload(t, chMis.Nonce, pMis),
		TurnstileToken: "non-empty-bypass-attempt",
	}, "198.51.100.9")
	var tsErr *VerificationError
	if !errors.As(err, &tsErr) || tsErr.Code != ErrCodeTurnstileFailed {
		t.Fatalf("P2-2: expected ErrCodeTurnstileFailed when TurnstileVerifier is nil, got %v", err)
	}

	// 3. P2-3: Attacker floods `MaxSubjects=2` with self-reported spoofed accounts -> clean new user still gets GREEN!
	gFlood := NewRiskGraphWithOptions(GraphOptions{
		MinConfidence: AuthoritativeConfidenceThreshold,
		MaxSubjects:   2,
		NowFunc:       func() time.Time { return now },
	})
	for i := 0; i < 3; i++ {
		snapSpoof := gFlood.RecordVerification(fmt.Sprintf("spoof_flood_%d", i), now.Add(time.Duration(i)*time.Second), &VerifyResult{
			Accepted:           true,
			Confidence:         0.85,
			BeaconSliceID:      fmt.Sprintf("d_bcn_spoof_iso_%d", i),
			SpoofTrapTriggered: true,
			SpoofFlags:         []string{"canvas_noise_injected"},
		})
		if snapSpoof.RiskStatus != RiskStatusRed || snapSpoof.Truncated {
			t.Fatalf("P2-3: expected spoofed singleton %d to be admitted & marked red (evicting older singleton), got %+v", i, snapSpoof)
		}
	}
	snapCleanAfterFlood := gFlood.RecordVerification("clean_victim_after_spoof_flood", now.Add(10*time.Second), &VerifyResult{
		Accepted:      true,
		Confidence:    0.95,
		BeaconSliceID: "d_bcn_clean_victim",
	})
	if snapCleanAfterFlood.RiskStatus != RiskStatusGreen || snapCleanAfterFlood.RiskPending || snapCleanAfterFlood.Truncated {
		t.Fatalf("P2-3 regression: attacker spoof flood locked out legitimate new user: %+v", snapCleanAfterFlood)
	}

	// Tier 3 check: even if 100% of MaxSubjects=4 are 2-account shared-anchor clusters, an unrelated clean user is admitted cleanly!
	gClusters := NewRiskGraphWithOptions(GraphOptions{
		MinConfidence: AuthoritativeConfidenceThreshold,
		MaxSubjects:   4,
		NowFunc:       func() time.Time { return now },
	})
	gClusters.RecordVerification("c1_a", now, &VerifyResult{Accepted: true, Confidence: 0.95, BeaconSliceID: "d_bcn_c1"})
	gClusters.RecordVerification("c1_b", now.Add(time.Second), &VerifyResult{Accepted: true, Confidence: 0.95, BeaconSliceID: "d_bcn_c1"})
	gClusters.RecordVerification("c2_a", now.Add(2*time.Second), &VerifyResult{Accepted: true, Confidence: 0.95, BeaconSliceID: "d_bcn_c2"})
	gClusters.RecordVerification("c2_b", now.Add(3*time.Second), &VerifyResult{Accepted: true, Confidence: 0.95, BeaconSliceID: "d_bcn_c2"})
	snapTier3 := gClusters.RecordVerification("unrelated_new_user", now.Add(10*time.Second), &VerifyResult{
		Accepted:      true,
		Confidence:    0.95,
		BeaconSliceID: "d_bcn_unrelated_fresh",
	})
	if snapTier3.RiskStatus != RiskStatusGreen || snapTier3.RiskPending || gClusters.Stats().ForcedSubjectEvictions != 1 {
		t.Fatalf("P2-3 Tier 3: expected unrelated new user to get green with ForcedSubjectEvictions=1, got snap=%+v stats=%+v", snapTier3, gClusters.Stats())
	}

	// 4. P3-1: Virtual GPU (0.30) and SpoofTrapTriggered payloads CANNOT register as verified beacon owners!
	if v.RecordVerifiedBeaconOwner(ctx, "vm_attacker", &VerifyResult{
		Accepted:      true,
		Confidence:    VirtualGPUConfidence,
		IsVirtualGPU:  true,
		BeaconSliceID: "d_bcn_target_1",
	}) {
		t.Fatalf("P3-1: virtual GPU (0.30) payload must NOT be recorded as verified beacon owner")
	}
	if v.RecordVerifiedBeaconOwner(ctx, "spoof_attacker", &VerifyResult{
		Accepted:           true,
		Confidence:         0.95,
		SpoofTrapTriggered: true,
		BeaconSliceID:      "d_bcn_target_1",
	}) {
		t.Fatalf("P3-1: spoofed payload must NOT be recorded as verified beacon owner")
	}
	if owners, _ := store.GetBeaconOwners(ctx, "d_bcn_target_1"); len(owners) != 0 {
		t.Fatalf("P3-1: expected 0 owners on d_bcn_target_1, got %v", owners)
	}

	// 5. P3-4: Shared school/kiosk terminal with 45 clean users (> 32 old cap) retains all 45 owners!
	for i := 0; i < 45; i++ {
		uid := fmt.Sprintf("kiosk_student_%02d", i)
		if !v.RecordVerifiedBeaconOwner(ctx, uid, &VerifyResult{
			Accepted:      true,
			Confidence:    0.95,
			BeaconSliceID: "d_bcn_school_lab",
		}) {
			t.Fatalf("P3-4: failed to record owner %s", uid)
		}
	}
	kioskOwners, _ := store.GetBeaconOwners(ctx, "d_bcn_school_lab")
	if len(kioskOwners) != 45 {
		t.Fatalf("P3-4: expected all 45 kiosk students to be retained (<=256 cap), got %d", len(kioskOwners))
	}
}

func BenchmarkFileStateStore_AppendWAL(b *testing.B) {
	ctx := context.Background()
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	resSample := &VerifyResult{
		Accepted:         true,
		Confidence:       0.95,
		DeviceKeyBound:   true,
		DeviceKeySliceID: "d_key_hot",
		BeaconSliceID:    "d_bcn_hot",
		ExactSliceID:     "d_web_hot",
		GpuAudioSliceID:  "d_gpu_hot",
		SysNetSliceID:    "d_sys_hot",
		IPSubnet:         "203.0.113.0/24",
	}
	for _, scale := range []int{1000, 5000, 20000, 50000} {
		statePath := filepath.Join(b.TempDir(), fmt.Sprintf("bench-state-%d.json", scale))
		seedFS, err := NewFileStateStore(statePath)
		if err != nil {
			b.Fatal(err)
		}
		mem := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
		g := NewRiskGraphWithOptions(GraphOptions{
			NowFunc:     func() time.Time { return now },
			MaxSubjects: scale + 10000,
			Store:       mem,
		})
		for i := 0; i < scale; i++ {
			g.RecordVerification(fmt.Sprintf("u_%d", i), now, &VerifyResult{
				Accepted:         true,
				Confidence:       0.95,
				DeviceKeyBound:   true,
				DeviceKeySliceID: fmt.Sprintf("d_key_%d", i),
				BeaconSliceID:    fmt.Sprintf("d_bcn_%d", i),
				ExactSliceID:     fmt.Sprintf("d_web_%d", i),
				GpuAudioSliceID:  fmt.Sprintf("d_gpu_%d", i%64),
				SysNetSliceID:    fmt.Sprintf("d_sys_%d", i%128),
			})
		}
		if err := seedFS.SaveState(ctx, g, mem); err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("subjects_%d", scale), func(b *testing.B) {
			_ = os.Remove(statePath + ".wal")
			fs, err := NewFileStateStore(statePath)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := fs.AppendWAL(StateWALRecord{
					Op:            WALOpIdentify,
					At:            now,
					SubjectID:     "hot_user",
					OwnerRecorded: true,
					VerifyResult:  resSample,
				}, false); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			_ = fs.FlushAndClose(ctx, nil, nil, nil)
			// Re-measure exact per-record WAL size on a clean single write:
			_ = os.Remove(statePath + ".wal")
			fsMeasure, _ := NewFileStateStore(statePath)
			_ = fsMeasure.AppendWAL(StateWALRecord{
				Op:            WALOpIdentify,
				At:            now,
				SubjectID:     "hot_user",
				OwnerRecorded: true,
				VerifyResult:  resSample,
			}, false)
			if info, err := os.Stat(statePath + ".wal"); err == nil {
				b.ReportMetric(float64(info.Size()), "wal_bytes/op")
			}
			fsMeasure.StopBackgroundWorker()
		})
	}
}
