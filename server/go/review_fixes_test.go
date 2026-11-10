package prismid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func signReviewPayload(t *testing.T, payload *ProbePayload, key *ecdsa.PrivateKey) {
	t.Helper()
	transcript := strings.Join([]string{"prismid-v2-sig", payload.Nonce,
		strings.ToLower(payload.BeaconID), strings.ToLower(payload.WebGL.StaticWebGLFpHash),
		strings.ToLower(payload.AudioCompressorHash)}, "|")
	digest := sha256.Sum256([]byte(transcript))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	payload.DeviceKey = &DeviceKeyProof{Alg: "ecdsa-p256",
		PubKey:    hex.EncodeToString(elliptic.Marshal(elliptic.P256(), key.X, key.Y)),
		Signature: hex.EncodeToString(sig)}
}

func TestReviewFix_KeyLossRequiresRecoveryWithoutPoisoning(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(fmt.Sprintf("missing=%v", missing), func(t *testing.T) {
			ctx := context.Background()
			v := NewVerifier(Config{HMACSecret: []byte("review-test-secret")}, nil)
			original, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			replacement, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			verify := func(key *ecdsa.PrivateKey) *VerifyResult {
				ch, err := v.IssueChallenge(ctx, "198.51.100.1")
				if err != nil {
					t.Fatal(err)
				}
				payload := buildValidPayload(ch)
				payload.BeaconID = "1234567890abcdef1234567890abcdef"
				if key != nil {
					signReviewPayload(t, &payload, key)
				}
				res, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce,
					SealedPayload: sealProbePayload(t, ch.Nonce, payload)}, "198.51.100.1")
				if err != nil {
					t.Fatal(err)
				}
				return res
			}
			g := NewRiskGraph(.6)
			t0 := time.Now()
			first := verify(original)
			g.RecordVerification("owner", t0, first)
			var res *VerifyResult
			if missing {
				res = verify(nil)
			} else {
				res = verify(replacement)
			}
			if res.SpoofTrapTriggered || res.Confidence >= AuthoritativeConfidenceThreshold {
				t.Fatalf("lost/replaced key must require recovery, not spoof or authoritative identity: %+v", res)
			}
			snap := g.RecordVerification("owner", t0, res)
			if !snap.RiskPending || snap.RiskStatus != RiskStatusUnknown {
				t.Fatalf("current request must wait for recovery: %+v", snap)
			}
			if restored := verify(original); restored.SpoofTrapTriggered || !restored.DeviceKeyAttested {
				t.Fatalf("recovery attempt changed original binding: %+v", restored)
			}
			if old := g.EvaluateSubject("owner"); old.RiskStatus != RiskStatusGreen {
				t.Fatalf("recovery attempt poisoned retained history: %+v", old)
			}
		})
	}
}

func TestReviewFix_CapacityNeverRestoresGreen(t *testing.T) {
	t0 := time.Now()
	t.Run("slice fanout", func(t *testing.T) {
		g := NewRiskGraph(.6)
		for i := 0; i <= MaxSubjectsPerSlice; i++ {
			g.RecordVerification(fmt.Sprintf("user%03d", i), t0.Add(time.Duration(i)*time.Minute),
				&VerifyResult{Accepted: true, Confidence: .95, BeaconSliceID: "d_bcn_shared",
					ExactSliceID: fmt.Sprintf("d_web_%d", i)})
		}
		for _, id := range []string{"user001", "user000", "user256"} {
			snap := g.EvaluateSubject(id)
			if !snap.Truncated || !snap.RiskPending || snap.RiskStatus == RiskStatusGreen || snap.EarliestSubjectID != "" {
				t.Fatalf("%s lost evidence without uncertainty: %+v", id, snap)
			}
		}
	})
	t.Run("subject slices", func(t *testing.T) {
		g := NewRiskGraph(.6)
		for i := 0; i <= MaxSlicesPerSubject; i++ {
			g.RecordVerification("owner", t0, &VerifyResult{Accepted: true, Confidence: .95,
				BeaconSliceID: fmt.Sprintf("d_bcn_%d", i)})
		}
		snap := g.EvaluateSubject("owner")
		if !snap.Truncated || !snap.RiskPending || snap.RiskStatus == RiskStatusGreen {
			t.Fatalf("per-subject eviction must be explicit: %+v", snap)
		}
		// A later observation of an evicted anchor must also retain the uncertainty.
		for i := 0; i <= MaxSlicesPerSubject; i++ {
			id := fmt.Sprintf("neighbor%d", i)
			g.RecordVerification(id, t0.Add(time.Hour), &VerifyResult{Accepted: true, Confidence: .95,
				BeaconSliceID: fmt.Sprintf("d_bcn_%d", i)})
			if snap := g.EvaluateSubject(id); snap.RiskStatus == RiskStatusGreen && !snap.RiskPending {
				t.Fatalf("forgotten anchor became clean for new observer: %+v", snap)
			}
		}
	})
	t.Run("global subjects", func(t *testing.T) {
		g := NewRiskGraph(.6)
		g.maxSubjects = 2
		for _, id := range []string{"first", "second", "third"} {
			snap := g.RecordVerification(id, t0, &VerifyResult{Accepted: true, Confidence: .95, BeaconSliceID: "d_bcn_all"})
			if id == "third" && (!snap.Truncated || !snap.RiskPending) {
				t.Fatalf("full cache must apply backpressure: %+v", snap)
			}
		}
		if _, ok := g.subjectEdges["first"]; !ok {
			t.Fatal("capacity deleted trusted history")
		}
	})
}

func TestReviewFix_MixedIdentityChainIsComplete(t *testing.T) {
	g := NewRiskGraph(.6)
	t0 := time.Now()
	g.RecordVerification("A", t0, &VerifyResult{Accepted: true, Confidence: .95, BeaconSliceID: "d_bcn_A", GpuAudioSliceID: "d_gpu_shared", SysNetSliceID: "d_sys_shared"})
	g.RecordVerification("B", t0.Add(time.Minute), &VerifyResult{Accepted: true, Confidence: .85, BeaconSliceID: "d_bcn_BC", GpuAudioSliceID: "d_gpu_shared", SysNetSliceID: "d_sys_shared", SpoofTrapTriggered: true})
	g.RecordVerification("C", t0.Add(2*time.Minute), &VerifyResult{Accepted: true, Confidence: .95, BeaconSliceID: "d_bcn_BC", GpuAudioSliceID: "d_gpu_C", SysNetSliceID: "d_sys_C"})
	for _, id := range []string{"A", "B", "C"} {
		snap := g.EvaluateSubject(id)
		if !reflect.DeepEqual(snap.ComponentSubjects, []string{"A", "B", "C"}) || snap.Truncated {
			t.Fatalf("%s sees incomplete mixed chain: %+v", id, snap)
		}
	}
	if snapA := g.EvaluateSubject("A"); snapA.RiskStatus != RiskStatusYellow || !snapA.RiskPending {
		t.Fatalf("expected clean-beacon peer A on same /24 within 25m to be capped at yellow+pending, got %+v", snapA)
	}
	if snapB := g.EvaluateSubject("B"); snapB.RiskStatus != RiskStatusRed {
		t.Fatalf("expected spoofed B to be red, got %+v", snapB)
	}
	if snapC := g.EvaluateSubject("C"); snapC.RiskStatus != RiskStatusRed {
		t.Fatalf("expected hard-beacon-linked C to be red, got %+v", snapC)
	}
}
