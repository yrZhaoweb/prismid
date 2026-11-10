package prismid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func buildValidPayload(ch *Challenge) ProbePayload {
	spots := ComputeAllExpectedSpotPixels(ch.SamplePoints, ch.RenderSeed)
	return ProbePayload{
		Version:     1,
		Nonce:       ch.Nonce,
		CollectedAt: time.Now().UnixMilli(),
		WebGL: WebGLProbeData{
			GPUVendor:         "Apple",
			GPURenderer:       "Apple M1 Pro",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|a1b2c3d4",
			StaticWebGLFpHash: "7c4a8d09ca3762af61e59520943dc26494f8941b00112233445566778899aabb",
			SpotPixels:        spots,
		},
		AudioCompressorHash: "4a9e8b7c6d5f4e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a",
		System: SystemProbeData{
			UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			Platform:        "MacIntel",
			CPUCores:        10,
			DeviceMemory:    8,
			Timezone:        "Asia/Shanghai",
			Languages:       []string{"zh-CN", "en-US"},
			ScreenSpec:      "1728x1117x30@2",
			Canvas2DHash:    "8f3d2a1b9c0e7f6a5b4c3d2e1f0a9b8c",
			FontsBitmapHash: "1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f",
		},
		Lies: LieProbeData{
			WorkerUnavailable:       false,
			WorkerLieDetected:       false,
			WorkerGPURenderer:       "Apple M1 Pro",
			WorkerStaticWebGLFpHash: "7c4a8d09ca3762af61e59520943dc26494f8941b00112233445566778899aabb",
			WorkerCPUCores:          10,
			WorkerPlatform:          "MacIntel",
			WorkerUserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
			MathEngineSignature:     "v8",
			MathConstantsHash:       "b9f8e7d6c5b4a392",
		},
	}
}

func sealProbePayload(t *testing.T, nonce string, payload ProbePayload) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sealed, err := SealPayload(nonce, nil, raw)
	if err != nil {
		t.Fatalf("seal payload: %v", err)
	}
	return sealed
}

// Vector 1: Normal genuine device passes first-time verification with 3 orthogonal slices.
func TestVector1_GenuineDevicePasses(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	ch, err := v.IssueChallenge(ctx, "203.0.113.10")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	payload := buildValidPayload(ch)
	// Simulate ±1 hardware SFU rounding difference on channel 0 of sample 0
	if payload.WebGL.SpotPixels[0][0] < 254 {
		payload.WebGL.SpotPixels[0][0]++
	}
	sealed := sealProbePayload(t, ch.Nonce, payload)

	res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealed,
	}, "203.0.113.10")
	if err != nil {
		t.Fatalf("VerifyAndDerive failed: %v", err)
	}

	if !res.Accepted {
		t.Fatalf("expected Accepted=true")
	}
	if res.Confidence < 0.90 {
		t.Fatalf("expected Confidence >= 0.90, got %v", res.Confidence)
	}
	if !strings.HasPrefix(res.ExactSliceID, "d_web_") {
		t.Fatalf("expected d_web_ prefix, got %s", res.ExactSliceID)
	}
	if !strings.HasPrefix(res.GpuAudioSliceID, "d_gpu_") {
		t.Fatalf("expected d_gpu_ prefix, got %s", res.GpuAudioSliceID)
	}
	if !strings.HasPrefix(res.SysNetSliceID, "d_sys_") {
		t.Fatalf("expected d_sys_ prefix, got %s", res.SysNetSliceID)
	}
	if res.IsVirtualGPU || res.SpoofTrapTriggered {
		t.Fatalf("unexpected flags: IsVirtualGPU=%v SpoofTrapTriggered=%v", res.IsVirtualGPU, res.SpoofTrapTriggered)
	}
}

// Vector 2: Challenge nonce replay attack is 100% blocked on second submission.
func TestVector2_NonceReplayBlocked(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	ch, err := v.IssueChallenge(ctx, "203.0.113.11")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	sealed := sealProbePayload(t, ch.Nonce, buildValidPayload(ch))

	// First submission succeeds
	if _, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealed,
	}, "203.0.113.11"); err != nil {
		t.Fatalf("first VerifyAndDerive failed: %v", err)
	}

	// Second submission with same nonce & ciphertext is rejected
	_, err = v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealed,
	}, "203.0.113.12")
	if err == nil {
		t.Fatalf("expected replay attack to fail, but got nil error")
	}
	vErr, ok := err.(*VerificationError)
	if !ok || vErr.Code != ErrCodeChallengeInvalid {
		t.Fatalf("expected error code %s, got %v", ErrCodeChallengeInvalid, err)
	}
}

// Vector 3: Headless Python script fabricating random spot pixels is 100% blocked.
func TestVector3_RandomScriptShaderMismatchBlocked(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	ch, err := v.IssueChallenge(ctx, "203.0.113.15")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}

	payload := buildValidPayload(ch)
	// Script fabricates bogus RGBA values
	payload.WebGL.SpotPixels[3] = [4]uint8{
		payload.WebGL.SpotPixels[3][0] ^ 0x7F,
		payload.WebGL.SpotPixels[3][1] ^ 0x3F,
		payload.WebGL.SpotPixels[3][2],
		255,
	}
	sealed := sealProbePayload(t, ch.Nonce, payload)

	_, err = v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealed,
	}, "203.0.113.15")
	if err == nil {
		t.Fatalf("expected random pixel script to fail, got nil")
	}
	vErr, ok := err.(*VerificationError)
	if !ok || vErr.Code != ErrCodeShaderPixelMismatch {
		t.Fatalf("expected %s, got %v", ErrCodeShaderPixelMismatch, err)
	}
}

// Vector 4: Anti-detect browser mutating Canvas 2D, fonts, screen resolution,gpu_renderer text,
// AND switching across different /24 residential proxy IPs STILL produces the exact same d_gpu_*!
// Also verifies Chrome (deviceMemory=8) vs macOS Tauri WKWebView (deviceMemory=0/undefined) and
// dual-monitor screen change produce the exact same d_sys_* on the same /24 subnet!
func TestVector4_AntiDetectBrowserAndResidentialProxyLockedByGpuSlice(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	// Account 1 on Residential Proxy IP 1 (198.51.100.10)
	ch1, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p1 := buildValidPayload(ch1)
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch1.Nonce,
		SealedPayload:  sealProbePayload(t, ch1.Nonce, p1),
	}, "198.51.100.10")
	if err != nil {
		t.Fatalf("Account 1 verify failed: %v", err)
	}

	// Account 2 on completely different Residential Proxy IP 2 (203.0.113.250),
	// with randomized Canvas 2D, randomized Fonts, different Screen resolution, and spoofed gpu_renderer string!
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.250")
	p2 := buildValidPayload(ch2)
	p2.System.Canvas2DHash = "mutated_canvas_noise_99999999"
	p2.System.FontsBitmapHash = "mutated_fonts_subset_88888888"
	p2.System.ScreenSpec = "2560x1440x24@1"
	p2.WebGL.GPURenderer = "Apple M3 Max" // Attacker changed the text string
	p2.Lies.WorkerGPURenderer = "Apple M3 Max"

	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch2.Nonce,
		SealedPayload:  sealProbePayload(t, ch2.Nonce, p2),
	}, "203.0.113.250")
	if err != nil {
		t.Fatalf("Account 2 verify failed: %v", err)
	}

	if res1.ExactSliceID == res2.ExactSliceID {
		t.Fatalf("expected d_web_* to differ when canvas/fonts/screen changed")
	}
	if res1.SysNetSliceID == res2.SysNetSliceID {
		t.Fatalf("expected d_sys_* to differ when /24 IP changed")
	}
	// CRITICAL INVARIANT: d_gpu_* MUST BE 100% IDENTICAL!
	if res1.GpuAudioSliceID != res2.GpuAudioSliceID {
		t.Fatalf("d_gpu_* mismatch across proxy & canvas mutation: %s vs %s", res1.GpuAudioSliceID, res2.GpuAudioSliceID)
	}

	// Also verify Chrome (deviceMemory=8, screen 1728x1117) vs Tauri WKWebView (deviceMemory=0, external monitor 3840x2160)
	// on the same Mac & same /24 IP produce the EXACT SAME d_sys_*!
	ch3, _ := v.IssueChallenge(ctx, "198.51.100.88")
	p3 := buildValidPayload(ch3)
	p3.System.DeviceMemory = 0 // undefined in macOS WKWebView
	p3.System.ScreenSpec = "3840x2160x30@2"
	p3.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "FD7FC36D-1111-2222-3333-444455556666",
		SerialNumber:   "T41KH4C9TF",
		KeychainAnchor: "kc_anchor_001",
		CPUCores:       10,
	}
	res3, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch3.Nonce,
		SealedPayload:  sealProbePayload(t, ch3.Nonce, p3),
	}, "198.51.100.88")
	if err != nil {
		t.Fatalf("Account 3 (Tauri WKWebView) verify failed: %v", err)
	}
	if res1.SysNetSliceID != res3.SysNetSliceID {
		t.Fatalf("expected Chrome and Tauri WKWebView on same Mac & /24 IP to share d_sys_*, got %s vs %s", res1.SysNetSliceID, res3.SysNetSliceID)
	}
}

// Vector 5: Main-thread window.navigator / WebGL is hooked, but inline Web Worker + OffscreenCanvas
// captures the real unhooked GPU hash and triggers worker_lie_detected while preserving the true d_gpu_*!
func TestVector5_WorkerOffscreenCanvasDetectsMainThreadHook(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	// Baseline honest report on the machine
	chBase, _ := v.IssueChallenge(ctx, "198.51.100.1")
	pBase := buildValidPayload(chBase)
	resBase, _ := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chBase.Nonce,
		SealedPayload:  sealProbePayload(t, chBase.Nonce, pBase),
	}, "198.51.100.1")

	// Attacker uses an extension that hooks main-thread WebGL & navigator,
	// but forgets or fails to hook the inline Blob Worker's OffscreenCanvas!
	chHook, _ := v.IssueChallenge(ctx, "203.0.113.99")
	pHook := buildValidPayload(chHook)
	pHook.WebGL.GPURenderer = "Fake Hooked Renderer XYZ"
	pHook.WebGL.StaticWebGLFpHash = "fake_hooked_main_thread_hash_0000000000000000"
	pHook.System.CPUCores = 32
	// Worker still sees the true hardware:
	pHook.Lies.WorkerGPURenderer = "Apple M1 Pro"
	pHook.Lies.WorkerStaticWebGLFpHash = pBase.WebGL.StaticWebGLFpHash
	pHook.Lies.WorkerCPUCores = 10

	resHook, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chHook.Nonce,
		SealedPayload:  sealProbePayload(t, chHook.Nonce, pHook),
	}, "203.0.113.99")
	if err != nil {
		t.Fatalf("VerifyAndDerive failed: %v", err)
	}

	if !resHook.SpoofTrapTriggered {
		t.Fatalf("expected SpoofTrapTriggered=true when main thread differs from Worker")
	}
	foundFlag := false
	for _, f := range resHook.SpoofFlags {
		if f == "worker_lie_detected" {
			foundFlag = true
		}
	}
	if !foundFlag {
		t.Fatalf("expected worker_lie_detected in SpoofFlags, got %v", resHook.SpoofFlags)
	}
	// Because the verifier substitutes Worker's OffscreenCanvas hash, d_gpu_* STILL matches the baseline machine!
	if resHook.GpuAudioSliceID != resBase.GpuAudioSliceID {
		t.Fatalf("expected Worker OffscreenCanvas fallback to preserve d_gpu_*: got %s, want %s", resHook.GpuAudioSliceID, resBase.GpuAudioSliceID)
	}
}

// Vector 6: Spoofing gpu_renderer as "Apple M3 Max" while carrying Windows platform or non-[1,1] line width
// triggers gpu_register_law_violation.
func TestVector6_GPURegisterLawViolationDetected(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{
		HMACSecret:              []byte("test-secret-key-32-bytes-long-000"),
		RejectOnGPULawViolation: true,
	}, nil)

	ch, _ := v.IssueChallenge(ctx, "203.0.113.50")
	p := buildValidPayload(ch)
	p.WebGL.GPURenderer = "Apple M3 Max"
	p.System.Platform = "Win32"
	// Line width 1,10 violates Apple Silicon Metal law [1,1]
	p.WebGL.WebGLLimitsVector = "16384|16384|16384,16384|16384|4096|1024|31|1,10|1,511|16|23,23,23,23|a1b2c3d4"

	_, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealProbePayload(t, ch.Nonce, p),
	}, "203.0.113.50")
	if err == nil {
		t.Fatalf("expected GPU law violation to be rejected when RejectOnGPULawViolation=true")
	}
	vErr, ok := err.(*VerificationError)
	if !ok || vErr.Code != ErrCodeGPURegisterViolation {
		t.Fatalf("expected %s, got %v", ErrCodeGPURegisterViolation, err)
	}
}

// Vector 7: Reporting two different native motherboard UUIDs (d_nat_*) under the same physical GPU (d_gpu_*)
// triggers the native_uuid_split_trap honeypot AND links both via d_gpu_*!
func TestVector7_NativeUUIDSplitHoneypotTriggered(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	// Launch 1 with real UUID
	ch1, _ := v.IssueChallenge(ctx, "198.51.100.70")
	p1 := buildValidPayload(ch1)
	p1.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "FD7FC36D-REAL-0001-0001-000000000001",
		SerialNumber:   "SER001",
		KeychainAnchor: "kc001",
		CPUCores:       10,
	}
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch1.Nonce,
		SealedPayload:  sealProbePayload(t, ch1.Nonce, p1),
	}, "198.51.100.70")
	if err != nil {
		t.Fatalf("Launch 1 failed: %v", err)
	}
	if res1.SpoofTrapTriggered {
		t.Fatalf("did not expect SpoofTrapTriggered on first native UUID")
	}

	// Launch 2 on the same physical MacBook (same KeychainAnchor kc001), but attacker hooked ioreg to return a fake random UUID!
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.80")
	p2 := buildValidPayload(ch2)
	p2.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "FAKE-UUID-9999-8888-7777-666655554444",
		SerialNumber:   "FAKESER999",
		KeychainAnchor: "kc001",
		CPUCores:       10,
	}
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch2.Nonce,
		SealedPayload:  sealProbePayload(t, ch2.Nonce, p2),
	}, "203.0.113.80")
	if err != nil {
		t.Fatalf("Launch 2 failed: %v", err)
	}

	if res1.GpuAudioSliceID != res2.GpuAudioSliceID {
		t.Fatalf("expected same d_gpu_* across UUID hook")
	}
	if !res2.SpoofTrapTriggered {
		t.Fatalf("expected SpoofTrapTriggered=true on second distinct d_nat_* under same d_gpu_*")
	}
	hasSplitTrap := false
	for _, f := range res2.SpoofFlags {
		if f == "native_uuid_split_trap" {
			hasSplitTrap = true
		}
	}
	if !hasSplitTrap {
		t.Fatalf("expected native_uuid_split_trap in SpoofFlags, got %v", res2.SpoofFlags)
	}
}

// Vector 8: Headless browser SwiftShader / llvmpipe / VMware virtual GPU is automatically demoted
// to Confidence = 0.30 (< 0.60 authoritative threshold).
func TestVector8_VirtualGPUSwiftShaderDemotedTo030(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	ch, _ := v.IssueChallenge(ctx, "203.0.113.100")
	p := buildValidPayload(ch)
	p.WebGL.GPUVendor = "Google Inc. (Google)"
	p.WebGL.GPURenderer = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), Google SwiftShader)"
	p.Lies.WorkerGPURenderer = p.WebGL.GPURenderer

	res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch.Nonce,
		SealedPayload:  sealProbePayload(t, ch.Nonce, p),
	}, "203.0.113.100")
	if err != nil {
		t.Fatalf("VerifyAndDerive failed: %v", err)
	}

	if !res.IsVirtualGPU {
		t.Fatalf("expected IsVirtualGPU=true for SwiftShader")
	}
	if res.Confidence != VirtualGPUConfidence || res.Confidence >= AuthoritativeConfidenceThreshold {
		t.Fatalf("expected Confidence=%v (< %v), got %v", VirtualGPUConfidence, AuthoritativeConfidenceThreshold, res.Confidence)
	}
}

// Bonus Vector: 7-Day /24 Subnet Hardware Mutation Capacity Breaker (>3 distinct GPUs on same /24 IP -> d_ip24_crowd_*)
func TestSubnetHardwareCrowdBreaker(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{
		HMACSecret:               []byte("test-secret-key-32-bytes-long-000"),
		MaxDistinctGPUsPerSubnet: 3,
	}, nil)

	for i := 1; i <= 4; i++ {
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("198.51.100.%d", i*10))
		p := buildValidPayload(ch)
		p.WebGL.StaticWebGLFpHash = fmt.Sprintf("distinct_gpu_fp_hash_%d", i)
		p.Lies.WorkerStaticWebGLFpHash = p.WebGL.StaticWebGLFpHash

		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
			ChallengeNonce: ch.Nonce,
			SealedPayload:  sealProbePayload(t, ch.Nonce, p),
		}, fmt.Sprintf("198.51.100.%d", i*10))
		if err != nil {
			t.Fatalf("iter %d failed: %v", i, err)
		}
		if i <= 3 && res.CrowdSliceID != "" {
			t.Fatalf("iter %d: did not expect CrowdSliceID yet, got %s", i, res.CrowdSliceID)
		}
		if i == 4 && !strings.HasPrefix(res.CrowdSliceID, "d_ip24_crowd_") {
			t.Fatalf("iter 4: expected d_ip24_crowd_* slice, got %q", res.CrowdSliceID)
		}
	}
}

// TestConnectedComponentRiskGraph verifies singleton green, multi-account earliest yellow + later red,
// two-hop transitive closure across orthogonal slices, and virtual GPU (<0.60) staying unknown/pending.
func TestConnectedComponentRiskGraph(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

	// 1. Account "user_1001" registers on MacBook Chrome at IP 198.51.100.10 -> Green
	ch1, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p1 := buildValidPayload(ch1)
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch1.Nonce,
		SealedPayload:  sealProbePayload(t, ch1.Nonce, p1),
	}, "198.51.100.10")
	if err != nil {
		t.Fatalf("user_1001 verify: %v", err)
	}
	snap1 := graph.RecordVerification("user_1001", t0, res1)
	if snap1.RiskStatus != RiskStatusGreen || snap1.RiskPending {
		t.Fatalf("expected user_1001 to be green, got %+v", snap1)
	}

	// 2. Account "user_1002" uses rotating residential proxy IP 203.0.113.99 and mutates Canvas/Fonts,
	//    but runs on the same physical GPU -> shares d_gpu_* with user_1001!
	//    user_1001 becomes Yellow (earliest), user_1002 becomes Red!
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.99")
	p2 := buildValidPayload(ch2)
	p2.System.Canvas2DHash = "different_canvas_2d"
	p2.System.FontsBitmapHash = "different_fonts"
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch2.Nonce,
		SealedPayload:  sealProbePayload(t, ch2.Nonce, p2),
	}, "203.0.113.99")
	if err != nil {
		t.Fatalf("user_1002 verify: %v", err)
	}
	snap2 := graph.RecordVerification("user_1002", t0.Add(5*time.Minute), res2)
	if snap2.RiskStatus != RiskStatusRed {
		t.Fatalf("expected user_1002 to be red, got %+v", snap2)
	}
	snap1After := graph.EvaluateSubject("user_1001")
	if snap1After.RiskStatus != RiskStatusYellow {
		t.Fatalf("expected earliest user_1001 to become yellow, got %+v", snap1After)
	}

	// 3. Account "user_1003" on same /24 IP (203.0.113.200) and same OS/CPU/TZ as user_1002,
	//    even with a mocked different GPU hash -> shares d_sys_* with user_1002 (2-hop transitive link to user_1001)!
	ch3, _ := v.IssueChallenge(ctx, "203.0.113.200")
	p3 := buildValidPayload(ch3)
	p3.WebGL.StaticWebGLFpHash = "spoofed_gpu_hash_for_2hop_test"
	p3.Lies.WorkerStaticWebGLFpHash = p3.WebGL.StaticWebGLFpHash
	res3, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch3.Nonce,
		SealedPayload:  sealProbePayload(t, ch3.Nonce, p3),
	}, "203.0.113.200")
	if err != nil {
		t.Fatalf("user_1003 verify: %v", err)
	}
	snap3 := graph.RecordVerification("user_1003", t0.Add(10*time.Minute), res3)
	if snap3.RiskStatus != RiskStatusRed || len(snap3.ComponentSubjects) != 3 {
		t.Fatalf("expected 2-hop transitive component of 3 users with user_1003=red, got %+v", snap3)
	}

	// 4. Account "user_vm" on SwiftShader virtual GPU (Confidence = 0.30 < 0.60) -> stays Unknown (RiskPending = true)
	chVM, _ := v.IssueChallenge(ctx, "192.0.2.55")
	pVM := buildValidPayload(chVM)
	pVM.WebGL.GPURenderer = "Google SwiftShader"
	pVM.Lies.WorkerGPURenderer = "Google SwiftShader"
	resVM, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chVM.Nonce,
		SealedPayload:  sealProbePayload(t, chVM.Nonce, pVM),
	}, "192.0.2.55")
	if err != nil {
		t.Fatalf("user_vm verify: %v", err)
	}
	snapVM := graph.RecordVerification("user_vm", t0.Add(15*time.Minute), resVM)
	if snapVM.RiskStatus != RiskStatusUnknown || !snapVM.RiskPending {
		t.Fatalf("expected SwiftShader user_vm to remain unknown/pending, got %+v", snapVM)
	}
}

// TestAuditRegression_F2_SameModelColleagues48hAndCrossCity5mStayGreen verifies GPT Finding F2:
// 1. Two users sharing the exact same GPU/Audio and same /24 subnet with different beacons 48h apart stay Green.
// 2. Two users sharing the exact same GPU/Audio across different /24 subnets with different beacons 5m apart stay Green.
func TestAuditRegression_F2_SameModelColleagues48hAndCrossCity5mStayGreen(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

	// Case 1: Same GPU/Audio, same /24 subnet (198.51.100.x), distinct beacons, 48 hours apart
	ch1, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = "a0010000000000000000000000000001"
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "198.51.100.10")
	if err != nil {
		t.Fatalf("alice verify: %v", err)
	}
	snap1 := graph.RecordVerification("colleague_alice", t0, res1)
	if snap1.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected colleague_alice green, got %+v", snap1)
	}

	ch2, _ := v.IssueChallenge(ctx, "198.51.100.20")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = "a0020000000000000000000000000002"
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "198.51.100.20")
	if err != nil {
		t.Fatalf("bob verify: %v", err)
	}
	snap2 := graph.RecordVerification("colleague_bob", t0.Add(48*time.Hour), res2)
	if snap2.RiskStatus != RiskStatusGreen || len(snap2.ComponentSubjects) != 1 {
		t.Fatalf("expected colleague_bob (48h later, distinct beacon, same /24 & GPU) to stay green, got %+v", snap2)
	}

	// Case 2: Different /24 subnet, same GPU/Audio, distinct beacons, 5 minutes apart
	ch3, _ := v.IssueChallenge(ctx, "203.0.113.55")
	p3 := buildValidPayload(ch3)
	p3.BeaconID = "a0030000000000000000000000000003"
	res3, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch3.Nonce, SealedPayload: sealProbePayload(t, ch3.Nonce, p3)}, "203.0.113.55")
	if err != nil {
		t.Fatalf("charlie verify: %v", err)
	}
	snap3 := graph.RecordVerification("stranger_charlie", t0.Add(5*time.Minute), res3)
	if snap3.RiskStatus != RiskStatusGreen || len(snap3.ComponentSubjects) != 1 {
		t.Fatalf("expected stranger_charlie (5m later, different /24, distinct beacon, same GPU) to stay green, got %+v", snap3)
	}
}

// TestAuditRegression_F2_TwoDistinctPhysicalMacBooksDoNotTriggerUUIDSplitTrap verifies GPT Finding F2:
// Two separate physical MacBooks of the same model (distinct HWUUID, SerialNumber, KeychainAnchor, and BeaconID)
// do NOT trigger native_uuid_split_trap and stay Green, whereas hooking HWUUID on the SAME machine (same KeychainAnchor)
// DOES trigger native_uuid_split_trap and turns Red.
func TestAuditRegression_F2_TwoDistinctPhysicalMacBooksDoNotTriggerUUIDSplitTrap(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)

	// Physical MacBook #1
	ch1, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = "b0010000000000000000000000000001"
	p1.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "11111111-2222-3333-4444-555555550001",
		SerialNumber:   "C02MACBOOK01",
		KeychainAnchor: "kc_macbook_01",
		CPUCores:       10,
	}
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "198.51.100.10")
	if err != nil {
		t.Fatalf("macbook 1 verify: %v", err)
	}
	snap1 := graph.RecordVerification("mac_owner_1", t0, res1)
	if res1.SpoofTrapTriggered || snap1.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected mac_owner_1 green without spoof trap, got res=%+v snap=%+v", res1, snap1)
	}

	// Physical MacBook #2 (exact same M1 Pro GPU/Audio & same office /24 IP, but distinct physical machine!)
	ch2, _ := v.IssueChallenge(ctx, "198.51.100.11")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = "b0020000000000000000000000000002"
	p2.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "99999999-8888-7777-6666-555555550002",
		SerialNumber:   "C02MACBOOK02",
		KeychainAnchor: "kc_macbook_02",
		CPUCores:       10,
	}
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "198.51.100.11")
	if err != nil {
		t.Fatalf("macbook 2 verify: %v", err)
	}
	snap2 := graph.RecordVerification("mac_owner_2", t0.Add(2*time.Minute), res2)
	if res2.SpoofTrapTriggered || snap2.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected distinct physical MacBook #2 to NOT trigger native_uuid_split_trap and stay green, got res=%+v snap=%+v", res2, snap2)
	}

	// Now simulate an attacker on Physical MacBook #1 hooking ioreg HWUUID while KeychainAnchor `kc_macbook_01` persists:
	ch3, _ := v.IssueChallenge(ctx, "203.0.113.99")
	p3 := buildValidPayload(ch3)
	p3.BeaconID = "b0030000000000000000000000000003"
	p3.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "HOOKED-UUID-0000-0000-999999999999",
		SerialNumber:   "HOOKEDSER99",
		KeychainAnchor: "kc_macbook_01", // Same OS Keychain anchor on MacBook #1
		CPUCores:       10,
	}
	res3, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch3.Nonce, SealedPayload: sealProbePayload(t, ch3.Nonce, p3)}, "203.0.113.99")
	if err != nil {
		t.Fatalf("hooked macbook 1 verify: %v", err)
	}
	snap3 := graph.RecordVerification("mac_owner_1_alt", t0.Add(10*time.Minute), res3)
	if !res3.SpoofTrapTriggered || snap3.RiskStatus != RiskStatusRed {
		t.Fatalf("expected hooked HWUUID on same KeychainAnchor to trigger native_uuid_split_trap and turn red, got res=%+v snap=%+v", res3, snap3)
	}
}

// TestAuditRegression_F3_SingleUserStorageHealedStaysGreen verifies GPT Finding F3 & DeepSeek #5B:
// A single user who cleared Cookies / experienced Safari ITP (StorageHealed=true) is NOT marked red;
// PrivacySignals records "storage_healed" and only a 2nd account sharing the healed d_bcn_* turns red.
func TestAuditRegression_F3_SingleUserStorageHealedStaysGreen(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)

	ch1, _ := v.IssueChallenge(ctx, "198.51.100.30")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = "c0010000000000000000000000000001"
	p1.Lies.StorageHealed = true
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "198.51.100.30")
	if err != nil {
		t.Fatalf("single user verify: %v", err)
	}
	if res1.SpoofTrapTriggered {
		t.Fatalf("expected SpoofTrapTriggered=false for StorageHealed alone")
	}
	if len(res1.PrivacySignals) != 1 || res1.PrivacySignals[0] != "storage_healed" {
		t.Fatalf("expected PrivacySignals=[storage_healed], got %v", res1.PrivacySignals)
	}
	snap1 := graph.RecordVerification("single_safari_user", t0, res1)
	if snap1.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected single user with StorageHealed=true to be green, got %+v", snap1)
	}

	// Second account on the same healed beacon turns red:
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.40")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = "c0010000000000000000000000000001"
	p2.Lies.StorageHealed = true
	res2, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "203.0.113.40")
	snap2 := graph.RecordVerification("second_account_same_beacon", t0.Add(time.Hour), res2)
	if snap2.RiskStatus != RiskStatusRed {
		t.Fatalf("expected second account sharing healed d_bcn_* to be red, got %+v", snap2)
	}
}

// TestAuditRegression_F7_BeaconSliceIndependentOfGPUAndExtensionDrift verifies GPT Finding F7:
// 1. d_bcn_* remains 100% identical even when StaticWebGLFpHash, WebGLLimitsVector, and AudioCompressorHash change.
// 2. d_gpu_* remains 100% identical when only the 12th volatile extension hash segment of WebGLLimitsVector changes.
func TestAuditRegression_F7_BeaconSliceIndependentOfGPUAndExtensionDrift(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)

	ch1, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = "d0010000000000000000000000000001"
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, "198.51.100.10")
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}

	// Only extension hash (12th segment of WebGLLimitsVector) changes -> d_gpu_* must NOT change!
	ch2, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = "d0010000000000000000000000000001"
	p2.WebGL.WebGLLimitsVector = "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|new_ext_hash_ff00"
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "198.51.100.10")
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if res1.GpuAudioSliceID != res2.GpuAudioSliceID {
		t.Fatalf("expected d_gpu_* to ignore volatile 12th extension hash segment, got %s vs %s", res1.GpuAudioSliceID, res2.GpuAudioSliceID)
	}

	// Full GPU driver + ANGLE + Audio upgrade -> d_gpu_* changes, but d_bcn_* MUST remain identical!
	ch3, _ := v.IssueChallenge(ctx, "203.0.113.88")
	p3 := buildValidPayload(ch3)
	p3.BeaconID = "d0010000000000000000000000000001"
	p3.WebGL.StaticWebGLFpHash = "new_angle_shader_hash_after_browser_update_99999999"
	p3.Lies.WorkerStaticWebGLFpHash = p3.WebGL.StaticWebGLFpHash
	p3.AudioCompressorHash = "new_audio_compressor_hash_after_update_88888888"
	res3, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch3.Nonce, SealedPayload: sealProbePayload(t, ch3.Nonce, p3)}, "203.0.113.88")
	if err != nil {
		t.Fatalf("verify 3: %v", err)
	}
	if res1.BeaconSliceID != res3.BeaconSliceID {
		t.Fatalf("expected d_bcn_* to remain identical across GPU/Audio upgrade, got %s vs %s", res1.BeaconSliceID, res3.BeaconSliceID)
	}
}

// TestAuditRegression_DeepSeek5A_MobileCGNAT40UsersInSameSubnetStayGreen verifies DeepSeek Finding #5A:
// 40 unrelated normal users with distinct beacons and distinct GPUs sharing a single /24 mobile CGNAT
// subnet all remain Green (0 false positives), while SubnetCrowdTriggered telemetry is reported.
func TestAuditRegression_DeepSeek5A_MobileCGNAT40UsersInSameSubnetStayGreen(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{
		HMACSecret:               []byte("test-secret-key-32-bytes-long-000"),
		MaxDistinctGPUsPerSubnet: 3,
	}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 16, 0, 0, 0, time.UTC)

	for i := 0; i < 40; i++ {
		ip := fmt.Sprintf("100.64.88.%d", 10+i)
		ch, _ := v.IssueChallenge(ctx, ip)
		p := buildValidPayload(ch)
		p.BeaconID = fmt.Sprintf("e001000000000000000000000000%04x", i)
		p.WebGL.StaticWebGLFpHash = fmt.Sprintf("cgnat_distinct_gpu_hash_%04d", i)
		p.Lies.WorkerStaticWebGLFpHash = p.WebGL.StaticWebGLFpHash
		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		if err != nil {
			t.Fatalf("cgnat user %d verify: %v", i, err)
		}
		if i >= 3 && (!res.SubnetCrowdTriggered || res.CrowdSliceID == "") {
			t.Fatalf("expected SubnetCrowdTriggered=true and CrowdSliceID populated for user %d", i)
		}
		snap := graph.RecordVerification(fmt.Sprintf("cgnat_user_%d", i), t0.Add(time.Duration(i)*10*time.Second), res)
		if snap.RiskStatus != RiskStatusGreen {
			t.Fatalf("cgnat user %d falsely marked %s (expected green): %+v", i, snap.RiskStatus, snap)
		}
	}
}

// TestAuditRegression_F8_GraphDeduplicationAndClockInjection verifies GPT Finding F8 & DeepSeek other findings:
// 1. MemoryChallengeStore uses its injected NowFunc clock for deterministic TTL expiry.
// 2. RiskGraph deduplicates repeated verifications of the same subject without growing unbounded edges.
func TestAuditRegression_F8_GraphDeduplicationAndClockInjection(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 18, 0, 0, 0, time.UTC)
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })
	v := NewVerifier(Config{
		HMACSecret:   []byte("test-secret-key-32-bytes-long-000"),
		ChallengeTTL: 30 * time.Second,
	}, store)

	ch, err := v.IssueChallenge(ctx, "198.51.100.10")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	sealed := sealProbePayload(t, ch.Nonce, buildValidPayload(ch))

	// Advance fake clock past 30s TTL:
	now = now.Add(31 * time.Second)
	if _, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealed}, "198.51.100.10"); err == nil {
		t.Fatalf("expected expired challenge to be rejected when injected clock advances past TTL")
	}

	// Verify graph deduplication on repeated identifications of the same subject:
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	ch2, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = "f0010000000000000000000000000001"
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, "198.51.100.10")
	if err != nil {
		t.Fatalf("VerifyAndDerive: %v", err)
	}
	for repeat := 0; repeat < 25; repeat++ {
		snap := graph.RecordVerification("repeat_subject_1", now.Add(time.Duration(repeat)*time.Minute), res2)
		if snap.RiskStatus != RiskStatusGreen || len(snap.SliceIDs) != 4 {
			t.Fatalf("repeat %d: expected green with 4 deduplicated slices, got %+v", repeat, snap)
		}
	}
}

// TestRereview_R1_PermutationInvarianceAnd100xDeterministic verifies GPT v0.4.0 Re-Review Finding R1:
// 1. EvaluateSubjectComponent produces the exact same result across all 6 permutations of [A(0m), B(20m), C(121m)].
// 2. RiskGraph.EvaluateSubject("B") called 100 times in a loop is 100/100 deterministic (never green:89, red:11).
func TestRereview_R1_PermutationInvarianceAnd100xDeterministic(t *testing.T) {
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	edgeA := GraphEdge{SubjectID: "A", SubjectCreatedAt: t0, SliceID: "d_web_same", Confidence: 0.95, HasBeacon: true, BeaconSliceID: "d_bcn_1"}
	edgeB := GraphEdge{SubjectID: "B", SubjectCreatedAt: t0.Add(20 * time.Minute), SliceID: "d_web_same", Confidence: 0.95, HasBeacon: true, BeaconSliceID: "d_bcn_2"}
	edgeC := GraphEdge{SubjectID: "C", SubjectCreatedAt: t0.Add(121 * time.Minute), SliceID: "d_web_same", Confidence: 0.95, HasBeacon: true, BeaconSliceID: "d_bcn_3"}

	perms := [][]GraphEdge{
		{edgeA, edgeB, edgeC},
		{edgeA, edgeC, edgeB},
		{edgeB, edgeA, edgeC},
		{edgeB, edgeC, edgeA},
		{edgeC, edgeA, edgeB},
		{edgeC, edgeB, edgeA},
	}

	baseline := EvaluateSubjectComponent(perms[0], "B", AuthoritativeConfidenceThreshold)
	for idx, p := range perms {
		got := EvaluateSubjectComponent(p, "B", AuthoritativeConfidenceThreshold)
		if got.RiskStatus != baseline.RiskStatus || got.EarliestSubjectID != baseline.EarliestSubjectID || len(got.ComponentSubjects) != len(baseline.ComponentSubjects) {
			t.Fatalf("permutation %d differed from baseline: got %+v, want %+v", idx, got, baseline)
		}
	}

	// Also verify 100 repeated evaluations on RiskGraph:
	g := NewRiskGraph(AuthoritativeConfidenceThreshold)
	for i, e := range []GraphEdge{edgeA, edgeB, edgeC} {
		g.RecordVerification(e.SubjectID, e.SubjectCreatedAt, &VerifyResult{
			Accepted:        true,
			Confidence:      0.95,
			ExactSliceID:    "d_web_same",
			BeaconSliceID:   e.BeaconSliceID,
			GpuAudioSliceID: fmt.Sprintf("d_gpu_%d", i),
			SysNetSliceID:   fmt.Sprintf("d_sys_%d", i),
		})
	}
	firstSnap := g.EvaluateSubject("B")
	for iter := 0; iter < 100; iter++ {
		snap := g.EvaluateSubject("B")
		if snap.RiskStatus != firstSnap.RiskStatus || snap.BurstSuspicion != firstSnap.BurstSuspicion || len(snap.ComponentSubjects) != len(firstSnap.ComponentSubjects) {
			t.Fatalf("iteration %d non-deterministic: got %+v, want %+v", iter, snap, firstSnap)
		}
	}
}

// TestRereview_R2_ThreeOrMoreColleaguesNeverMergedIntoRed verifies GPT Finding R2 & DeepSeek #3:
// When 3, 5, or 10 colleagues on the same /24 office Wi-Fi with the exact same company MacBook model
// (identical d_gpu_* and d_sys_*, so identical d_gpusys_*) and distinct clean beacons register 1m apart:
// - None of them is ever merged into another colleague's ComponentSubjects (len == 1).
// - None of them is ever marked Red.
// - Instead, BurstSuspicion=true and RiskPending=true are set with status Yellow for step-up review.
func TestRereview_R2_ThreeOrMoreColleaguesNeverMergedIntoRed(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("198.51.100.%d", 10+i)
		ch, _ := v.IssueChallenge(ctx, ip)
		p := buildValidPayload(ch)
		p.BeaconID = fmt.Sprintf("c011ea60e0000000000000000000%04x", i)
		// Different local font subset per colleague, but identical GPU/Audio and /24 subnet (identical d_gpusys_*):
		p.System.FontsBitmapHash = fmt.Sprintf("colleague_font_subset_%d", i)
		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
			ChallengeNonce: ch.Nonce,
			SealedPayload:  sealProbePayload(t, ch.Nonce, p),
		}, ip)
		if err != nil {
			t.Fatalf("colleague %d verify: %v", i, err)
		}
		uid := fmt.Sprintf("office_colleague_%d", i)
		snap := graph.RecordVerification(uid, t0.Add(time.Duration(i)*time.Minute), res)
		if snap.RiskStatus == RiskStatusRed {
			t.Fatalf("colleague %d falsely marked RED on shared d_gpusys_*: %+v", i, snap)
		}
		if len(snap.ComponentSubjects) != 1 || snap.ComponentSubjects[0] != uid {
			t.Fatalf("colleague %d falsely merged with other colleagues: ComponentSubjects=%v", i, snap.ComponentSubjects)
		}
		if i >= 2 && (!snap.BurstSuspicion || !snap.RiskPending || snap.RiskStatus != RiskStatusYellow) {
			t.Fatalf("colleague %d expected BurstSuspicion=true, RiskPending=true, RiskStatus=yellow, got %+v", i, snap)
		}
	}
}

// TestRereview_R3_MultiHopHardSliceChainNoTruncation verifies GPT Finding R3:
// On a 4-hop hard-beacon/keychain chain A—B—C—D—E where A is globally earliest (t=0) and E (t=1m)
// is earlier than B(t=2m), C(t=3m), D(t=4m), querying E traverses the full hard-slice chain without
// truncating at 3 hops, returning EarliestSubjectID="A" and RiskStatus="red".
func TestRereview_R3_MultiHopHardSliceChainNoTruncation(t *testing.T) {
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)

	// Chain: A(t=0) --[bcn1]-- B(t=2m, kch1) --[kch1]-- C(t=3m, bcn2) --[bcn2]-- D(t=4m, kch2) --[kch2]-- E(t=1m)
	records := []struct {
		id  string
		at  time.Time
		bcn string
		kch string
	}{
		{"A", t0, "d_bcn_chain_1", ""},
		{"B", t0.Add(2 * time.Minute), "d_bcn_chain_1", "d_kch_chain_1"},
		{"C", t0.Add(3 * time.Minute), "d_bcn_chain_2", "d_kch_chain_1"},
		{"D", t0.Add(4 * time.Minute), "d_bcn_chain_2", "d_kch_chain_2"},
		{"E", t0.Add(1 * time.Minute), "", "d_kch_chain_2"},
	}

	for idx, r := range records {
		graph.RecordVerification(r.id, r.at, &VerifyResult{
			Accepted:        true,
			Confidence:      0.95,
			ExactSliceID:    fmt.Sprintf("d_web_%d", idx),
			BeaconSliceID:   r.bcn,
			KeychainSliceID: r.kch,
			GpuAudioSliceID: fmt.Sprintf("d_gpu_%d", idx),
			SysNetSliceID:   fmt.Sprintf("d_sys_%d", idx),
		})
	}

	snapE := graph.EvaluateSubject("E")
	if len(snapE.ComponentSubjects) != 5 {
		t.Fatalf("expected all 5 subjects A..E in connected component, got %v", snapE.ComponentSubjects)
	}
	if snapE.EarliestSubjectID != "A" {
		t.Fatalf("expected EarliestSubjectID=A (t=0), got %s", snapE.EarliestSubjectID)
	}
	if snapE.RiskStatus != RiskStatusRed {
		t.Fatalf("expected E to be red (since A is earlier than E), got %s (%+v)", snapE.RiskStatus, snapE)
	}
}

// TestDeepSeek_1_2_ECDSAP256DeviceKeyTOFUAndSilentAttacker verifies DeepSeek Roadmap #1 & #2:
//  1. Valid ECDSA P-256 challenge signature derives d_key_* and binds to d_bcn_* (TOFU).
//  2. Replaying the same beacon_id without the private key requires recovery and cannot create authoritative graph edges.
//  3. A "silent attacker" client that sets all boolean flags in Lies to false while tampering with raw
//     CanvasControlRGBA, AudioCopyHash, or stripping Worker fields is caught by server-side inference.
func TestDeepSeek_1_2_ECDSAP256DeviceKeyTOFUAndSilentAttacker(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 11, 0, 0, 0, time.UTC)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	pubB64 := base64.RawURLEncoding.EncodeToString(pubBytes)

	signPayload := func(p *ProbePayload) {
		msg := strings.Join([]string{
			"prismid-v2-sig",
			p.Nonce,
			strings.ToLower(p.BeaconID),
			strings.ToLower(p.WebGL.StaticWebGLFpHash),
			strings.ToLower(p.AudioCompressorHash),
		}, "|")
		digest := sha256.Sum256([]byte(msg))
		r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		var rawSig [64]byte
		r.FillBytes(rawSig[:32])
		s.FillBytes(rawSig[32:64])
		p.DeviceKey = &DeviceKeyProof{
			Alg:       "ES256",
			PubKey:    pubB64,
			Signature: base64.RawURLEncoding.EncodeToString(rawSig[:]),
		}
	}

	// 1. Genuine attested browser establishes d_key_* + TOFU binding with d_bcn_*
	ch1, _ := v.IssueChallenge(ctx, "198.51.100.10")
	p1 := buildValidPayload(ch1)
	p1.BeaconID = "aa010000000000000000000000000001"
	signPayload(&p1)
	res1, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch1.Nonce,
		SealedPayload:  sealProbePayload(t, ch1.Nonce, p1),
	}, "198.51.100.10")
	if err != nil {
		t.Fatalf("attested verify: %v", err)
	}
	if !res1.DeviceKeyBound || !res1.DeviceKeyAttested || !strings.HasPrefix(res1.DeviceKeySliceID, "d_key_") || res1.Confidence != 0.95 {
		t.Fatalf("expected DeviceKeyBound=true, d_key_* slice, and Confidence=0.95, got %+v", res1)
	}
	snap1 := graph.RecordVerification("honest_key_user", t0, res1)
	if snap1.RiskStatus != RiskStatusGreen {
		t.Fatalf("expected honest_key_user green, got %+v", snap1)
	}

	// 2. Attacker steals beacon_id "aa01..." and replays it from a script WITHOUT the non-extractable private key:
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.50")
	p2 := buildValidPayload(ch2)
	p2.BeaconID = "aa010000000000000000000000000001"
	p2.DeviceKey = nil // Missing private key signature!
	res2, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch2.Nonce,
		SealedPayload:  sealProbePayload(t, ch2.Nonce, p2),
	}, "203.0.113.50")
	if err != nil {
		t.Fatalf("stolen beacon verify: %v", err)
	}
	if !res2.DeviceKeyRecoveryRequired || res2.SpoofTrapTriggered || res2.Confidence >= AuthoritativeConfidenceThreshold {
		t.Fatalf("missing bound key must await recovery without authoritative identity or spoof poisoning, got %+v", res2)
	}

	// 3. Silent Attacker sets ALL boolean flags in Lies to false, but tampers with raw measurements:
	ch3, _ := v.IssueChallenge(ctx, "203.0.113.60")
	p3 := buildValidPayload(ch3)
	p3.BeaconID = "bb020000000000000000000000000002"
	p3.Lies.WorkerLieDetected = false
	p3.Lies.CanvasNoiseInjected = false
	p3.Lies.AudioNoiseInjected = false
	p3.Lies.WebGLNoiseInjected = false
	// Tamper raw CanvasControlRGBA (1-LSB noise in transparent control pixel):
	p3.System.CanvasControlRGBA = []int{0, 0, 1, 0, 17, 136, 221, 255}
	res3, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: ch3.Nonce,
		SealedPayload:  sealProbePayload(t, ch3.Nonce, p3),
	}, "203.0.113.60")
	if err != nil {
		t.Fatalf("silent attacker verify: %v", err)
	}
	if !res3.SpoofTrapTriggered {
		t.Fatalf("expected silent attacker with raw CanvasControlRGBA noise to be caught, got %+v", res3)
	}
	snap3 := graph.RecordVerification("silent_attacker_1", t0.Add(5*time.Minute), res3)
	if snap3.RiskStatus != RiskStatusRed {
		t.Fatalf("expected silent_attacker_1 to be marked red, got %+v", snap3)
	}
}

// TestDeepSeek_6_ExplainabilityEvidenceChainAndPrivacyDeletion verifies DeepSeek Roadmap #6:
// 1. Non-green verdicts include LogOddsScore and structured EvidenceChain items.
// 2. RiskGraph.RemoveSubject completely erases a subject's graph edges (GDPR/CCPA deletion).
func TestDeepSeek_6_ExplainabilityEvidenceChainAndPrivacyDeletion(t *testing.T) {
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)

	res := &VerifyResult{
		Accepted:        true,
		Confidence:      0.95,
		ExactSliceID:    "d_web_del_1",
		BeaconSliceID:   "d_bcn_del_shared",
		GpuAudioSliceID: "d_gpu_del_1",
		SysNetSliceID:   "d_sys_del_1",
	}
	graph.RecordVerification("user_del_1", t0, res)
	snap2 := graph.RecordVerification("user_del_2", t0.Add(time.Minute), res)
	if snap2.RiskStatus != RiskStatusRed || len(snap2.EvidenceChain) == 0 || snap2.LogOddsScore <= 0 {
		t.Fatalf("expected red verdict with positive LogOddsScore and non-empty EvidenceChain, got %+v", snap2)
	}

	// Erase user_del_1 via GDPR/CCPA RemoveSubject:
	if !graph.RemoveSubject("user_del_1") {
		t.Fatalf("expected RemoveSubject(user_del_1) to return true")
	}
	snap1After := graph.EvaluateSubject("user_del_1")
	if snap1After.RiskStatus != RiskStatusUnknown {
		t.Fatalf("expected erased subject user_del_1 to return unknown, got %+v", snap1After)
	}
	snap2After := graph.EvaluateSubject("user_del_2")
	if snap2After.RiskStatus != RiskStatusGreen || len(snap2After.ComponentSubjects) != 1 {
		t.Fatalf("expected user_del_2 to become green after user_del_1 was erased, got %+v", snap2After)
	}
}

// TestEngineeringBounds_ChallengeStoreAndPerSubjectSlices verifies GPT Re-Review Engineering Bounds:
// 1. MemoryChallengeStore enforces hard capacity <= 4096 even when all challenges are unexpired.
// 2. RiskGraph caps per-subject slices at MaxSlicesPerSubject (16) even if a subject mutates signals 100 times.
func TestEngineeringBounds_ChallengeStoreAndPerSubjectSlices(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)
	store := NewMemoryChallengeStoreWithClock(func() time.Time { return now })

	for i := 0; i < 4200; i++ {
		_ = store.SaveChallenge(ctx, Challenge{
			Nonce:     fmt.Sprintf("nonce_%d", i),
			IssuedAt:  now.UnixMilli(),
			ExpiresAt: now.Add(60 * time.Second).UnixMilli(),
		}, 60*time.Second)
	}
	store.mu.Lock()
	chCount := len(store.challenges)
	store.mu.Unlock()
	if chCount > 4096 {
		t.Fatalf("expected MemoryChallengeStore.challenges hard-capped at <= 4096, got %d", chCount)
	}

	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	for i := 0; i < 50; i++ {
		graph.RecordVerification("mutating_subject", now.Add(time.Duration(i)*time.Second), &VerifyResult{
			Accepted:        true,
			Confidence:      0.95,
			ExactSliceID:    fmt.Sprintf("d_web_mut_%d", i),
			BeaconSliceID:   "d_bcn_persistent_anchor",
			GpuAudioSliceID: fmt.Sprintf("d_gpu_mut_%d", i),
			SysNetSliceID:   fmt.Sprintf("d_sys_mut_%d", i),
		})
	}
	snap := graph.EvaluateSubject("mutating_subject")
	if len(snap.SliceIDs) > MaxSlicesPerSubject {
		t.Fatalf("expected subject slices capped at <= %d, got %d", MaxSlicesPerSubject, len(snap.SliceIDs))
	}
}

// TestDeepSeekV050_P0_SpoofDoesNotPoisonCleanSameModelUsers verifies DeepSeek v0.5.0 Review Fixes:
//  1. P0: 5 clean users on the same GPU model (d_gpu_*) + 1 Canvas-noise spoof user (Brave farbling / griefing)
//     + 1 subsequent ECDSA P-256 d_key_* bound user -> ONLY the 1 spoof user is red; all 5 prior clean users
//     and the subsequent d_key_* user remain green with len(ComponentSubjects) == 1.
//  2. P0 Edge TTL: A spoofed observation on the same /24 subnet expires after DefaultSpoofEdgeTTL (24h).
//  3. P2 Minimal Payload Compatibility: Omitting optional worker_* fields when WorkerUnavailable=false
//     records "worker_telemetry_missing" in PrivacySignals and stays green (SpoofTrapTriggered=false).
func TestDeepSeekV050_P0_SpoofDoesNotPoisonCleanSameModelUsers(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{HMACSecret: []byte("test-secret-key-32-bytes-long-000")}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)

	// 1. 5 clean users with the exact same GPU/Audio model (identical d_gpu_*) across different /24 subnets and distinct beacons -> all green
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("198.%d.100.10", 50+i)
		ch, _ := v.IssueChallenge(ctx, ip)
		p := buildValidPayload(ch)
		p.BeaconID = fmt.Sprintf("aa11000000000000000000000000%04x", i)
		p.System.FontsBitmapHash = fmt.Sprintf("clean_user_local_fonts_%d", i)
		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
			ChallengeNonce: ch.Nonce,
			SealedPayload:  sealProbePayload(t, ch.Nonce, p),
		}, ip)
		if err != nil {
			t.Fatalf("clean user %d verify: %v", i, err)
		}
		snap := graph.RecordVerification(fmt.Sprintf("clean_user_%d", i), t0.Add(time.Duration(i)*time.Minute), res)
		if snap.RiskStatus != RiskStatusGreen || len(snap.ComponentSubjects) != 1 {
			t.Fatalf("expected clean_user_%d green with members=1, got %+v", i, snap)
		}
	}

	// 2. 1 Canvas-noise user (Brave farbling / Firefox RFP / griefing attacker) on the exact same d_gpu_*
	chSpoof, _ := v.IssueChallenge(ctx, "203.0.113.77")
	pSpoof := buildValidPayload(chSpoof)
	pSpoof.BeaconID = "bb220000000000000000000000009999"
	pSpoof.System.CanvasControlRGBA = []int{0, 1, 0, 0, 17, 136, 221, 255} // triggers canvas_noise_injected
	resSpoof, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chSpoof.Nonce,
		SealedPayload:  sealProbePayload(t, chSpoof.Nonce, pSpoof),
	}, "203.0.113.77")
	if err != nil {
		t.Fatalf("spoof user verify: %v", err)
	}
	snapSpoof := graph.RecordVerification("canvas_noise_user", t0.Add(6*time.Minute), resSpoof)
	if snapSpoof.RiskStatus != RiskStatusRed || len(snapSpoof.ComponentSubjects) != 1 {
		t.Fatalf("expected canvas_noise_user to be red with members=1 (isolated from clean users), got %+v", snapSpoof)
	}

	// Verify all 5 prior clean users are STILL green with members=1 (zero cohort contamination!)
	for i := 0; i < 5; i++ {
		uid := fmt.Sprintf("clean_user_%d", i)
		snap := graph.EvaluateSubject(uid)
		if snap.RiskStatus != RiskStatusGreen || len(snap.ComponentSubjects) != 1 {
			t.Fatalf("P0 regression: %s was poisoned by canvas_noise_user on shared d_gpu_*: %+v", uid, snap)
		}
	}

	// 3. Subsequent d_key_* bound user on the exact same d_gpu_* registers after the spoof user -> stays green!
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	chKey, _ := v.IssueChallenge(ctx, "192.0.2.88")
	pKey := buildValidPayload(chKey)
	pKey.BeaconID = "cc330000000000000000000000008888"
	pKey.System.FontsBitmapHash = "subsequent_dkey_fonts"
	// Also test P2 minimal payload compatibility: omit optional worker_* fields while WorkerUnavailable=false
	pKey.Lies.WorkerStaticWebGLFpHash = ""
	pKey.Lies.WorkerGPURenderer = ""
	pKey.Lies.WorkerPlatform = ""
	pKey.Lies.WorkerUserAgent = ""
	pKey.Lies.WorkerCPUCores = 0
	msg := strings.Join([]string{
		"prismid-v2-sig",
		pKey.Nonce,
		strings.ToLower(pKey.BeaconID),
		strings.ToLower(pKey.WebGL.StaticWebGLFpHash),
		strings.ToLower(pKey.AudioCompressorHash),
	}, "|")
	digest := sha256.Sum256([]byte(msg))
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, digest[:])
	var rawSig [64]byte
	r.FillBytes(rawSig[:32])
	s.FillBytes(rawSig[32:64])
	pKey.DeviceKey = &DeviceKeyProof{
		Alg:       "ecdsa-p256",
		PubKey:    base64.RawURLEncoding.EncodeToString(pubBytes),
		Signature: base64.RawURLEncoding.EncodeToString(rawSig[:]),
	}
	resKey, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chKey.Nonce,
		SealedPayload:  sealProbePayload(t, chKey.Nonce, pKey),
	}, "192.0.2.88")
	if err != nil {
		t.Fatalf("d_key_* user verify: %v", err)
	}
	if !resKey.DeviceKeyBound || resKey.SpoofTrapTriggered {
		t.Fatalf("expected DeviceKeyBound=true and SpoofTrapTriggered=false on minimal worker payload, got %+v", resKey)
	}
	snapKey := graph.RecordVerification("subsequent_dkey_user", t0.Add(10*time.Minute), resKey)
	if snapKey.RiskStatus != RiskStatusGreen || len(snapKey.ComponentSubjects) != 1 {
		t.Fatalf("P0 regression: subsequent_dkey_user was poisoned by earlier spoof user: %+v", snapKey)
	}

	// 4. Verify DefaultSpoofEdgeTTL (24h) expiry on the exact same /24 subnet (203.0.113.x):
	chLater, _ := v.IssueChallenge(ctx, "203.0.113.78")
	pLater := buildValidPayload(chLater)
	pLater.BeaconID = "dd440000000000000000000000007777"
	pLater.System.FontsBitmapHash = "later_user_fonts"
	resLater, err := v.VerifyAndDerive(ctx, IdentifyRequest{
		ChallengeNonce: chLater.Nonce,
		SealedPayload:  sealProbePayload(t, chLater.Nonce, pLater),
	}, "203.0.113.78")
	if err != nil {
		t.Fatalf("later user verify: %v", err)
	}
	snapLater := graph.RecordVerification("same_subnet_after_25h", t0.Add(25*time.Hour), resLater)
	if snapLater.RiskStatus != RiskStatusGreen || len(snapLater.ComponentSubjects) != 1 {
		t.Fatalf("expected spoof edge on same /24 to expire after 24h TTL, got %+v", snapLater)
	}
}
