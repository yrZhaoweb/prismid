package prismid

import (
	"context"
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

	// Launch 2 on the same physical GPU, but attacker hooked ioreg to return a fake random UUID!
	ch2, _ := v.IssueChallenge(ctx, "203.0.113.80")
	p2 := buildValidPayload(ch2)
	p2.NativeAnchor = &NativeHardwareAnchor{
		Platform:       "macos",
		HWUUID:         "FAKE-UUID-9999-8888-7777-666655554444",
		SerialNumber:   "FAKESER999",
		KeychainAnchor: "fake_kc_999",
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
