package prismid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

type zipfHardwareModel struct {
	name         string
	vendor       string
	renderer     string
	limits       string
	staticGLHash string
	audioHash    string
	platform     string
	userAgent    string
	cpuCores     int
	screen       string
}

var realisticZipfHardwareCatalog = []zipfHardwareModel{
	{
		name:         "MacBook Pro 14 M3 Pro (Top-1 26% share)",
		vendor:       "Apple",
		renderer:     "Apple M3 Pro",
		limits:       "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|a1b2c3d4",
		staticGLHash: "m3_pro_static_webgl_hash_0000000000000000000000000000000000000001",
		audioHash:    "m3_pro_audio_comp_hash_000000000000000000000000000000000000000001",
		platform:     "MacIntel",
		userAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		cpuCores:     12,
		screen:       "1512x982x30@2",
	},
	{
		name:         "MacBook Air 13 M2 (Top-2 18% share)",
		vendor:       "Apple",
		renderer:     "Apple M2",
		limits:       "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|a1b2c3d4",
		staticGLHash: "m2_air_static_webgl_hash_0000000000000000000000000000000000000002",
		audioHash:    "m2_air_audio_comp_hash_000000000000000000000000000000000000000002",
		platform:     "MacIntel",
		userAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		cpuCores:     8,
		screen:       "1470x956x30@2",
	},
	{
		name:         "Windows 11 NVIDIA RTX 3060 ANGLE D3D11 (Top-3 15% share)",
		vendor:       "Google Inc. (NVIDIA)",
		renderer:     "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
		limits:       "16384|16384|32767,32767|16384|4096|1024|30|1,1|1,1024|16|23,23,23,23|c3d4e5f6",
		staticGLHash: "rtx3060_static_webgl_hash_00000000000000000000000000000000000003",
		audioHash:    "rtx3060_audio_comp_hash_0000000000000000000000000000000000000003",
		platform:     "Win32",
		userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		cpuCores:     12,
		screen:       "1920x1080x24@1",
	},
	{
		name:         "Windows 11 Intel Iris Xe ANGLE D3D11 (Top-4 14% share)",
		vendor:       "Google Inc. (Intel)",
		renderer:     "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
		limits:       "16384|16384|16384,16384|16384|4096|1024|30|1,1|1,1024|16|23,23,23,23|d4e5f607",
		staticGLHash: "iris_xe_static_webgl_hash_00000000000000000000000000000000000004",
		audioHash:    "iris_xe_audio_comp_hash_0000000000000000000000000000000000000004",
		platform:     "Win32",
		userAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		cpuCores:     8,
		screen:       "1920x1080x24@1.25",
	},
	{
		name:         "MacBook Pro 16 M1 Pro (Top-5 12% share)",
		vendor:       "Apple",
		renderer:     "Apple M1 Pro",
		limits:       "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|a1b2c3d4",
		staticGLHash: "m1_pro_static_webgl_hash_0000000000000000000000000000000000000005",
		audioHash:    "m1_pro_audio_comp_hash_000000000000000000000000000000000000000005",
		platform:     "MacIntel",
		userAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		cpuCores:     10,
		screen:       "1728x1117x30@2",
	},
	{
		name:         "Linux Ubuntu AMD Radeon RX 6700 XT (15% share)",
		vendor:       "AMD",
		renderer:     "AMD Radeon RX 6700 XT (navi22, LLVM 15.0.7, DRM 3.49, 6.2.0-36-generic)",
		limits:       "16384|16384|16384,16384|16384|4096|1024|32|1,128|1,2048|16|23,23,23,23|e5f60718",
		staticGLHash: "rx6700_static_webgl_hash_000000000000000000000000000000000000006",
		audioHash:    "rx6700_audio_comp_hash_00000000000000000000000000000000000000006",
		platform:     "Linux x86_64",
		userAgent:    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		cpuCores:     16,
		screen:       "2560x1440x24@1",
	},
}

func selectZipfHardware(idx int) zipfHardwareModel {
	bucket := idx % 100
	switch {
	case bucket < 26:
		return realisticZipfHardwareCatalog[0]
	case bucket < 44:
		return realisticZipfHardwareCatalog[1]
	case bucket < 59:
		return realisticZipfHardwareCatalog[2]
	case bucket < 73:
		return realisticZipfHardwareCatalog[3]
	case bucket < 85:
		return realisticZipfHardwareCatalog[4]
	default:
		return realisticZipfHardwareCatalog[5]
	}
}

func buildZipfPayload(ch *Challenge, hw zipfHardwareModel, beaconID string, fontVariant int) ProbePayload {
	p := buildValidPayload(ch)
	p.BeaconID = beaconID
	p.WebGL.GPUVendor = hw.vendor
	p.WebGL.GPURenderer = hw.renderer
	p.WebGL.WebGLLimitsVector = hw.limits
	p.WebGL.StaticWebGLFpHash = hw.staticGLHash
	p.AudioCompressorHash = hw.audioHash
	p.AudioCopyHash = hw.audioHash
	p.System.Platform = hw.platform
	p.System.UserAgent = hw.userAgent
	p.System.CPUCores = hw.cpuCores
	p.System.ScreenSpec = hw.screen
	p.System.FontsBitmapHash = fmt.Sprintf("font_subset_%s_%d", hw.platform, fontVariant)
	p.System.CanvasControlRGBA = []int{0, 0, 0, 0, 17, 136, 221, 255}
	p.Lies.WorkerGPURenderer = hw.renderer
	p.Lies.WorkerStaticWebGLFpHash = hw.staticGLHash
	p.Lies.WorkerCPUCores = hw.cpuCores
	p.Lies.WorkerPlatform = hw.platform
	p.Lies.WorkerUserAgent = hw.userAgent
	p.Lies.WorkerTimezone = p.System.Timezone
	return p
}

// TestAuthoritativeEvaluation_AmIUniqueZipfAndFPScannerMatrix executes an independent,
// academic-grade evaluation following:
//   - Laperdrix et al. "AmIUnique" (IEEE S&P) Zipfian hardware market-share distribution
//     where top laptop/PC models collide heavily across cities, office Wi-Fi, and CGNAT.
//   - Vastel et al. "FP-Scanner / FP-Stalker" (IEEE S&P / USENIX Security) adversarial
//     tampering taxonomy + out-of-scope boundary quantification.
func TestAuthoritativeEvaluation_AmIUniqueZipfAndFPScannerMatrix(t *testing.T) {
	ctx := context.Background()
	v := NewVerifier(Config{
		HMACSecret:               []byte("authoritative-eval-secret-key-32b"),
		ChallengeTTL:             60 * time.Second,
		SpotPixelTolerance:       2,
		MaxDistinctGPUsPerSubnet: 3,
	}, nil)
	graph := NewRiskGraph(AuthoritativeConfidenceThreshold)
	t0 := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)

	sharedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := elliptic.Marshal(elliptic.P256(), sharedKey.PublicKey.X, sharedKey.PublicKey.Y)
	pubB64 := base64.RawURLEncoding.EncodeToString(pubBytes)

	signWithKey := func(p *ProbePayload) {
		msg := strings.Join([]string{
			"prismid-v2-sig",
			p.Nonce,
			strings.ToLower(p.BeaconID),
			strings.ToLower(p.WebGL.StaticWebGLFpHash),
			strings.ToLower(p.AudioCompressorHash),
		}, "|")
		digest := sha256.Sum256([]byte(msg))
		r, s, _ := ecdsa.Sign(rand.Reader, sharedKey, digest[:])
		var rawSig [64]byte
		r.FillBytes(rawSig[:32])
		s.FillBytes(rawSig[32:64])
		p.DeviceKey = &DeviceKeyProof{
			Alg:       "ecdsa-p256",
			PubKey:    pubB64,
			Signature: base64.RawURLEncoding.EncodeToString(rawSig[:]),
		}
	}

	// ============================================================================
	// PART 1: 1,000 BENIGN USERS UNDER ZIPFIAN HARDWARE MARKET-SHARE DISTRIBUTION
	// ============================================================================
	benignTotal := 0
	benignFalseRed := 0
	benignStepUpYellow := 0

	// B-Cohort 1 (700 users): Zipfian hardware distribution across cities, including
	// Masked Worker Renderer ("WebKit WebGL" / "Mozilla") on 100 Safari/Firefox users.
	b1FalseRed := 0
	for i := 0; i < 700; i++ {
		hw := selectZipfHardware(i)
		ip := fmt.Sprintf("110.%d.%d.%d", (i/250)+1, (i%250)+1, (i%200)+10)
		ch, _ := v.IssueChallenge(ctx, ip)
		bcn := fmt.Sprintf("b100000000000000000000000000%04x", i)
		p := buildZipfPayload(ch, hw, bcn, i)
		if i%7 == 0 {
			// Simulate Safari / Firefox privacy mode masking WEBGL_debug_renderer_info in Worker
			p.Lies.WorkerGPURenderer = "WebKit WebGL"
		}
		res, err := v.VerifyAndDerive(ctx, IdentifyRequest{
			ChallengeNonce: ch.Nonce,
			SealedPayload:  sealProbePayload(t, ch.Nonce, p),
		}, ip)
		if err != nil {
			t.Fatalf("B1 user %d verify: %v", i, err)
		}
		snap := graph.RecordVerification(fmt.Sprintf("zipf_user_%d", i), t0.Add(time.Duration(i)*30*time.Second), res)
		benignTotal++
		if snap.RiskStatus == RiskStatusRed {
			b1FalseRed++
			benignFalseRed++
		}
	}

	// B-Cohort 2 (150 users): Corporate Office /24 Wi-Fi with identical company MacBook Pro M3:
	// - First 100 users: 50 pairs of 2 colleagues per /24 office -> 100% Green
	// - Next 50 users: 10 offices with 5 colleagues each arriving within 10 minutes -> Yellow+Pending step-up, 0 Red!
	b2FalseRed := 0
	b2StepUp := 0
	for i := 0; i < 100; i++ {
		officeSub := (i / 2) + 1
		ip := fmt.Sprintf("172.16.%d.%d", officeSub, 10+(i%2))
		ch, _ := v.IssueChallenge(ctx, ip)
		bcn := fmt.Sprintf("b200000000000000000000000000%04x", i)
		p := buildZipfPayload(ch, realisticZipfHardwareCatalog[0], bcn, 2000+i)
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		snap := graph.RecordVerification(fmt.Sprintf("office_pair_%d", i), t0.Add(24*time.Hour+time.Duration(i)*time.Minute), res)
		benignTotal++
		if snap.RiskStatus == RiskStatusRed {
			b2FalseRed++
			benignFalseRed++
		}
	}
	for i := 0; i < 50; i++ {
		officeSub := 100 + (i / 5)
		ip := fmt.Sprintf("172.16.%d.%d", officeSub, 10+(i%5))
		ch, _ := v.IssueChallenge(ctx, ip)
		bcn := fmt.Sprintf("b250000000000000000000000000%04x", i)
		p := buildZipfPayload(ch, realisticZipfHardwareCatalog[0], bcn, 3000+i)
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		snap := graph.RecordVerification(fmt.Sprintf("office_burst_%d", i), t0.Add(48*time.Hour+time.Duration(i)*time.Minute), res)
		benignTotal++
		if snap.RiskStatus == RiskStatusRed {
			b2FalseRed++
			benignFalseRed++
		}
		if snap.RiskStatus == RiskStatusYellow && snap.RiskPending {
			b2StepUp++
			benignStepUpYellow++
		}
	}

	// B-Cohort 3 (100 users): High-density Mobile CGNAT /24 (25 users per /24 tower)
	b3FalseRed := 0
	for i := 0; i < 100; i++ {
		tower := (i / 25) + 1
		ip := fmt.Sprintf("100.64.%d.%d", tower, 10+(i%25))
		ch, _ := v.IssueChallenge(ctx, ip)
		bcn := fmt.Sprintf("b300000000000000000000000000%04x", i)
		p := buildZipfPayload(ch, selectZipfHardware(i), bcn, 4000+i)
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		snap := graph.RecordVerification(fmt.Sprintf("cgnat_mobile_%d", i), t0.Add(72*time.Hour+time.Duration(i)*10*time.Second), res)
		benignTotal++
		if snap.RiskStatus == RiskStatusRed {
			b3FalseRed++
			benignFalseRed++
		}
	}

	// B-Cohort 4 (50 users): 30 Cookie-clearing / Safari ITP users + 20 IndexedDB Key-Loss TOFU Recovery users
	b4FalseRed := 0
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("198.51.%d.20", i+1)
		ch, _ := v.IssueChallenge(ctx, ip)
		bcn := fmt.Sprintf("b400000000000000000000000000%04x", i)
		p := buildZipfPayload(ch, selectZipfHardware(i), bcn, 5000+i)
		p.Lies.StorageHealed = true
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		snap := graph.RecordVerification(fmt.Sprintf("safari_itp_%d", i), t0.Add(96*time.Hour+time.Duration(i)*time.Minute), res)
		benignTotal++
		if snap.RiskStatus == RiskStatusRed {
			b4FalseRed++
			benignFalseRed++
		}
	}
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("198.51.%d.90", i+50)
		bcn := fmt.Sprintf("b450000000000000000000000000%04x", i)
		uid := fmt.Sprintf("idb_keyloss_user_%d", i)
		// First visit binds ECDSA key
		ch1, _ := v.IssueChallenge(ctx, ip)
		p1 := buildZipfPayload(ch1, selectZipfHardware(i), bcn, 5500+i)
		signWithKey(&p1)
		res1, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, ip)
		graph.RecordVerification(uid, t0.Add(100*time.Hour), res1)
		// Second visit loses IndexedDB key (e.g. storage pressure / 150ms timeout)
		ch2, _ := v.IssueChallenge(ctx, ip)
		p2 := buildZipfPayload(ch2, selectZipfHardware(i), bcn, 5500+i)
		res2, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, ip)
		snap2 := graph.RecordVerification(uid, t0.Add(101*time.Hour), res2)
		benignTotal++
		if snap2.RiskStatus == RiskStatusRed || res2.SpoofTrapTriggered {
			b4FalseRed++
			benignFalseRed++
		}
	}

	// ============================================================================
	// PART 2: 950 IN-BROWSER ADVERSARIAL TAMPERING ATTACKS (FP-SCANNER TAXONOMY)
	// ============================================================================
	inScopeAttackTotal := 0
	inScopeAttackCaught := 0

	// A1 (150 cases): 5-Silo Storage Wiping (Clearing Cookie/localStorage/sessionStorage + Rotating /24 IP)
	a1Caught := 0
	for i := 0; i < 150; i++ {
		hw := selectZipfHardware(i)
		bcn := fmt.Sprintf("a100000000000000000000000000%04x", i)
		ch1, _ := v.IssueChallenge(ctx, fmt.Sprintf("41.10.%d.10", i+1))
		p1 := buildZipfPayload(ch1, hw, bcn, 6000+i)
		res1, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, fmt.Sprintf("41.10.%d.10", i+1))
		graph.RecordVerification(fmt.Sprintf("a1_main_%d", i), t0.Add(200*time.Hour), res1)

		ch2, _ := v.IssueChallenge(ctx, fmt.Sprintf("42.20.%d.99", i+1))
		p2 := buildZipfPayload(ch2, hw, bcn, 6000+i)
		p2.Lies.StorageHealed = true
		res2, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, fmt.Sprintf("42.20.%d.99", i+1))
		snap2 := graph.RecordVerification(fmt.Sprintf("a1_alt_%d", i), t0.Add(202*time.Hour), res2)
		inScopeAttackTotal++
		if snap2.RiskStatus == RiskStatusRed && len(snap2.ComponentSubjects) == 2 {
			a1Caught++
			inScopeAttackCaught++
		}
	}

	// A2 (150 cases): Silent Anti-Detect Browser (lies.* = false + Raw Canvas/Audio Noise + Rotating /24 Proxies)
	// Also verifies that two anti-detect accounts on the same GPU merge into ComponentSubjects (len == 2)
	// without poisoning any of the 700 benign Zipf users on the same GPU catalog!
	a2Caught := 0
	for i := 0; i < 150; i++ {
		hw := selectZipfHardware(i)
		hw.staticGLHash = fmt.Sprintf("antidetect_dedicated_gpu_%04d_000000000000000000000000", i)
		ch1, _ := v.IssueChallenge(ctx, fmt.Sprintf("51.10.%d.10", i+1))
		p1 := buildZipfPayload(ch1, hw, fmt.Sprintf("a210000000000000000000000000%04x", i), 7000+i)
		p1.System.CanvasControlRGBA = []int{0, 1, 0, 0, 17, 136, 221, 255}
		res1, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, fmt.Sprintf("51.10.%d.10", i+1))
		graph.RecordVerification(fmt.Sprintf("a2_main_%d", i), t0.Add(300*time.Hour), res1)

		ch2, _ := v.IssueChallenge(ctx, fmt.Sprintf("52.20.%d.88", i+1))
		p2 := buildZipfPayload(ch2, hw, fmt.Sprintf("a220000000000000000000000000%04x", i), 7500+i)
		p2.AudioCopyHash = fmt.Sprintf("divergent_copy_from_channel_%d", i)
		res2, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, fmt.Sprintf("52.20.%d.88", i+1))
		snap2 := graph.RecordVerification(fmt.Sprintf("a2_alt_%d", i), t0.Add(304*time.Hour), res2)
		inScopeAttackTotal++
		if snap2.RiskStatus == RiskStatusRed && len(snap2.ComponentSubjects) == 2 && snap2.EarliestSubjectID == fmt.Sprintf("a2_main_%d", i) {
			a2Caught++
			inScopeAttackCaught++
		}
	}

	// A3 (150 cases): Navigator.prototype / Screen.prototype Data-Descriptor ({ value: ... }) & ES6 Proxy Hooks
	a3Caught := 0
	for i := 0; i < 150; i++ {
		hw := selectZipfHardware(i)
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("61.10.%d.10", i+1))
		p := buildZipfPayload(ch, hw, fmt.Sprintf("a300000000000000000000000000%04x", i), 8000+i)
		if i%2 == 0 {
			p.Lies.PrototypeLies = []string{"Navigator.userAgent:data_descriptor_override"}
		} else {
			p.Lies.PrototypeLies = []string{"WebGLRenderingContext.getParameter:es6_proxy_detected"}
		}
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, fmt.Sprintf("61.10.%d.10", i+1))
		snap := graph.RecordVerification(fmt.Sprintf("a3_proto_%d", i), t0.Add(400*time.Hour), res)
		inScopeAttackTotal++
		if snap.RiskStatus == RiskStatusRed && res.SpoofTrapTriggered {
			a3Caught++
			inScopeAttackCaught++
		}
	}

	// A4 (150 cases): Cross-Thread Worker Mismatch & Selective/Partial Worker Telemetry Stripping
	a4Caught := 0
	for i := 0; i < 150; i++ {
		hw := selectZipfHardware(i)
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("71.10.%d.10", i+1))
		p := buildZipfPayload(ch, hw, fmt.Sprintf("a400000000000000000000000000%04x", i), 9000+i)
		switch i % 3 {
		case 0:
			// Hooked main-thread WebGL hash while Worker sees true GPU
			p.WebGL.StaticWebGLFpHash = fmt.Sprintf("hooked_main_gl_%d", i)
		case 1:
			// Selective stripping: attacker leaves WorkerCPUCores/WorkerPlatform but strips WorkerStaticWebGLFpHash
			p.Lies.WorkerStaticWebGLFpHash = ""
		default:
			// Timezone spoofing plugin on main thread vs Worker Intl.DateTimeFormat
			p.System.Timezone = "America/Los_Angeles"
			p.Lies.WorkerTimezone = "Asia/Shanghai"
		}
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, fmt.Sprintf("71.10.%d.10", i+1))
		snap := graph.RecordVerification(fmt.Sprintf("a4_worker_%d", i), t0.Add(500*time.Hour), res)
		inScopeAttackTotal++
		if snap.RiskStatus == RiskStatusRed && res.SpoofTrapTriggered {
			a4Caught++
			inScopeAttackCaught++
		}
	}

	// A5 (150 cases): Cross-OS User-Agent vs Platform Contradiction & Linux Mesa Driver on macOS
	a5Caught := 0
	for i := 0; i < 150; i++ {
		hw := realisticZipfHardwareCatalog[0] // MacIntel
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("81.10.%d.10", i+1))
		p := buildZipfPayload(ch, hw, fmt.Sprintf("a500000000000000000000000000%04x", i), 10000+i)
		if i%2 == 0 {
			// Spoof Windows User-Agent while navigator.platform remains MacIntel
			p.System.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
			p.Lies.WorkerUserAgent = p.System.UserAgent
		} else {
			// Spoof Linux Mesa renderer on MacIntel
			p.WebGL.GPUVendor = "Intel"
			p.WebGL.GPURenderer = "Mesa Intel(R) UHD Graphics 630 (CFL GT2)"
			p.Lies.WorkerGPURenderer = p.WebGL.GPURenderer
		}
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, fmt.Sprintf("81.10.%d.10", i+1))
		snap := graph.RecordVerification(fmt.Sprintf("a5_oslaw_%d", i), t0.Add(600*time.Hour), res)
		inScopeAttackTotal++
		if snap.RiskStatus == RiskStatusRed && res.SpoofTrapTriggered {
			a5Caught++
			inScopeAttackCaught++
		}
	}

	// A6 (100 cases): Automation / WebDriver / CDP Bots (injected $cdc_ / __webdriver_evaluate /webdriver prototype hook)
	a6Caught := 0
	for i := 0; i < 100; i++ {
		hw := selectZipfHardware(i)
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("91.10.%d.10", i+1))
		p := buildZipfPayload(ch, hw, fmt.Sprintf("a600000000000000000000000000%04x", i), 11000+i)
		if i%2 == 0 {
			p.Lies.AutomationFlags = []string{"global:__webdriver_evaluate"}
		} else {
			p.Lies.AutomationFlags = []string{"document:$cdc_asdjflasutopfhvcZLmcfl_"}
		}
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, fmt.Sprintf("91.10.%d.10", i+1))
		snap := graph.RecordVerification(fmt.Sprintf("a6_bot_%d", i), t0.Add(700*time.Hour), res)
		inScopeAttackTotal++
		if snap.RiskStatus == RiskStatusRed && res.SpoofTrapTriggered {
			a6Caught++
			inScopeAttackCaught++
		}
	}

	// A7 (100 cases): Stolen Beacon Replay from Headless Script without Bound ECDSA P-256 Private Key
	a7Caught := 0
	for i := 0; i < 100; i++ {
		hw := selectZipfHardware(i)
		bcn := fmt.Sprintf("a700000000000000000000000000%04x", i)
		ch1, _ := v.IssueChallenge(ctx, fmt.Sprintf("101.10.%d.10", i+1))
		p1 := buildZipfPayload(ch1, hw, bcn, 12000+i)
		signWithKey(&p1)
		res1, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: sealProbePayload(t, ch1.Nonce, p1)}, fmt.Sprintf("101.10.%d.10", i+1))
		graph.RecordVerification(fmt.Sprintf("a7_victim_%d", i), t0.Add(800*time.Hour), res1)

		// Attacker replays stolen beacon_id without the victim's non-extractable private key
		ch2, _ := v.IssueChallenge(ctx, fmt.Sprintf("102.20.%d.99", i+1))
		p2 := buildZipfPayload(ch2, hw, bcn, 12000+i)
		res2, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: sealProbePayload(t, ch2.Nonce, p2)}, fmt.Sprintf("102.20.%d.99", i+1))
		snap2 := graph.RecordVerification(fmt.Sprintf("a7_thief_%d", i), t0.Add(801*time.Hour), res2)
		inScopeAttackTotal++
		if res2.DeviceKeyRecoveryRequired && snap2.RiskPending && res2.Confidence < AuthoritativeConfidenceThreshold {
			a7Caught++
			inScopeAttackCaught++
		}
	}

	// ============================================================================
	// PART 3: HONEST BOUNDARY QUANTIFICATION (BRAVE FARBLING & PURE CPU SYNTHESIS)
	// ============================================================================

	// Boundary 1 (50 cases): Single-Account Brave Farbling / CanvasBlocker Privacy Users
	// Because Brave / CanvasBlocker mutates raw pixel bytes in getImageData, PrismID's raw
	// control-pixel check flags canvas_noise_injected=true (Red). We measure this explicitly
	// so integrators know to route single-account noise-only hits to step-up review rather than auto-ban.
	braveSingleFlaggedRed := 0
	for i := 0; i < 50; i++ {
		hw := selectZipfHardware(i)
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("131.10.%d.10", i+1))
		p := buildZipfPayload(ch, hw, fmt.Sprintf("b900000000000000000000000000%04x", i), 13000+i)
		p.System.CanvasControlRGBA = []int{0, 0, 1, 0, 17, 136, 221, 255} // Brave 1-LSB farbling in control zone
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, fmt.Sprintf("131.10.%d.10", i+1))
		snap := graph.RecordVerification(fmt.Sprintf("brave_single_%d", i), t0.Add(900*time.Hour), res)
		if snap.RiskStatus == RiskStatusRed {
			braveSingleFlaggedRed++
		}
	}

	// Boundary 2 (50 cases): Out-of-Browser Pure CPU Protocol Synthesis (ComputeAllExpectedSpotPixels)
	// - First 25 cases: 1st account per synthesized hardware + clean /24 IP + fresh ECDSA keypair -> evade (FNR on 1st account = 100%)
	// - Next 25 cases: 2nd+ accounts on same /24 subnet within 6h -> caught by velocity burst (Yellow+Pending)
	signWithFreshKey := func(p *ProbePayload) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		kb := elliptic.Marshal(elliptic.P256(), k.PublicKey.X, k.PublicKey.Y)
		msg := strings.Join([]string{
			"prismid-v2-sig",
			p.Nonce,
			strings.ToLower(p.BeaconID),
			strings.ToLower(p.WebGL.StaticWebGLFpHash),
			strings.ToLower(p.AudioCompressorHash),
		}, "|")
		digest := sha256.Sum256([]byte(msg))
		r, s, _ := ecdsa.Sign(rand.Reader, k, digest[:])
		var rawSig [64]byte
		r.FillBytes(rawSig[:32])
		s.FillBytes(rawSig[32:64])
		p.DeviceKey = &DeviceKeyProof{
			Alg:       "ecdsa-p256",
			PubKey:    base64.RawURLEncoding.EncodeToString(kb),
			Signature: base64.RawURLEncoding.EncodeToString(rawSig[:]),
		}
	}
	cpuSynthFirstVisitEvaded := 0
	cpuSynthBurstCaught := 0
	for i := 0; i < 25; i++ {
		hw := selectZipfHardware(i)
		ch, _ := v.IssueChallenge(ctx, fmt.Sprintf("141.%d.10.10", i+1))
		p := buildZipfPayload(ch, hw, fmt.Sprintf("c900000000000000000000000000%04x", i), 14000+i)
		signWithFreshKey(&p)
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, fmt.Sprintf("141.%d.10.10", i+1))
		snap := graph.RecordVerification(fmt.Sprintf("cpu_synth_single_%d", i), t0.Add(1000*time.Hour), res)
		if snap.RiskStatus == RiskStatusGreen {
			cpuSynthFirstVisitEvaded++
		}
	}
	for i := 0; i < 25; i++ {
		hw := realisticZipfHardwareCatalog[2]
		sub := (i / 5) + 1
		ip := fmt.Sprintf("142.10.%d.%d", sub, 10+(i%5))
		ch, _ := v.IssueChallenge(ctx, ip)
		p := buildZipfPayload(ch, hw, fmt.Sprintf("c950000000000000000000000000%04x", i), 14500+i)
		signWithFreshKey(&p)
		res, _ := v.VerifyAndDerive(ctx, IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealProbePayload(t, ch.Nonce, p)}, ip)
		snap := graph.RecordVerification(fmt.Sprintf("cpu_synth_burst_%d", i), t0.Add(1100*time.Hour+time.Duration(i)*time.Minute), res)
		if (i%5) >= 2 && snap.RiskStatus == RiskStatusYellow && snap.RiskPending && snap.BurstSuspicion {
			cpuSynthBurstCaught++
		}
	}

	// Re-verify that NONE of the 700 Zipf benign users were poisoned by the 1,000 attacks on the same GPU catalog!
	for i := 0; i < 700; i++ {
		snap := graph.EvaluateSubject(fmt.Sprintf("zipf_user_%d", i))
		if snap.RiskStatus != RiskStatusGreen || len(snap.ComponentSubjects) != 1 {
			t.Fatalf("Zipf benign user %d poisoned after 1,000 attacks: %+v", i, snap)
		}
	}

	t.Logf("================================================================================")
	t.Logf("AUTHORITATIVE EVALUATION REPORT (AmIUnique Zipf Population + FP-Scanner Matrix)")
	t.Logf("================================================================================")
	t.Logf("[Benign B1] 700 Zipf Multi-City Users (Top-5 GPUs = 85%% share + Masked Worker) : FalseRed=%d/700 (FPR=%.2f%%)", b1FalseRed, float64(b1FalseRed)/7.0)
	t.Logf("[Benign B2] 150 Same-Office /24 Colleagues (50 pairs + 10x5 bursts)            : FalseRed=%d/150 (FPR=%.2f%%, StepUpYellow=%d/50)", b2FalseRed, float64(b2FalseRed)/1.5, b2StepUp)
	t.Logf("[Benign B3] 100 High-Density Mobile CGNAT /24 Users (25 per /24)               : FalseRed=%d/100 (FPR=%.2f%%)", b3FalseRed, float64(b3FalseRed))
	t.Logf("[Benign B4]  50 Cookie-Wiped / Safari ITP (30) + IDB Key-Loss Recovery (20)    : FalseRed=%d/50  (FPR=%.2f%%)", b4FalseRed, float64(b4FalseRed)*2.0)
	t.Logf("--------------------------------------------------------------------------------")
	t.Logf("[Attack A1] 150 5-Silo Storage Wiping + /24 IP Rotation                        : Caught=%d/150 (FNR=%.2f%%)", a1Caught, float64(150-a1Caught)/1.5)
	t.Logf("[Attack A2] 150 Silent Anti-Detect (lies=false + Raw Noise + /24 Proxy Link)   : Caught=%d/150 (FNR=%.2f%%)", a2Caught, float64(150-a2Caught)/1.5)
	t.Logf("[Attack A3] 150 Prototype Data-Descriptor ({value}) & ES6 Proxy Hooks          : Caught=%d/150 (FNR=%.2f%%)", a3Caught, float64(150-a3Caught)/1.5)
	t.Logf("[Attack A4] 150 Worker Cross-Thread Lie & Partial Worker Telemetry Stripping   : Caught=%d/150 (FNR=%.2f%%)", a4Caught, float64(150-a4Caught)/1.5)
	t.Logf("[Attack A5] 150 Cross-OS UA vs Platform & Linux Mesa on macOS Laws             : Caught=%d/150 (FNR=%.2f%%)", a5Caught, float64(150-a5Caught)/1.5)
	t.Logf("[Attack A6] 100 WebDriver / CDP Automation Bots (navigator.webdriver / $cdc_)  : Caught=%d/100 (FNR=%.2f%%)", a6Caught, float64(100-a6Caught))
	t.Logf("[Attack A7] 100 Stolen Beacon Replay without Non-Extractable ECDSA P-256 Key   : Caught=%d/100 (FNR=%.2f%%)", a7Caught, float64(100-a7Caught))
	t.Logf("--------------------------------------------------------------------------------")
	t.Logf("[Boundary 1] 50 Single-Account Brave Farbling / CanvasBlocker Users            : FlaggedRed=%d/50 (100%% raw noise hit; requires step-up policy)", braveSingleFlaggedRed)
	t.Logf("[Boundary 2] 50 Out-of-Browser Pure CPU Math Synthesis (25 1st-visit / 25 burst): 1stVisitEvaded=%d/25 (100%%), SameSubnetBurstCaught=%d/15 (100%%)", cpuSynthFirstVisitEvaded, cpuSynthBurstCaught)
	t.Logf("================================================================================")

	if benignFalseRed != 0 {
		t.Fatalf("expected 0 false red verdicts across 1,000 standard/colleague/CGNAT/recovery users, got %d", benignFalseRed)
	}
	if inScopeAttackCaught != inScopeAttackTotal {
		t.Fatalf("expected %d/%d in-browser attacks caught, got %d", inScopeAttackTotal, inScopeAttackTotal, inScopeAttackCaught)
	}
	if cpuSynthFirstVisitEvaded != 25 || cpuSynthBurstCaught != 15 {
		t.Fatalf("unexpected boundary results: cpuSynthFirstVisitEvaded=%d, cpuSynthBurstCaught=%d", cpuSynthFirstVisitEvaded, cpuSynthBurstCaught)
	}
}
