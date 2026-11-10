package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

// AccuracyCohortResult summarizes the confusion-matrix metrics for one synthetic regression cohort.
type AccuracyCohortResult struct {
	Category     string
	CohortName   string
	TotalCases   int
	CorrectCount int
	ErrorCount   int
	RateLabel    string
	ErrorRatePct float64
}

// BuildValidPayload constructs a baseline valid ProbePayload for a given Challenge.
func BuildValidPayload(ch *prismid.Challenge) prismid.ProbePayload {
	spots := prismid.ComputeAllExpectedSpotPixels(ch.SamplePoints, ch.RenderSeed)
	return prismid.ProbePayload{
		Version:     1,
		Nonce:       ch.Nonce,
		CollectedAt: time.Now().UnixMilli(),
		WebGL: prismid.WebGLProbeData{
			GPUVendor:         "Apple",
			GPURenderer:       "Apple M1 Pro",
			WebGLLimitsVector: "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|a1b2c3d4",
			StaticWebGLFpHash: "7c4a8d09ca3762af61e59520943dc26494f8941b00112233445566778899aabb",
			SpotPixels:        spots,
		},
		AudioCompressorHash: "4a9e8b7c6d5f4e3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a",
		System: prismid.SystemProbeData{
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
		Lies: prismid.LieProbeData{
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

// RunFullConfusionMatrixBenchmark executes 1,000 synthetic rule-regression scenarios
// (500 benign users across high-collision environments + 500 adversarial multi-account /
// anti-detect / hook scenarios) to verify the decision-table invariants of Verifier and RiskGraph.
//
// Note: As documented in README.md and ARCHITECTURE.md, these 1,000 cases are synthetic protocol
// and graph-rule regression vectors verifying that the engine's correlation rules do not suffer
// from model-collision false merges or browser-upgrade beacon drift; they are not a substitute
// for live traffic telemetry across external anti-detect products.
func RunFullConfusionMatrixBenchmark() ([]AccuracyCohortResult, float64, float64, error) {
	ctx := context.Background()
	v := prismid.NewVerifier(prismid.Config{
		HMACSecret:               []byte("benchmark-hmac-secret-key-32-bytes-long"),
		ChallengeTTL:             60 * time.Second,
		SpotPixelTolerance:       2,
		MaxDistinctGPUsPerSubnet: 3,
	}, nil)
	graph := prismid.NewRiskGraph(prismid.AuthoritativeConfidenceThreshold)

	seal := func(nonce string, p prismid.ProbePayload) (string, error) {
		raw, err := json.Marshal(p)
		if err != nil {
			return "", err
		}
		return prismid.SealPayload(nonce, nil, raw)
	}

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var results []AccuracyCohortResult

	// ========================================================================
	// PART A: 500 BENIGN USERS (Measuring Rule-Level False Positive Rate / FPR)
	// ========================================================================

	// Cohort FP-1: 200 Innocent Users Across Different Cities Owning the Exact Same Stock MacBook Pro M3
	// All 200 share the exact same StaticWebGLFpHash, WebGLLimitsVector, and AudioCompressorHash (d_gpu_* 100% identical)
	// AND register only 1 minute apart (25+ concurrent users inside every 25-minute window)!
	fp1Errors := 0
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("114.%d.%d.10", (i/50)+10, (i%50)+1)
		ch, err := v.IssueChallenge(ctx, ip)
		if err != nil {
			return nil, 0, 0, err
		}
		p := BuildValidPayload(ch)
		p.BeaconID = fmt.Sprintf("a100000000000000000000000000%04x", i)
		// Same stock M3 MacBook Pro GPU & Audio across all 200 users
		p.WebGL.StaticWebGLFpHash = "stock_apple_m3_pro_webgl_hash_00000000000000000000000000000000"
		p.Lies.WorkerStaticWebGLFpHash = p.WebGL.StaticWebGLFpHash
		// Each user has their own local font subset / canvas rendering context in their city
		p.System.FontsBitmapHash = fmt.Sprintf("city_user_font_subset_%04d", i)
		sealed, err := seal(ch.Nonce, p)
		if err != nil {
			return nil, 0, 0, err
		}
		res, err := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealed}, ip)
		if err != nil {
			return nil, 0, 0, err
		}
		// Users register only 1 minute apart (high concurrency across cities!)
		userTime := baseTime.Add(time.Duration(i) * time.Minute)
		snap := graph.RecordVerification(fmt.Sprintf("benign_m3_user_%d", i), userTime, res)
		if snap.RiskStatus != prismid.RiskStatusGreen {
			fp1Errors++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FPR (防误杀)",
		CohortName:   "FP-1: 异地 200 台同款 MacBook Pro M3 正常用户 (间隔 1m 高并发，d_gpu_* 100% 相同)",
		TotalCases:   200,
		CorrectCount: 200 - fp1Errors,
		ErrorCount:   fp1Errors,
		RateLabel:    fmt.Sprintf("FPR = %.2f%%", float64(fp1Errors)/200.0*100.0),
		ErrorRatePct: float64(fp1Errors) / 200.0 * 100.0,
	})

	// Cohort FP-2: 150 Innocent Users on Shared /24 Subnets:
	// - Cases 0..99: 50 pairs of office colleagues on the SAME /24 Wi-Fi owning the EXACT SAME company-issued
	//   MacBook model (sharing BOTH d_gpu_* AND d_sys_* -> identical d_gpusys_*!), registering 5m or 48h apart!
	// - Cases 100..149: 50 unrelated mobile users behind the EXACT SAME carrier-grade NAT (CGNAT /24 `100.64.1.0/24`)
	//   registering within 15 minutes (exceeding MaxDistinctGPUsPerSubnet)!
	fp2Errors := 0
	officeBaseTime := baseTime.Add(1000 * time.Hour)
	for i := 0; i < 150; i++ {
		var ip string
		var gpuHash string
		var userTime time.Time

		if i < 100 {
			pairIdx := i / 2
			ip = fmt.Sprintf("198.51.%d.%d", 10+(pairIdx/10), 10+(pairIdx%10)*2+(i%2)) // Same /24 per office pair!
			// Both colleagues in each pair share the EXACT SAME company MacBook GPU hash (identical d_gpusys_*)!
			gpuHash = fmt.Sprintf("company_issued_m3_batch_%02d_000000000000000000000000", pairIdx)
			if pairIdx%2 == 0 {
				// Registering 5 minutes apart
				userTime = officeBaseTime.Add(time.Duration(i%2) * 5 * time.Minute)
			} else {
				// Registering 48 hours apart
				userTime = officeBaseTime.Add(time.Duration(i%2) * 48 * time.Hour)
			}
		} else {
			// 50 mobile users sharing a single CGNAT /24 (`100.64.1.0/24`) within 15 minutes
			cgnatIdx := i - 100
			ip = fmt.Sprintf("100.64.1.%d", 10+cgnatIdx)
			gpuHash = fmt.Sprintf("mobile_cgnat_device_gpu_%04d_0000000000000000000000", cgnatIdx)
			userTime = officeBaseTime.Add(time.Duration(cgnatIdx) * 15 * time.Second)
		}

		ch, err := v.IssueChallenge(ctx, ip)
		if err != nil {
			return nil, 0, 0, err
		}
		p := BuildValidPayload(ch)
		p.BeaconID = fmt.Sprintf("b200000000000000000000000000%04x", i)
		p.WebGL.StaticWebGLFpHash = gpuHash
		p.Lies.WorkerStaticWebGLFpHash = gpuHash
		sealed, err := seal(ch.Nonce, p)
		if err != nil {
			return nil, 0, 0, err
		}
		res, err := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch.Nonce, SealedPayload: sealed}, ip)
		if err != nil {
			return nil, 0, 0, err
		}
		snap := graph.RecordVerification(fmt.Sprintf("benign_office_cgnat_user_%d", i), userTime, res)
		if snap.RiskStatus != prismid.RiskStatusGreen {
			fp2Errors++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FPR (防误杀)",
		CohortName:   "FP-2: 100 名同网段同款办公本同事 (d_gpusys_* 相同) + 50 名同 /24 CGNAT 移动用户",
		TotalCases:   150,
		CorrectCount: 150 - fp2Errors,
		ErrorCount:   fp2Errors,
		RateLabel:    fmt.Sprintf("FPR = %.2f%%", float64(fp2Errors)/150.0*100.0),
		ErrorRatePct: float64(fp2Errors) / 150.0 * 100.0,
	})

	// Cohort FP-3: 150 Existing Users Upgrading Chrome (130 -> 131 where WebGL static hash, WebGL extension list,
	// Audio hash, Canvas 2D hash, and 4K monitor ScreenSpec ALL change!) + 75 Single Users Clearing Cookies (StorageHealed=true)
	fp3Errors := 0
	for i := 0; i < 150; i++ {
		uid := fmt.Sprintf("benign_upgrade_user_%d", i)
		bcn := fmt.Sprintf("c300000000000000000000000000%04x", i)
		gpuHashDay1 := fmt.Sprintf("upgrade_user_gpu_v130_%04d_000000000000000000000000", i)
		tUser := baseTime.Add(time.Duration(2000+i*5) * time.Hour)

		// Day 1: Chrome 130 on Built-in Retina Display at Home Wi-Fi
		ip1 := fmt.Sprintf("120.24.%d.10", (i%200)+1)
		ch1, _ := v.IssueChallenge(ctx, ip1)
		p1 := BuildValidPayload(ch1)
		p1.BeaconID = bcn
		p1.WebGL.StaticWebGLFpHash = gpuHashDay1
		p1.Lies.WorkerStaticWebGLFpHash = gpuHashDay1
		s1, _ := seal(ch1.Nonce, p1)
		res1, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: s1}, ip1)
		graph.RecordVerification(uid, tUser, res1)

		// Day 14: Upgraded to Chrome 131 — ANGLE shader hash, WebGL extension hash, Audio hash, Canvas 2D hash,
		// ScreenSpec, and IP ALL changed! Half of users also cleared browser Cookies (StorageHealed = true)!
		ip2 := fmt.Sprintf("121.35.%d.88", (i%200)+1)
		ch2, _ := v.IssueChallenge(ctx, ip2)
		p2 := BuildValidPayload(ch2)
		p2.BeaconID = bcn
		gpuHashDay14 := fmt.Sprintf("upgrade_user_gpu_v131_new_angle_%04d_999999999999", i)
		p2.WebGL.StaticWebGLFpHash = gpuHashDay14
		p2.Lies.WorkerStaticWebGLFpHash = gpuHashDay14
		p2.WebGL.WebGLLimitsVector = "16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|new_ext_hash_131"
		p2.AudioCompressorHash = fmt.Sprintf("chrome131_new_audio_hash_%04d_abcdef0123456789", i)
		p2.System.Canvas2DHash = fmt.Sprintf("chrome131_new_canvas_%d", i)
		p2.System.ScreenSpec = "3840x2160x30@2"
		if i%2 == 1 {
			p2.Lies.StorageHealed = true // Safari ITP / single-user cookie cleanup
		}
		s2, _ := seal(ch2.Nonce, p2)
		res2, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: s2}, ip2)
		snap2 := graph.RecordVerification(uid, tUser.Add(14*24*time.Hour), res2)

		// Must still keep the exact same BeaconSliceID and remain Green!
		if res1.BeaconSliceID != res2.BeaconSliceID || snap2.RiskStatus != prismid.RiskStatusGreen {
			fp3Errors++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FPR (纵向稳定)",
		CohortName:   "FP-3: 150 名老用户升级浏览器 (GPU/Audio/Canvas/副屏全变) + 单用户清 Cookie 自愈",
		TotalCases:   150,
		CorrectCount: 150 - fp3Errors,
		ErrorCount:   fp3Errors,
		RateLabel:    fmt.Sprintf("Drift = %.2f%%", float64(fp3Errors)/150.0*100.0),
		ErrorRatePct: float64(fp3Errors) / 150.0 * 100.0,
	})

	// ========================================================================
	// PART B: 500 ADVERSARIAL ATTACKS (Measuring Rule-Level False Negative Rate / FNR)
	// ========================================================================

	// Cohort FN-1: 100 Attacks Wiping Cookies & localStorage (Resurrected by IndexedDB/CacheStorage/OPFS 5-Silo Beacon)
	fn1Missed := 0
	for i := 0; i < 100; i++ {
		bcn := fmt.Sprintf("d400000000000000000000000000%04x", i)
		gpuHash := fmt.Sprintf("wiper_attacker_gpu_%04d_000000000000000000000000000000", i)
		tAtk := baseTime.Add(time.Duration(4000+i*10) * time.Hour)

		// Account 1 (Initial registration)
		ip1 := fmt.Sprintf("101.80.%d.11", (i%200)+1)
		ch1, _ := v.IssueChallenge(ctx, ip1)
		p1 := BuildValidPayload(ch1)
		p1.BeaconID = bcn
		p1.WebGL.StaticWebGLFpHash = gpuHash
		p1.Lies.WorkerStaticWebGLFpHash = gpuHash
		s1, _ := seal(ch1.Nonce, p1)
		res1, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: s1}, ip1)
		graph.RecordVerification(fmt.Sprintf("wiper_main_%d", i), tAtk, res1)

		// Account 2 (Attacker wiped localStorage & cookies + changed IP, 8 hours later; IndexedDB healed beacon_id!)
		ip2 := fmt.Sprintf("102.90.%d.22", (i%200)+1)
		ch2, _ := v.IssueChallenge(ctx, ip2)
		p2 := BuildValidPayload(ch2)
		p2.BeaconID = bcn
		p2.Lies.StorageHealed = true
		p2.WebGL.StaticWebGLFpHash = gpuHash
		p2.Lies.WorkerStaticWebGLFpHash = gpuHash
		s2, _ := seal(ch2.Nonce, p2)
		res2, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: s2}, ip2)
		snap2 := graph.RecordVerification(fmt.Sprintf("wiper_alt_%d", i), tAtk.Add(8*time.Hour), res2)
		if snap2.RiskStatus != prismid.RiskStatusRed {
			fn1Missed++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FNR (防漏报)",
		CohortName:   "FN-1: 100 次 F12 清空 Cookie/LocalStorage + 换 IP 注册小号 (5 源自愈信标拦截)",
		TotalCases:   100,
		CorrectCount: 100 - fn1Missed,
		ErrorCount:   fn1Missed,
		RateLabel:    fmt.Sprintf("FNR = %.2f%% (Recall %.1f%%)", float64(fn1Missed), float64(100-fn1Missed)),
		ErrorRatePct: float64(fn1Missed),
	})

	// Cohort FN-2: 100 Anti-Detect Browser Attacks (Injecting Canvas/Audio noise + fresh beacon_id + rotating /24 proxy IPs + 6h delay)
	fn2Missed := 0
	for i := 0; i < 100; i++ {
		gpuHash := fmt.Sprintf("antidetect_gpu_%04d_0000000000000000000000000000000000", i)
		tAtk := baseTime.Add(time.Duration(6000+i*10) * time.Hour)

		// Account 1 on Residential Proxy IP 1
		ip1 := fmt.Sprintf("45.10.%d.10", (i%200)+1)
		ch1, _ := v.IssueChallenge(ctx, ip1)
		p1 := BuildValidPayload(ch1)
		p1.BeaconID = fmt.Sprintf("e501000000000000000000000000%04x", i)
		p1.WebGL.StaticWebGLFpHash = gpuHash
		p1.Lies.WorkerStaticWebGLFpHash = gpuHash
		s1, _ := seal(ch1.Nonce, p1)
		res1, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: s1}, ip1)
		graph.RecordVerification(fmt.Sprintf("adspower_main_%d", i), tAtk, res1)

		// Account 2 on Residential Proxy IP 2 (6 hours later, brand new profile, Canvas/Audio noise injected!)
		ip2 := fmt.Sprintf("89.20.%d.99", (i%200)+1)
		ch2, _ := v.IssueChallenge(ctx, ip2)
		p2 := BuildValidPayload(ch2)
		p2.BeaconID = fmt.Sprintf("e502000000000000000000000000%04x", i)
		p2.WebGL.StaticWebGLFpHash = gpuHash
		p2.Lies.WorkerStaticWebGLFpHash = gpuHash
		p2.System.Canvas2DHash = fmt.Sprintf("random_canvas_noise_%d", i)
		p2.System.FontsBitmapHash = fmt.Sprintf("random_font_subset_%d", i)
		p2.System.ScreenSpec = "1920x1080x24@1"
		p2.Lies.CanvasNoiseInjected = true
		s2, _ := seal(ch2.Nonce, p2)
		res2, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: s2}, ip2)
		snap2 := graph.RecordVerification(fmt.Sprintf("adspower_alt_%d", i), tAtk.Add(6*time.Hour), res2)
		if snap2.RiskStatus != prismid.RiskStatusRed {
			fn2Missed++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FNR (防漏报)",
		CohortName:   "FN-2: 100 次指纹浏览器 (Canvas 加噪 + 换住宅代理 IP + 隔 6h 慢速养号)",
		TotalCases:   100,
		CorrectCount: 100 - fn2Missed,
		ErrorCount:   fn2Missed,
		RateLabel:    fmt.Sprintf("FNR = %.2f%% (Recall %.1f%%)", float64(fn2Missed), float64(100-fn2Missed)),
		ErrorRatePct: float64(fn2Missed),
	})

	// Cohort FN-3: 100 Main-Thread Hook Attacks (Spoofing window.navigator / WebGL / Timezone) + Rotating Proxy IPs
	fn3Missed := 0
	for i := 0; i < 100; i++ {
		realGPUHash := fmt.Sprintf("hook_real_gpu_%04d_0000000000000000000000000000000000", i)
		tAtk := baseTime.Add(time.Duration(8000+i*10) * time.Hour)

		ip1 := fmt.Sprintf("66.30.%d.15", (i%200)+1)
		ch1, _ := v.IssueChallenge(ctx, ip1)
		p1 := BuildValidPayload(ch1)
		p1.BeaconID = fmt.Sprintf("f601000000000000000000000000%04x", i)
		p1.WebGL.StaticWebGLFpHash = realGPUHash
		p1.Lies.WorkerStaticWebGLFpHash = realGPUHash
		s1, _ := seal(ch1.Nonce, p1)
		res1, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: s1}, ip1)
		graph.RecordVerification(fmt.Sprintf("hook_main_%d", i), tAtk, res1)

		// Account 2 hooks main-thread WebGL & Timezone, but inline Blob Worker + OffscreenCanvas catches it!
		ip2 := fmt.Sprintf("77.40.%d.88", (i%200)+1)
		ch2, _ := v.IssueChallenge(ctx, ip2)
		p2 := BuildValidPayload(ch2)
		p2.BeaconID = fmt.Sprintf("f602000000000000000000000000%04x", i)
		p2.WebGL.StaticWebGLFpHash = fmt.Sprintf("hooked_fake_main_webgl_%d", i)
		p2.Lies.WorkerStaticWebGLFpHash = realGPUHash
		p2.System.Timezone = "America/New_York"
		p2.Lies.WorkerTimezone = "Asia/Shanghai"
		s2, _ := seal(ch2.Nonce, p2)
		res2, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: s2}, ip2)
		snap2 := graph.RecordVerification(fmt.Sprintf("hook_alt_%d", i), tAtk.Add(12*time.Hour), res2)
		if snap2.RiskStatus != prismid.RiskStatusRed {
			fn3Missed++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FNR (防漏报)",
		CohortName:   "FN-3: 100 次插件篡改主线程 WebGL/时区 + 换代理 IP (Worker 跨线程测谎拦截)",
		TotalCases:   100,
		CorrectCount: 100 - fn3Missed,
		ErrorCount:   fn3Missed,
		RateLabel:    fmt.Sprintf("FNR = %.2f%% (Recall %.1f%%)", float64(fn3Missed), float64(100-fn3Missed)),
		ErrorRatePct: float64(fn3Missed),
	})

	// Cohort FN-4: 100 Clean Incognito Multi-Account Farming Batches (>=3 Accounts per Batch: 50 Same-Network + 50 Proxy Burst)
	fn4Missed := 0
	for i := 0; i < 100; i++ {
		gpuHash := fmt.Sprintf("incognito_gpu_%04d_0000000000000000000000000000000000", i)
		canvasHash := fmt.Sprintf("incognito_canvas_%04d", i)
		tAtk := baseTime.Add(time.Duration(10000+i*10) * time.Hour)

		// Account 1 (Initial registration)
		ip1 := fmt.Sprintf("91.50.%d.10", (i%200)+1)
		ch1, _ := v.IssueChallenge(ctx, ip1)
		p1 := BuildValidPayload(ch1)
		p1.BeaconID = fmt.Sprintf("9701000000000000000000000000%04x", i)
		p1.WebGL.StaticWebGLFpHash = gpuHash
		p1.Lies.WorkerStaticWebGLFpHash = gpuHash
		p1.System.Canvas2DHash = canvasHash
		s1, _ := seal(ch1.Nonce, p1)
		res1, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: s1}, ip1)
		graph.RecordVerification(fmt.Sprintf("incog_main_%d", i), tAtk, res1)

		var ip2, ip3 string
		var delay2, delay3 time.Duration
		if i < 50 {
			// Same /24 network Incognito farming batch (3 accounts within 4 hours -> caught by d_gpusys_* burst >= 3)
			ip2 = fmt.Sprintf("91.50.%d.55", (i%200)+1)
			ip3 = fmt.Sprintf("91.50.%d.99", (i%200)+1)
			delay2 = 2 * time.Hour
			delay3 = 4 * time.Hour
		} else {
			// Rotating proxy IP Incognito farming burst (3 accounts within 16 minutes -> caught by d_web_* burst >= 3)
			ip2 = fmt.Sprintf("92.60.%d.77", (i%200)+1)
			ip3 = fmt.Sprintf("93.70.%d.88", (i%200)+1)
			delay2 = 8 * time.Minute
			delay3 = 16 * time.Minute
		}

		ch2, _ := v.IssueChallenge(ctx, ip2)
		p2 := BuildValidPayload(ch2)
		p2.BeaconID = fmt.Sprintf("9702000000000000000000000000%04x", i)
		p2.WebGL.StaticWebGLFpHash = gpuHash
		p2.Lies.WorkerStaticWebGLFpHash = gpuHash
		p2.System.Canvas2DHash = canvasHash
		s2, _ := seal(ch2.Nonce, p2)
		res2, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: s2}, ip2)
		graph.RecordVerification(fmt.Sprintf("incog_alt1_%d", i), tAtk.Add(delay2), res2)

		ch3, _ := v.IssueChallenge(ctx, ip3)
		p3 := BuildValidPayload(ch3)
		p3.BeaconID = fmt.Sprintf("9703000000000000000000000000%04x", i)
		p3.WebGL.StaticWebGLFpHash = gpuHash
		p3.Lies.WorkerStaticWebGLFpHash = gpuHash
		p3.System.Canvas2DHash = canvasHash
		s3, _ := seal(ch3.Nonce, p3)
		res3, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch3.Nonce, SealedPayload: s3}, ip3)
		snap3 := graph.RecordVerification(fmt.Sprintf("incog_alt2_%d", i), tAtk.Add(delay3), res3)

		if snap3.RiskStatus != prismid.RiskStatusRed {
			fn4Missed++
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FNR (防漏报)",
		CohortName:   "FN-4: 100 次纯净无痕模式批量养号 (>=3 号簇：50 同网段跨时 + 50 代理池连发)",
		TotalCases:   100,
		CorrectCount: 100 - fn4Missed,
		ErrorCount:   fn4Missed,
		RateLabel:    fmt.Sprintf("FNR = %.2f%% (Recall %.1f%%)", float64(fn4Missed), float64(100-fn4Missed)),
		ErrorRatePct: float64(fn4Missed),
	})

	// Cohort FN-5: 100 Desktop Reinstall / Native UUID Hook / Cloud Headless SwiftShader & VMware Attacks
	fn5Missed := 0
	for i := 0; i < 100; i++ {
		gpuHash := fmt.Sprintf("desktop_vm_gpu_%04d_00000000000000000000000000000000", i)
		tAtk := baseTime.Add(time.Duration(12000+i*10) * time.Hour)
		ip1 := fmt.Sprintf("95.70.%d.10", (i%200)+1)

		if i < 50 {
			// Desktop SQLite wipe (0..24) or Native UUID Hook (25..49)
			ch1, _ := v.IssueChallenge(ctx, ip1)
			p1 := BuildValidPayload(ch1)
			p1.WebGL.StaticWebGLFpHash = gpuHash
			p1.Lies.WorkerStaticWebGLFpHash = gpuHash
			p1.NativeAnchor = &prismid.NativeHardwareAnchor{
				Platform:       "macos",
				HWUUID:         fmt.Sprintf("FD7FC36D-0000-0000-0000-%012d", i),
				SerialNumber:   fmt.Sprintf("SER%06d", i),
				KeychainAnchor: fmt.Sprintf("kc_%06d", i),
				CPUCores:       10,
			}
			s1, _ := seal(ch1.Nonce, p1)
			res1, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch1.Nonce, SealedPayload: s1}, ip1)
			graph.RecordVerification(fmt.Sprintf("desk_main_%d", i), tAtk, res1)

			ip2 := fmt.Sprintf("96.80.%d.20", (i%200)+1)
			ch2, _ := v.IssueChallenge(ctx, ip2)
			p2 := BuildValidPayload(ch2)
			p2.WebGL.StaticWebGLFpHash = gpuHash
			p2.Lies.WorkerStaticWebGLFpHash = gpuHash
			if i < 25 {
				// Reinstall / SQLite wipe: same NativeAnchor
				p2.NativeAnchor = p1.NativeAnchor
			} else {
				// Kernel/API Hook randomizing HWUUID & SerialNumber on the same physical machine while KeychainAnchor persists
				p2.NativeAnchor = &prismid.NativeHardwareAnchor{
					Platform:       "macos",
					HWUUID:         fmt.Sprintf("FAKE-HOOK-UUID-9999-%012d", i),
					SerialNumber:   fmt.Sprintf("FAKESER%06d", i),
					KeychainAnchor: fmt.Sprintf("kc_%06d", i),
					CPUCores:       10,
				}
			}
			s2, _ := seal(ch2.Nonce, p2)
			res2, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: ch2.Nonce, SealedPayload: s2}, ip2)
			snap2 := graph.RecordVerification(fmt.Sprintf("desk_alt_%d", i), tAtk.Add(24*time.Hour), res2)
			if snap2.RiskStatus != prismid.RiskStatusRed {
				fn5Missed++
			}
		} else {
			// Cloud Docker Headless SwiftShader / VMware farm (50..99)
			chVM, _ := v.IssueChallenge(ctx, ip1)
			pVM := BuildValidPayload(chVM)
			pVM.WebGL.GPURenderer = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device), Google SwiftShader)"
			pVM.Lies.WorkerGPURenderer = pVM.WebGL.GPURenderer
			sVM, _ := seal(chVM.Nonce, pVM)
			resVM, _ := v.VerifyAndDerive(ctx, prismid.IdentifyRequest{ChallengeNonce: chVM.Nonce, SealedPayload: sVM}, ip1)
			snapVM := graph.RecordVerification(fmt.Sprintf("vm_bot_%d", i), tAtk, resVM)
			if !snapVM.RiskPending || snapVM.RiskStatus != prismid.RiskStatusUnknown {
				fn5Missed++
			}
		}
	}
	results = append(results, AccuracyCohortResult{
		Category:     "FNR (防漏报)",
		CohortName:   "FN-5: 100 次桌面端删库重装 / Hook 篡改主板 UUID / 云端 SwiftShader 容器农场",
		TotalCases:   100,
		CorrectCount: 100 - fn5Missed,
		ErrorCount:   fn5Missed,
		RateLabel:    fmt.Sprintf("FNR = %.2f%% (Recall %.1f%%)", float64(fn5Missed), float64(100-fn5Missed)),
		ErrorRatePct: float64(fn5Missed),
	})

	totalFPErrors := fp1Errors + fp2Errors + fp3Errors
	totalFNMissed := fn1Missed + fn2Missed + fn3Missed + fn4Missed + fn5Missed
	overallFPR := float64(totalFPErrors) / 500.0 * 100.0
	overallFNR := float64(totalFNMissed) / 500.0 * 100.0

	return results, overallFPR, overallFNR, nil
}
