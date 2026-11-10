package prismid

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Standard error codes returned when verification rejects a request.
const (
	ErrCodeChallengeInvalid      = "CHALLENGE_NONCE_INVALID_OR_REPLAYED"
	ErrCodeAEADDecryptFailed     = "AEAD_DECRYPT_FAILED"
	ErrCodePayloadNonceMismatch  = "PAYLOAD_NONCE_MISMATCH"
	ErrCodeShaderPixelMismatch   = "SHADER_SPOT_PIXEL_MATH_MISMATCH"
	ErrCodeGPURegisterViolation  = "GPU_REGISTER_LAW_VIOLATION"
	ErrCodeIncompleteHardwareSig = "INCOMPLETE_HARDWARE_SIGNALS"
)

// AEADKeyDomainPrefix is the canonical salt prefix used to derive the 256-bit AES-GCM key
// from a single-use challenge nonce: Key = SHA256("prismid-v1-aead:" + nonce).
const AEADKeyDomainPrefix = "prismid-v1-aead:"

// AuthoritativeConfidenceThreshold is the minimum confidence weight required for a device slice
// observation to participate in risk association graphs.
// Note: Confidence values (0.99, 0.95, 0.85, 0.30) are deterministic rule-tier weights,
// not calibrated statistical probabilities.
const AuthoritativeConfidenceThreshold = 0.60

// VirtualGPUConfidence is the demoted rule weight assigned to virtual GPUs / software renderers.
const VirtualGPUConfidence = 0.30

// VerificationError represents a structured rejection error from the PrismID verifier.
type VerificationError struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *VerificationError) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// Challenge represents a single-use dynamic shader challenge issued by the server.
type Challenge struct {
	Nonce        string     `json:"nonce"`
	RenderSeed   [4]float64 `json:"render_seed"`
	SamplePoints [][2]int   `json:"sample_points"`
	IssuedAt     int64      `json:"issued_at"`
	ExpiresAt    int64      `json:"expires_at"`
	ClientIP     string     `json:"-"`
}

// IdentifyRequest is the encrypted wire request sent to POST /api/v1/risk/identify.
type IdentifyRequest struct {
	ChallengeNonce string `json:"c"`
	SealedPayload  string `json:"p"`
	TurnstileToken string `json:"ts,omitempty"`
}

// DeviceKeyProof carries a challenge-bound ECDSA P-256 signature produced by a non-extractable
// WebCrypto CryptoKey stored in IndexedDB (or OS hardware keystore).
type DeviceKeyProof struct {
	Alg       string `json:"alg"`
	PubKey    string `json:"pub_key"`
	Signature string `json:"signature"`
}

// ProbePayload is the plaintext JSON structure sealed inside IdentifyRequest.SealedPayload.
type ProbePayload struct {
	Version             int                   `json:"v"`
	Nonce               string                `json:"nonce"`
	CollectedAt         int64                 `json:"collected_at"`
	BeaconID            string                `json:"beacon_id,omitempty"`
	WebGL               WebGLProbeData        `json:"webgl"`
	AudioCompressorHash string                `json:"audio_compressor_hash"`
	AudioCopyHash       string                `json:"audio_copy_hash,omitempty"`
	AudioSilentDelta    float64               `json:"audio_silent_delta,omitempty"`
	System              SystemProbeData       `json:"system"`
	Lies                LieProbeData          `json:"lies"`
	DeviceKey           *DeviceKeyProof       `json:"device_key,omitempty"`
	NativeAnchor        *NativeHardwareAnchor `json:"native_anchor,omitempty"`
}

// WebGLProbeData captures GPU rasterization and hardware register signals.
type WebGLProbeData struct {
	GPUVendor           string     `json:"gpu_vendor"`
	GPURenderer         string     `json:"gpu_renderer"`
	WebGLLimitsVector   string     `json:"webgl_limits_vector"`
	WebGLExtensionsHash string     `json:"webgl_extensions_hash,omitempty"`
	WebGLAvailable      *bool      `json:"webgl_available,omitempty"`
	StaticWebGLFpHash   string     `json:"static_webgl_fp_hash"`
	SpotPixels          [][4]uint8 `json:"spot_pixels"`
}

// SystemProbeData captures browser and OS environment signals.
type SystemProbeData struct {
	UserAgent           string   `json:"user_agent"`
	Platform            string   `json:"platform"`
	CPUCores            int      `json:"cpu_cores"`
	DeviceMemory        float64  `json:"device_memory,omitempty"`
	Timezone            string   `json:"timezone"`
	Languages           []string `json:"languages"`
	ScreenSpec          string   `json:"screen_spec"`
	DisplayGamutSpec    string   `json:"display_gamut_spec,omitempty"`
	VoicesHash          string   `json:"voices_hash,omitempty"`
	IntlHash            string   `json:"intl_hash,omitempty"`
	Canvas2DHash        string   `json:"canvas_2d_hash"`
	FontsBitmapHash     string   `json:"fonts_bitmap_hash"`
	CanvasControlRGBA   []int    `json:"canvas_control_rgba,omitempty"`
	CanvasReadbackDelta int      `json:"canvas_readback_delta,omitempty"`
}

// LieProbeData captures cross-thread Web Worker + OffscreenCanvas comparisons,
// Canvas/WebGL/Audio noise-injection traps, storage self-healing, FDLIBM Math constants,
// and prototype tampering indicators.
type LieProbeData struct {
	WorkerUnavailable       bool     `json:"worker_unavailable"`
	WorkerLieDetected       bool     `json:"worker_lie_detected"`
	WorkerGPURenderer       string   `json:"worker_gpu_renderer,omitempty"`
	WorkerStaticWebGLFpHash string   `json:"worker_static_webgl_fp_hash,omitempty"`
	WorkerCPUCores          int      `json:"worker_cpu_cores,omitempty"`
	WorkerPlatform          string   `json:"worker_platform,omitempty"`
	WorkerUserAgent         string   `json:"worker_user_agent,omitempty"`
	WorkerTimezone          string   `json:"worker_timezone,omitempty"`
	CanvasNoiseInjected     bool     `json:"canvas_noise_injected,omitempty"`
	WebGLNoiseInjected      bool     `json:"webgl_noise_injected,omitempty"`
	AudioNoiseInjected      bool     `json:"audio_noise_injected,omitempty"`
	StorageHealed           bool     `json:"storage_healed,omitempty"`
	MathEngineSignature     string   `json:"math_engine_signature"`
	MathConstantsHash       string   `json:"math_constants_hash"`
	PrototypeLies           []string `json:"prototype_lies,omitempty"`
	AutomationFlags         []string `json:"automation_flags,omitempty"`
}

// NativeHardwareAnchor captures out-of-sandbox OS hardware identifiers from prismid-native.
type NativeHardwareAnchor struct {
	Platform       string `json:"platform"`
	HWUUID         string `json:"hw_uuid"`
	SerialNumber   string `json:"serial_number"`
	KeychainAnchor string `json:"keychain_anchor"`
	CPUBrand       string `json:"cpu_brand"`
	CPUCores       int    `json:"cpu_cores"`
	MemoryBytes    uint64 `json:"memory_bytes"`
	IsVM           bool   `json:"is_vm"`
	VMVendor       string `json:"vm_vendor,omitempty"`
}

// VerifyResult contains the verified orthogonal spectral slice IDs and forensic flags.
type VerifyResult struct {
	Accepted                  bool          `json:"accepted"`
	Confidence                float64       `json:"confidence"`
	DeviceKeySliceID          string        `json:"device_key_slice_id,omitempty"`
	DeviceKeyBound            bool          `json:"device_key_bound,omitempty"`
	DeviceKeyAttested         bool          `json:"device_key_attested,omitempty"`
	DeviceKeyRecoveryRequired bool          `json:"device_key_recovery_required,omitempty"`
	RiskPending               bool          `json:"risk_pending,omitempty"`
	ExactSliceID              string        `json:"exact_slice_id"`
	KeychainSliceID           string        `json:"keychain_slice_id,omitempty"`
	BeaconSliceID             string        `json:"beacon_slice_id,omitempty"`
	GpuAudioSliceID           string        `json:"gpu_audio_slice_id"`
	SysNetSliceID             string        `json:"sys_net_slice_id"`
	CrowdSliceID              string        `json:"crowd_slice_id,omitempty"`
	SubnetCrowdTriggered      bool          `json:"subnet_crowd_triggered,omitempty"`
	IPSubnet                  string        `json:"ip_subnet"`
	IsNative                  bool          `json:"is_native"`
	IsVirtualGPU              bool          `json:"is_virtual_gpu"`
	SpoofTrapTriggered        bool          `json:"spoof_trap_triggered"`
	SpoofFlags                []string      `json:"spoof_flags,omitempty"`
	PrivacySignals            []string      `json:"privacy_signals,omitempty"`
	DecryptedPayload          *ProbePayload `json:"-"`
}

// SliceNodes returns all non-empty orthogonal slice node IDs that participate in graph linking.
// Note: CrowdSliceID (d_ip24_crowd_*) is intentionally excluded from graph linking so that
// high-density mobile CGNAT or large office /24 networks never falsely merge unrelated users.
func (r *VerifyResult) SliceNodes() []string {
	nodes := make([]string, 0, 6)
	for _, id := range []string{r.DeviceKeySliceID, r.ExactSliceID, r.KeychainSliceID, r.BeaconSliceID, r.GpuAudioSliceID, r.SysNetSliceID} {
		if strings.TrimSpace(id) != "" {
			nodes = append(nodes, id)
		}
	}
	return nodes
}

// ChallengeStore abstracts single-use challenge persistence and stateful anti-spoofing traps.
type ChallengeStore interface {
	// SaveChallenge stores a newly issued challenge until its expiration.
	SaveChallenge(ctx context.Context, ch Challenge, ttl time.Duration) error
	// ConsumeChallenge atomically retrieves and deletes a challenge by nonce (GETDEL semantics).
	ConsumeChallenge(ctx context.Context, nonce string) (*Challenge, error)
	// RecordNativeAnchorForGPU records an (anchorScopeKey, nativeSliceID) pair and returns the count
	// of distinct nativeSliceIDs observed under that scope.
	RecordNativeAnchorForGPU(ctx context.Context, anchorScopeKey, nativeSliceID string) (int, error)
	// RecordSubnetGPU records an (ipSubnet, gpuSliceID) pair within a rolling window and
	// returns the number of distinct gpuSliceIDs observed on that subnet.
	RecordSubnetGPU(ctx context.Context, ipSubnet, gpuSliceID string, window time.Duration) (int, error)
}

// DeviceKeyBindingStore is an optional extension of ChallengeStore that enforces
// Trust-On-First-Use (TOFU) binding between a storage beacon (d_bcn_*) and an attested
// ECDSA P-256 public key (d_key_*), preventing stolen beacon replay from headless scripts.
type DeviceKeyBindingStore interface {
	CheckOrBindBeaconDeviceKey(ctx context.Context, beaconSliceID, deviceKeySliceID string) (bool, error)
}

// Config configures the PrismID Verifier engine.
type Config struct {
	HMACSecret               []byte
	ChallengeTTL             time.Duration
	SpotPixelTolerance       int
	MaxDistinctGPUsPerSubnet int
	SubnetWindow             time.Duration
	RejectOnGPULawViolation  bool
	NowFunc                  func() time.Time
}

// Verifier implements the PrismID Challenge-Response, AEAD opening, consistency checks,
// and orthogonal spectral slice derivation engine.
type Verifier struct {
	cfg   Config
	store ChallengeStore
}

// NewVerifier creates a new PrismID Verifier with safe defaults.
// If cfg.HMACSecret is empty, an ephemeral random 32-byte key is generated rather than
// falling back to a static hardcoded string.
func NewVerifier(cfg Config, store ChallengeStore) *Verifier {
	if len(cfg.HMACSecret) == 0 {
		ephemeral := make([]byte, 32)
		if _, err := rand.Read(ephemeral); err != nil {
			panic("prismid: failed to generate ephemeral HMAC secret: " + err.Error())
		}
		cfg.HMACSecret = ephemeral
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 60 * time.Second
	}
	if cfg.SpotPixelTolerance <= 0 {
		cfg.SpotPixelTolerance = 2
	}
	if cfg.MaxDistinctGPUsPerSubnet <= 0 {
		cfg.MaxDistinctGPUsPerSubnet = 3
	}
	if cfg.SubnetWindow <= 0 {
		cfg.SubnetWindow = 7 * 24 * time.Hour
	}
	if cfg.NowFunc == nil {
		if ms, ok := store.(*MemoryChallengeStore); ok && ms != nil && ms.nowFunc != nil {
			cfg.NowFunc = ms.nowFunc
		} else {
			cfg.NowFunc = time.Now
		}
	}
	if store == nil {
		store = NewMemoryChallengeStoreWithClock(cfg.NowFunc)
	}
	return &Verifier{cfg: cfg, store: store}
}

// IssueChallenge generates a cryptographically random 60s single-use nonce and a 4-float
// dynamic WebGL fragment shader seed in [1.25, 6.75].
func (v *Verifier) IssueChallenge(ctx context.Context, clientIP string) (*Challenge, error) {
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate challenge nonce: %w", err)
	}
	seedBytes := make([]byte, 16)
	if _, err := rand.Read(seedBytes); err != nil {
		return nil, fmt.Errorf("generate render seed: %w", err)
	}

	var renderSeed [4]float64
	for i := 0; i < 4; i++ {
		u := binary.LittleEndian.Uint32(seedBytes[i*4 : (i+1)*4])
		// Map uint32 to [1.25, 6.75] rounded to 6 decimal places for clean JSON serialization
		val := 1.25 + (float64(u)/float64(math.MaxUint32))*5.50
		renderSeed[i] = math.Round(val*1e6) / 1e6
	}

	now := v.cfg.NowFunc()
	points := make([][2]int, len(DefaultSamplePoints))
	copy(points, DefaultSamplePoints)

	ch := Challenge{
		Nonce:        hex.EncodeToString(nonceBytes),
		RenderSeed:   renderSeed,
		SamplePoints: points,
		IssuedAt:     now.UnixMilli(),
		ExpiresAt:    now.Add(v.cfg.ChallengeTTL).UnixMilli(),
		ClientIP:     strings.TrimSpace(clientIP),
	}

	if err := v.store.SaveChallenge(ctx, ch, v.cfg.ChallengeTTL); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}
	return &ch, nil
}

// canonicalizeWebGLLimits keeps the 11 physical hardware register segments and strips
// any trailing volatile browser-extension hash (segment 12) so minor browser updates
// adding WebGL extensions do not alter d_gpu_*.
func canonicalizeWebGLLimits(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	parts := strings.Split(trimmed, "|")
	if len(parts) > 11 {
		return strings.Join(parts[:11], "|")
	}
	return trimmed
}

// VerifyAndDerive executes the verification pipeline and derives the orthogonal device slices.
func (v *Verifier) VerifyAndDerive(ctx context.Context, req IdentifyRequest, clientIP string) (*VerifyResult, error) {
	nonce := strings.TrimSpace(req.ChallengeNonce)
	if nonce == "" {
		return nil, &VerificationError{Code: ErrCodeChallengeInvalid, Detail: "empty challenge nonce"}
	}

	// Layer 1A: Atomic single-use nonce consumption & expiration check
	ch, err := v.store.ConsumeChallenge(ctx, nonce)
	if err != nil || ch == nil {
		return nil, &VerificationError{Code: ErrCodeChallengeInvalid, Detail: "nonce not found, expired, or already replayed"}
	}
	nowMs := v.cfg.NowFunc().UnixMilli()
	if nowMs > ch.ExpiresAt {
		return nil, &VerificationError{Code: ErrCodeChallengeInvalid, Detail: "challenge expired"}
	}

	// Layer 1B: Open AEAD (AES-256-GCM) sealed payload
	plaintext, err := OpenSealedPayload(nonce, req.SealedPayload)
	if err != nil {
		return nil, &VerificationError{Code: ErrCodeAEADDecryptFailed, Detail: err.Error()}
	}

	var payload ProbePayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, &VerificationError{Code: ErrCodeAEADDecryptFailed, Detail: "invalid inner json: " + err.Error()}
	}
	if strings.TrimSpace(payload.Nonce) != nonce {
		return nil, &VerificationError{Code: ErrCodePayloadNonceMismatch, Detail: "inner payload nonce does not match challenge nonce"}
	}

	// Validate essential hardware signal presence
	if strings.TrimSpace(payload.WebGL.StaticWebGLFpHash) == "" ||
		strings.TrimSpace(payload.WebGL.WebGLLimitsVector) == "" ||
		strings.TrimSpace(payload.AudioCompressorHash) == "" {
		return nil, &VerificationError{Code: ErrCodeIncompleteHardwareSig, Detail: "missing webgl or audio hardware fingerprint hashes"}
	}

	// Layer 1C: Dynamic shader spot-pixel math verification (absDiff <= 2)
	samplePts := ch.SamplePoints
	if len(samplePts) == 0 {
		samplePts = DefaultSamplePoints
	}
	if ok, reason := VerifySpotPixels(samplePts, ch.RenderSeed, payload.WebGL.SpotPixels, v.cfg.SpotPixelTolerance); !ok {
		return nil, &VerificationError{Code: ErrCodeShaderPixelMismatch, Detail: reason}
	}

	var spoofFlags []string
	var privacySignals []string
	spoofTrapTriggered := false

	// Layer 2: Cross-Thread Web Worker + OffscreenCanvas Lie Detection & Noise Traps
	effectiveStaticWebGLHash := strings.TrimSpace(payload.WebGL.StaticWebGLFpHash)
	effectiveGPURenderer := strings.TrimSpace(payload.WebGL.GPURenderer)
	effectiveCPUCores := payload.System.CPUCores
	effectivePlatform := strings.TrimSpace(payload.System.Platform)
	effectiveTimezone := strings.TrimSpace(payload.System.Timezone)

	if payload.Lies.WorkerUnavailable {
		spoofFlags = appendUniqueFlag(spoofFlags, "worker_unavailable")
		privacySignals = appendUniqueFlag(privacySignals, "worker_unavailable")
	} else {
		workerLie := payload.Lies.WorkerLieDetected
		wRenderer := strings.TrimSpace(payload.Lies.WorkerGPURenderer)
		if wRenderer != "" && !isGenericMaskedWebGLRenderer(wRenderer) &&
			!isGenericMaskedWebGLRenderer(effectiveGPURenderer) &&
			!strings.EqualFold(wRenderer, effectiveGPURenderer) {
			workerLie = true
			effectiveGPURenderer = wRenderer
		}
		wHash := strings.TrimSpace(payload.Lies.WorkerStaticWebGLFpHash)
		if wHash != "" && !strings.EqualFold(wHash, effectiveStaticWebGLHash) {
			workerLie = true
			// Override hooked main-thread WebGL hash with unhooked Worker OffscreenCanvas hash
			effectiveStaticWebGLHash = wHash
		}
		if payload.Lies.WorkerCPUCores > 0 && payload.System.CPUCores > 0 && payload.Lies.WorkerCPUCores != payload.System.CPUCores {
			workerLie = true
			effectiveCPUCores = payload.Lies.WorkerCPUCores
		}
		wPlat := strings.TrimSpace(payload.Lies.WorkerPlatform)
		if wPlat != "" && effectivePlatform != "" && !strings.EqualFold(wPlat, effectivePlatform) {
			workerLie = true
			effectivePlatform = wPlat
		}
		wUA := strings.TrimSpace(payload.Lies.WorkerUserAgent)
		if wUA != "" && strings.TrimSpace(payload.System.UserAgent) != "" && wUA != strings.TrimSpace(payload.System.UserAgent) {
			workerLie = true
		}
		if wTZ := strings.TrimSpace(payload.Lies.WorkerTimezone); wTZ != "" && effectiveTimezone != "" && wTZ != effectiveTimezone {
			workerLie = true
			effectiveTimezone = wTZ
			spoofFlags = appendUniqueFlag(spoofFlags, "worker_timezone_mismatch")
		}
		// Server-side telemetry (DeepSeek v0.5 P2): if optional worker_* fields are all omitted while
		// WorkerUnavailable=false, record "worker_telemetry_missing" in PrivacySignals without
		// falsely marking minimal/legacy payloads as active spoofing (spoofTrapTriggered=false).
		// However, if a client provides partial worker_* fields while selectively blanking out
		// WorkerStaticWebGLFpHash or WorkerUserAgent, flag selective stripping!
		allWorkerEmpty := wHash == "" && wRenderer == "" && wPlat == "" && wUA == "" && payload.Lies.WorkerCPUCores == 0
		if payload.NativeAnchor == nil {
			if allWorkerEmpty {
				privacySignals = appendUniqueFlag(privacySignals, "worker_telemetry_missing")
			} else if (wHash == "" && (payload.WebGL.WebGLAvailable == nil || *payload.WebGL.WebGLAvailable)) ||
				(wUA == "" && strings.TrimSpace(payload.System.UserAgent) != "") {
				workerLie = true
				spoofFlags = appendUniqueFlag(spoofFlags, "worker_partial_telemetry_stripped")
			}
		}
		if workerLie {
			spoofFlags = appendUniqueFlag(spoofFlags, "worker_lie_detected")
			spoofTrapTriggered = true
		}
	}

	// Server-side raw measurement inference for Canvas 2D (DeepSeek #2):
	// Even if a silent attacker sets payload.Lies.CanvasNoiseInjected=false, the server
	// independently verifies raw control-pixel RGBA values and dual-readback delta.
	canvasNoiseInferred := payload.Lies.CanvasNoiseInjected || payload.System.CanvasReadbackDelta != 0
	if len(payload.System.CanvasControlRGBA) > 0 {
		c := payload.System.CanvasControlRGBA
		if len(c) != 8 ||
			c[0] != 0 || c[1] != 0 || c[2] != 0 || c[3] != 0 ||
			absInt(c[4]-17) > 2 || absInt(c[5]-136) > 2 || absInt(c[6]-221) > 2 || absInt(c[7]-255) > 2 {
			canvasNoiseInferred = true
		}
	}
	if canvasNoiseInferred {
		spoofFlags = appendUniqueFlag(spoofFlags, "canvas_noise_injected")
		spoofTrapTriggered = true
	}

	if payload.Lies.WebGLNoiseInjected {
		spoofFlags = appendUniqueFlag(spoofFlags, "webgl_noise_injected")
		spoofTrapTriggered = true
	}

	// Server-side raw measurement inference for WebAudio (DeepSeek #2):
	// Even if a silent attacker sets payload.Lies.AudioNoiseInjected=false, the server
	// independently compares raw getChannelData vs copyFromChannel hashes and silent-tail delta.
	audioNoiseInferred := payload.Lies.AudioNoiseInjected || payload.AudioSilentDelta != 0
	if copyHash := strings.TrimSpace(payload.AudioCopyHash); copyHash != "" &&
		!strings.EqualFold(copyHash, strings.TrimSpace(payload.AudioCompressorHash)) {
		audioNoiseInferred = true
	}
	if audioNoiseInferred {
		spoofFlags = appendUniqueFlag(spoofFlags, "audio_noise_injected")
		spoofTrapTriggered = true
	}

	if strings.TrimSpace(payload.Lies.MathEngineSignature) == "unknown_tampered_math" {
		spoofFlags = appendUniqueFlag(spoofFlags, "math_engine_tampered")
		spoofTrapTriggered = true
	}
	// StorageHealed is recorded as a telemetry/privacy signal; by itself it does NOT set
	// spoofTrapTriggered=true so a single user clearing cookies (or Safari ITP) is never marked red,
	// while a multi-account fraudster wiping cookies is still linked via the healed BeaconSliceID (d_bcn_*).
	if payload.Lies.StorageHealed {
		spoofFlags = appendUniqueFlag(spoofFlags, "storage_healed")
		privacySignals = appendUniqueFlag(privacySignals, "storage_healed")
	}

	for _, protoLie := range payload.Lies.PrototypeLies {
		if trimmed := strings.TrimSpace(protoLie); trimmed != "" {
			spoofFlags = appendUniqueFlag(spoofFlags, "prototype_lie:"+trimmed)
			spoofTrapTriggered = true
		}
	}
	for _, autoFlag := range payload.Lies.AutomationFlags {
		if trimmed := strings.TrimSpace(autoFlag); trimmed != "" {
			spoofFlags = appendUniqueFlag(spoofFlags, "automation:"+trimmed)
			if trimmed == "navigator_webdriver" {
				privacySignals = appendUniqueFlag(privacySignals, "automation:navigator_webdriver")
			} else {
				spoofTrapTriggered = true
			}
		}
	}

	// Layer 3A: GPU Register Law Verification
	lawViolations := VerifyGPURegisterLaws(&payload)
	if len(lawViolations) > 0 {
		spoofFlags = appendUniqueFlag(spoofFlags, "gpu_register_law_violation")
		for _, lv := range lawViolations {
			spoofFlags = appendUniqueFlag(spoofFlags, lv)
		}
		spoofTrapTriggered = true
		if v.cfg.RejectOnGPULawViolation {
			return nil, &VerificationError{
				Code:   ErrCodeGPURegisterViolation,
				Detail: strings.Join(lawViolations, "; "),
			}
		}
	}

	// Derive Orthogonal Spectral Slices:
	// 1. GpuAudioSliceID (d_gpu_*): model-level GPU rasterization + canonical register limits + audio hash.
	canonicalLimits := canonicalizeWebGLLimits(payload.WebGL.WebGLLimitsVector)
	gpuAudioSliceID := "d_gpu_" + v.hmacHex32(strings.Join([]string{
		strings.ToLower(effectiveStaticWebGLHash),
		canonicalLimits,
		strings.ToLower(strings.TrimSpace(payload.AudioCompressorHash)),
	}, "|"))

	// 2. ExactSliceID (d_nat_* for Desktop with NativeAnchor, or d_web_* for Browser Web)
	//    Plus KeychainSliceID (d_kch_*) when OS Keychain anchor is present.
	isNative := false
	var exactSliceID string
	var keychainSliceID string
	if payload.NativeAnchor != nil && strings.TrimSpace(payload.NativeAnchor.HWUUID) != "" {
		isNative = true
		exactSliceID = "d_nat_" + v.hmacHex32(strings.Join([]string{
			strings.ToLower(strings.TrimSpace(payload.NativeAnchor.Platform)),
			strings.ToUpper(strings.TrimSpace(payload.NativeAnchor.HWUUID)),
			strings.ToUpper(strings.TrimSpace(payload.NativeAnchor.SerialNumber)),
			strings.ToLower(strings.TrimSpace(payload.NativeAnchor.KeychainAnchor)),
		}, "|"))
		if kch := strings.ToLower(strings.TrimSpace(payload.NativeAnchor.KeychainAnchor)); kch != "" {
			keychainSliceID = "d_kch_" + v.hmacHex32("kch|"+kch)
		}
	} else {
		exactSliceID = "d_web_" + v.hmacHex32(strings.Join([]string{
			strings.ToLower(effectiveStaticWebGLHash),
			canonicalLimits,
			strings.ToLower(strings.TrimSpace(payload.AudioCompressorHash)),
			strings.ToLower(strings.TrimSpace(payload.System.Canvas2DHash)),
			strings.ToLower(strings.TrimSpace(payload.System.FontsBitmapHash)),
			strings.ToLower(strings.TrimSpace(payload.System.ScreenSpec)),
			effectiveTimezone,
		}, "|"))
	}

	// 2B. BeaconSliceID (d_bcn_*): 128-bit 5-silo self-healing cryptographic storage beacon!
	// Decoupled from d_gpu_* so browser updates that alter WebGL/Audio or GPU switching never
	// invalidate an existing persistent installation beacon.
	var beaconSliceID string
	if bcn := strings.ToLower(strings.TrimSpace(payload.BeaconID)); isValidHexBeacon(bcn) {
		beaconSliceID = "d_bcn_" + v.hmacHex32("bcn|"+bcn)
	}

	// 2C. DeviceKeySliceID (d_key_*): Challenge-bound ECDSA P-256 signature from non-extractable
	// WebCrypto CryptoKey (DeepSeek #1 Trust Root) + TOFU binding against BeaconSliceID.
	var deviceKeySliceID string
	deviceKeyBound := false
	deviceKeyRecoveryRequired := false
	if payload.DeviceKey != nil &&
		(strings.TrimSpace(payload.DeviceKey.PubKey) != "" || strings.TrimSpace(payload.DeviceKey.Signature) != "") {
		okSig, pubKeyHex := VerifyECDSAP256DeviceKey(
			payload.DeviceKey,
			nonce,
			payload.BeaconID,
			payload.WebGL.StaticWebGLFpHash,
			payload.AudioCompressorHash,
		)
		if !okSig && !strings.EqualFold(effectiveStaticWebGLHash, strings.TrimSpace(payload.WebGL.StaticWebGLFpHash)) {
			okSig, pubKeyHex = VerifyECDSAP256DeviceKey(
				payload.DeviceKey,
				nonce,
				payload.BeaconID,
				effectiveStaticWebGLHash,
				payload.AudioCompressorHash,
			)
		}
		if okSig && pubKeyHex != "" {
			deviceKeyBound = true
			deviceKeySliceID = "d_key_" + v.hmacHex32("key|"+pubKeyHex)
		} else {
			spoofFlags = appendUniqueFlag(spoofFlags, "device_key_signature_invalid")
			spoofTrapTriggered = true
		}
	}
	if beaconSliceID != "" {
		if tofuStore, ok := v.store.(DeviceKeyBindingStore); ok {
			okBind, err := tofuStore.CheckOrBindBeaconDeviceKey(ctx, beaconSliceID, deviceKeySliceID)
			if err != nil {
				return nil, fmt.Errorf("check device key binding: %w", err)
			}
			if !okBind {
				// Loss, timeout, or rotation of a stored key does not prove abuse. Keep the
				// old binding and withhold authoritative identity until independent recovery.
				deviceKeyRecoveryRequired = true
				privacySignals = appendUniqueFlag(privacySignals, "device_key_recovery_required")
				if deviceKeySliceID == "" {
					privacySignals = appendUniqueFlag(privacySignals, "device_key_missing")
				} else {
					privacySignals = appendUniqueFlag(privacySignals, "device_key_rotated")
				}
			}
		}
	}

	// 3. SysNetSliceID (d_sys_*): OS family + CPU cores + Timezone + /24 IP subnet
	ipSubnet := ExtractIPSubnet(clientIP)
	osFamily := NormalizeOSFamily(effectivePlatform, payload.NativeAnchor)
	if effectiveCPUCores <= 0 && payload.NativeAnchor != nil && payload.NativeAnchor.CPUCores > 0 {
		effectiveCPUCores = payload.NativeAnchor.CPUCores
	}
	sysNetSliceID := "d_sys_" + v.hmacHex32(strings.Join([]string{
		osFamily,
		strconv.Itoa(effectiveCPUCores),
		effectiveTimezone,
		ipSubnet,
	}, "|"))

	// Layer 3B: Native Hardware UUID Split / Hook Detection
	// Two distinct physical MacBooks of the same model share d_gpu_* legitimately. Therefore,
	// we trigger native_uuid_split_trap ONLY when two different d_nat_* identities are observed
	// under the same per-device persistent anchor (OS Keychain d_kch_* or 5-silo WebView d_bcn_*),
	// or when NativeAnchor CPUCores contradicts the verified browser/Worker CPUCores.
	if isNative && !deviceKeyRecoveryRequired {
		splitDetected := false
		if keychainSliceID != "" {
			if n, err := v.store.RecordNativeAnchorForGPU(ctx, "kch:"+keychainSliceID, exactSliceID); err == nil && n >= 2 {
				splitDetected = true
			}
		}
		if beaconSliceID != "" {
			if n, err := v.store.RecordNativeAnchorForGPU(ctx, "bcn:"+beaconSliceID, exactSliceID); err == nil && n >= 2 {
				splitDetected = true
			}
		}
		if payload.NativeAnchor.CPUCores > 0 && payload.System.CPUCores > 0 && payload.NativeAnchor.CPUCores != effectiveCPUCores {
			splitDetected = true
		}
		if splitDetected {
			spoofFlags = appendUniqueFlag(spoofFlags, "native_uuid_split_trap")
			spoofTrapTriggered = true
		}
	}

	// Layer 4: Virtual GPU / Software Renderer & VM Veto
	isVirtualGPU, vmReason := IsVirtualOrSoftwareGPU(payload.WebGL.GPUVendor, effectiveGPURenderer, payload.NativeAnchor)
	if payload.WebGL.WebGLAvailable != nil && !*payload.WebGL.WebGLAvailable {
		isVirtualGPU = true
		if vmReason == "" {
			vmReason = "webgl_unavailable_fallback"
		}
	}
	if isVirtualGPU {
		spoofFlags = appendUniqueFlag(spoofFlags, vmReason)
	}

	// Layer 5: 7-Day /24 IP Subnet Hardware Mutation Telemetry
	// Recorded as a non-linking telemetry indicator (CrowdSliceID is NOT included in SliceNodes()
	// so mobile CGNAT and large office /24 networks never merge unrelated users).
	var crowdSliceID string
	subnetCrowdTriggered := false
	if ipSubnet != "" && ipSubnet != "unknown" && !isVirtualGPU && !deviceKeyRecoveryRequired {
		distinctGPUs, err := v.store.RecordSubnetGPU(ctx, ipSubnet, gpuAudioSliceID, v.cfg.SubnetWindow)
		if err == nil && distinctGPUs > v.cfg.MaxDistinctGPUsPerSubnet {
			crowdSliceID = "d_ip24_crowd_" + v.hmacHex32("crowd|"+ipSubnet)
			subnetCrowdTriggered = true
			privacySignals = appendUniqueFlag(privacySignals, "subnet_high_gpu_diversity")
		}
	}

	// Rule-tier confidence weight (0.99 / 0.95 / 0.85 / 0.30):
	// Note (DeepSeek v0.5 P1): WebCrypto ECDSA P-256 proves keypair possession (DeviceKeyBound=true),
	// not hardware silicon attestation, so Web confidence stays 0.95 while native OS anchor gets 0.99.
	confidence := 0.95
	if isNative {
		confidence = 0.99
	}
	if spoofTrapTriggered {
		confidence = 0.85
	}
	if isVirtualGPU {
		confidence = VirtualGPUConfidence
	}
	if deviceKeyRecoveryRequired {
		confidence = VirtualGPUConfidence // below authoritative graph threshold
	}

	return &VerifyResult{
		Accepted:                  true,
		Confidence:                confidence,
		DeviceKeySliceID:          deviceKeySliceID,
		DeviceKeyBound:            deviceKeyBound,
		DeviceKeyAttested:         deviceKeyBound,
		DeviceKeyRecoveryRequired: deviceKeyRecoveryRequired,
		RiskPending:               deviceKeyRecoveryRequired,
		ExactSliceID:              exactSliceID,
		KeychainSliceID:           keychainSliceID,
		BeaconSliceID:             beaconSliceID,
		GpuAudioSliceID:           gpuAudioSliceID,
		SysNetSliceID:             sysNetSliceID,
		CrowdSliceID:              crowdSliceID,
		SubnetCrowdTriggered:      subnetCrowdTriggered,
		IPSubnet:                  ipSubnet,
		IsNative:                  isNative,
		IsVirtualGPU:              isVirtualGPU,
		SpoofTrapTriggered:        spoofTrapTriggered,
		SpoofFlags:                spoofFlags,
		PrivacySignals:            privacySignals,
		DecryptedPayload:          &payload,
	}, nil
}

// VerifyECDSAP256DeviceKey verifies a challenge-bound ECDSA P-256 signature over the canonical
// transcript "prismid-v2-sig|<nonce>|<beacon_id>|<static_webgl_fp_hash>|<audio_compressor_hash>".
// It accepts uncompressed SEC1 P-256 public keys (65 bytes: 0x04 || X[32] || Y[32]) and either
// IEEE P1363 64-byte (r || s) signatures (WebCrypto standard) or ASN.1 DER signatures.
func VerifyECDSAP256DeviceKey(proof *DeviceKeyProof, nonce, beaconID, staticWebGLHash, audioHash string) (bool, string) {
	if proof == nil {
		return false, ""
	}
	alg := strings.ToLower(strings.TrimSpace(proof.Alg))
	if alg != "" && alg != "ecdsa-p256" && alg != "es256" {
		return false, ""
	}
	pubRaw, err := decodeHexOrBase64(strings.TrimSpace(proof.PubKey))
	if err != nil || len(pubRaw) != 65 || pubRaw[0] != 0x04 {
		return false, ""
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(pubRaw[1:33])
	y := new(big.Int).SetBytes(pubRaw[33:65])
	if !curve.IsOnCurve(x, y) {
		return false, ""
	}
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	sigRaw, err := decodeHexOrBase64(strings.TrimSpace(proof.Signature))
	if err != nil || len(sigRaw) == 0 {
		return false, ""
	}

	transcript := strings.Join([]string{
		"prismid-v2-sig",
		strings.TrimSpace(nonce),
		strings.ToLower(strings.TrimSpace(beaconID)),
		strings.ToLower(strings.TrimSpace(staticWebGLHash)),
		strings.ToLower(strings.TrimSpace(audioHash)),
	}, "|")
	digest := sha256.Sum256([]byte(transcript))

	valid := false
	if len(sigRaw) == 64 {
		r := new(big.Int).SetBytes(sigRaw[:32])
		s := new(big.Int).SetBytes(sigRaw[32:64])
		valid = ecdsa.Verify(pubKey, digest[:], r, s)
	} else {
		valid = ecdsa.VerifyASN1(pubKey, digest[:], sigRaw)
	}
	if !valid {
		return false, ""
	}
	return true, hex.EncodeToString(pubRaw)
}

func decodeHexOrBase64(s string) ([]byte, error) {
	if len(s)%2 == 0 && isHexOnly(s) {
		return hex.DecodeString(s)
	}
	return decodeBase64Flexible(s)
}

func isHexOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func isValidHexBeacon(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// DeriveAEADKey derives the 32-byte AES-256-GCM key from a challenge nonce:
// Key = SHA256("prismid-v1-aead:" + nonce).
func DeriveAEADKey(nonce string) [32]byte {
	return sha256.Sum256([]byte(AEADKeyDomainPrefix + nonce))
}

// SealPayload encrypts plaintext bytes using AES-256-GCM with the nonce-derived key
// and returns Base64RawURL(IV [12B] || Ciphertext || GCM_Tag [16B]).
func SealPayload(nonce string, iv []byte, plaintext []byte) (string, error) {
	if len(iv) == 0 {
		iv = make([]byte, 12)
		if _, err := rand.Read(iv); err != nil {
			return "", err
		}
	}
	if len(iv) != 12 {
		return "", errors.New("iv must be 12 bytes")
	}
	key := DeriveAEADKey(nonce)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	aad := []byte(nonce)
	ciphertextWithTag := gcm.Seal(nil, iv, plaintext, aad)
	envelope := make([]byte, 0, len(iv)+len(ciphertextWithTag))
	envelope = append(envelope, iv...)
	envelope = append(envelope, ciphertextWithTag...)
	return base64.RawURLEncoding.EncodeToString(envelope), nil
}

// OpenSealedPayload decodes and decrypts a Base64RawURL(IV [12B] || Ciphertext || GCM_Tag [16B])
// envelope using the challenge nonce.
func OpenSealedPayload(nonce string, sealedBlob string) ([]byte, error) {
	raw, err := decodeBase64Flexible(strings.TrimSpace(sealedBlob))
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) < 12+16 {
		return nil, errors.New("ciphertext envelope too short")
	}
	iv := raw[:12]
	ciphertextWithTag := raw[12:]

	key := DeriveAEADKey(nonce)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := []byte(nonce)
	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open failed: %w", err)
	}
	return plaintext, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "+/") {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func (v *Verifier) hmacHex32(data string) string {
	mac := hmac.New(sha256.New, v.cfg.HMACSecret)
	mac.Write([]byte(data))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// ExtractIPSubnet normalizes a client IP address into a /24 IPv4 subnet or /48 IPv6 prefix.
func ExtractIPSubnet(rawIP string) string {
	trimmed := strings.TrimSpace(rawIP)
	if trimmed == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return "unknown"
	}
	if ip4 := ip.To4(); ip4 != nil {
		masked := ip4.Mask(net.CIDRMask(24, 32))
		return masked.String() + "/24"
	}
	masked := ip.Mask(net.CIDRMask(48, 128))
	return masked.String() + "/48"
}

// NormalizeOSFamily canonicalizes platform strings across Chrome, Safari/WKWebView, Firefox,
// and Rust native anchors so that the same OS always produces the identical string for d_sys_*.
func NormalizeOSFamily(webPlatform string, nativeAnchor *NativeHardwareAnchor) string {
	if nativeAnchor != nil {
		np := strings.ToLower(strings.TrimSpace(nativeAnchor.Platform))
		switch {
		case strings.Contains(np, "mac") || strings.Contains(np, "darwin"):
			return "macos"
		case strings.Contains(np, "win"):
			return "windows"
		case strings.Contains(np, "linux"):
			return "linux"
		}
	}
	wp := strings.ToLower(strings.TrimSpace(webPlatform))
	switch {
	case strings.Contains(wp, "mac") || strings.Contains(wp, "darwin"):
		return "macos"
	case strings.Contains(wp, "win"):
		return "windows"
	case strings.Contains(wp, "linux"):
		return "linux"
	case strings.Contains(wp, "iphone") || strings.Contains(wp, "ipad") || strings.Contains(wp, "ios"):
		return "ios"
	case strings.Contains(wp, "android"):
		return "android"
	default:
		if wp == "" {
			return "unknown"
		}
		return wp
	}
}

func isGenericMaskedWebGLRenderer(renderer string) bool {
	switch strings.ToLower(strings.TrimSpace(renderer)) {
	case "", "webkit webgl", "mozilla", "webgl", "unknown":
		return true
	default:
		return false
	}
}

func appendUniqueFlag(flags []string, flag string) []string {
	for _, f := range flags {
		if f == flag {
			return flags
		}
	}
	return append(flags, flag)
}

// MemoryChallengeStore is a thread-safe, capacity-bounded in-memory implementation of ChallengeStore
// suitable for standalone servers, unit tests, and single-node deployments.
type MemoryChallengeStore struct {
	mu          sync.Mutex
	nowFunc     func() time.Time
	challenges  map[string]Challenge
	gpuToNative map[string]map[string]struct{}
	subnetToGPU map[string]map[string]time.Time
	beaconToKey map[string]string
}

// NewMemoryChallengeStore creates an initialized MemoryChallengeStore using time.Now.
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return NewMemoryChallengeStoreWithClock(time.Now)
}

// NewMemoryChallengeStoreWithClock creates an initialized MemoryChallengeStore with an injected clock.
func NewMemoryChallengeStoreWithClock(nowFunc func() time.Time) *MemoryChallengeStore {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &MemoryChallengeStore{
		nowFunc:     nowFunc,
		challenges:  make(map[string]Challenge),
		gpuToNative: make(map[string]map[string]struct{}),
		subnetToGPU: make(map[string]map[string]time.Time),
		beaconToKey: make(map[string]string),
	}
}

func (m *MemoryChallengeStore) SaveChallenge(_ context.Context, ch Challenge, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	nowMs := m.nowFunc().UnixMilli()
	if len(m.challenges) >= 4096 {
		for k, v := range m.challenges {
			if nowMs > v.ExpiresAt {
				delete(m.challenges, k)
			}
		}
		// Hard capacity enforcement even if all 4096 entries are unexpired:
		for len(m.challenges) >= 4096 {
			var oldestKey string
			var oldestExp int64 = math.MaxInt64
			for k, v := range m.challenges {
				if v.ExpiresAt < oldestExp {
					oldestExp = v.ExpiresAt
					oldestKey = k
				}
			}
			if oldestKey == "" {
				break
			}
			delete(m.challenges, oldestKey)
		}
	}
	m.challenges[ch.Nonce] = ch
	return nil
}

func (m *MemoryChallengeStore) ConsumeChallenge(_ context.Context, nonce string) (*Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.challenges[nonce]
	if !ok {
		return nil, nil
	}
	delete(m.challenges, nonce)
	if m.nowFunc().UnixMilli() > ch.ExpiresAt {
		return nil, nil
	}
	return &ch, nil
}

func (m *MemoryChallengeStore) RecordNativeAnchorForGPU(_ context.Context, anchorScopeKey, nativeSliceID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.gpuToNative[anchorScopeKey]; !exists && len(m.gpuToNative) >= 32768 {
		for k := range m.gpuToNative {
			delete(m.gpuToNative, k)
			break
		}
	}
	set, ok := m.gpuToNative[anchorScopeKey]
	if !ok {
		set = make(map[string]struct{})
		m.gpuToNative[anchorScopeKey] = set
	}
	if _, exists := set[nativeSliceID]; !exists && len(set) >= 16 {
		for k := range set {
			delete(set, k)
			break
		}
	}
	set[nativeSliceID] = struct{}{}
	return len(set), nil
}

func (m *MemoryChallengeStore) RecordSubnetGPU(_ context.Context, ipSubnet, gpuSliceID string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.nowFunc()
	cutoff := now.Add(-window)
	if _, exists := m.subnetToGPU[ipSubnet]; !exists && len(m.subnetToGPU) >= 4096 {
		for sub, mset := range m.subnetToGPU {
			for k, seenAt := range mset {
				if seenAt.Before(cutoff) {
					delete(mset, k)
				}
			}
			if len(mset) == 0 {
				delete(m.subnetToGPU, sub)
			}
		}
		for len(m.subnetToGPU) >= 4096 {
			for sub := range m.subnetToGPU {
				delete(m.subnetToGPU, sub)
				break
			}
		}
	}
	set, ok := m.subnetToGPU[ipSubnet]
	if !ok {
		set = make(map[string]time.Time)
		m.subnetToGPU[ipSubnet] = set
	}
	for k, seenAt := range set {
		if seenAt.Before(cutoff) {
			delete(set, k)
		}
	}
	if _, exists := set[gpuSliceID]; !exists && len(set) >= 128 {
		for k := range set {
			delete(set, k)
			break
		}
	}
	set[gpuSliceID] = now
	return len(set), nil
}

// CheckOrBindBeaconDeviceKey enforces Trust-On-First-Use (TOFU) binding between a storage beacon
// (d_bcn_*) and an attested ECDSA P-256 public key (d_key_*).
//   - If beaconSliceID has not yet been bound to a device key, and deviceKeySliceID != "", it binds them and returns true.
//   - If beaconSliceID was previously bound to key K1, and a subsequent request with beaconSliceID
//     either omits deviceKeySliceID or presents K2 != K1, it returns false (flagging stolen beacon replay).
func (m *MemoryChallengeStore) CheckOrBindBeaconDeviceKey(_ context.Context, beaconSliceID, deviceKeySliceID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if beaconSliceID == "" {
		return true, nil
	}
	boundKey, exists := m.beaconToKey[beaconSliceID]
	if !exists {
		if deviceKeySliceID != "" {
			if len(m.beaconToKey) >= 32768 {
				for k := range m.beaconToKey {
					delete(m.beaconToKey, k)
					break
				}
			}
			m.beaconToKey[beaconSliceID] = deviceKeySliceID
		}
		return true, nil
	}
	// Beacon was previously bound to an attested ECDSA P-256 key:
	if deviceKeySliceID == "" || deviceKeySliceID != boundKey {
		return false, nil
	}
	return true, nil
}
