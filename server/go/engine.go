package prismid

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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

// AuthoritativeConfidenceThreshold is the minimum confidence required for a device slice
// to be considered authoritative in risk association graphs.
const AuthoritativeConfidenceThreshold = 0.60

// VirtualGPUConfidence is the demoted confidence assigned to virtual GPUs / software renderers.
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

// ProbePayload is the plaintext JSON structure sealed inside IdentifyRequest.SealedPayload.
type ProbePayload struct {
	Version             int                   `json:"v"`
	Nonce               string                `json:"nonce"`
	CollectedAt         int64                 `json:"collected_at"`
	WebGL               WebGLProbeData        `json:"webgl"`
	AudioCompressorHash string                `json:"audio_compressor_hash"`
	System              SystemProbeData       `json:"system"`
	Lies                LieProbeData          `json:"lies"`
	NativeAnchor        *NativeHardwareAnchor `json:"native_anchor,omitempty"`
}

// WebGLProbeData captures physical GPU rasterization and hardware register signals.
type WebGLProbeData struct {
	GPUVendor         string     `json:"gpu_vendor"`
	GPURenderer       string     `json:"gpu_renderer"`
	WebGLLimitsVector string     `json:"webgl_limits_vector"`
	StaticWebGLFpHash string     `json:"static_webgl_fp_hash"`
	SpotPixels        [][4]uint8 `json:"spot_pixels"`
}

// SystemProbeData captures browser and OS environment signals.
type SystemProbeData struct {
	UserAgent       string   `json:"user_agent"`
	Platform        string   `json:"platform"`
	CPUCores        int      `json:"cpu_cores"`
	DeviceMemory    float64  `json:"device_memory,omitempty"`
	Timezone        string   `json:"timezone"`
	Languages       []string `json:"languages"`
	ScreenSpec      string   `json:"screen_spec"`
	Canvas2DHash    string   `json:"canvas_2d_hash"`
	FontsBitmapHash string   `json:"fonts_bitmap_hash"`
}

// LieProbeData captures cross-thread Web Worker + OffscreenCanvas comparisons,
// FDLIBM Math constants, and prototype tampering indicators.
type LieProbeData struct {
	WorkerUnavailable       bool     `json:"worker_unavailable"`
	WorkerLieDetected       bool     `json:"worker_lie_detected"`
	WorkerGPURenderer       string   `json:"worker_gpu_renderer,omitempty"`
	WorkerStaticWebGLFpHash string   `json:"worker_static_webgl_fp_hash,omitempty"`
	WorkerCPUCores          int      `json:"worker_cpu_cores,omitempty"`
	WorkerPlatform          string   `json:"worker_platform,omitempty"`
	WorkerUserAgent         string   `json:"worker_user_agent,omitempty"`
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
	Accepted           bool          `json:"accepted"`
	Confidence         float64       `json:"confidence"`
	ExactSliceID       string        `json:"exact_slice_id"`
	GpuAudioSliceID    string        `json:"gpu_audio_slice_id"`
	SysNetSliceID      string        `json:"sys_net_slice_id"`
	CrowdSliceID       string        `json:"crowd_slice_id,omitempty"`
	IPSubnet           string        `json:"ip_subnet"`
	IsNative           bool          `json:"is_native"`
	IsVirtualGPU       bool          `json:"is_virtual_gpu"`
	SpoofTrapTriggered bool          `json:"spoof_trap_triggered"`
	SpoofFlags         []string      `json:"spoof_flags,omitempty"`
	DecryptedPayload   *ProbePayload `json:"-"`
}

// SliceNodes returns all non-empty orthogonal slice node IDs generated by this verification.
func (r *VerifyResult) SliceNodes() []string {
	nodes := make([]string, 0, 4)
	for _, id := range []string{r.ExactSliceID, r.GpuAudioSliceID, r.SysNetSliceID, r.CrowdSliceID} {
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
	// RecordNativeAnchorForGPU records a (gpuSliceID, nativeSliceID) pair and returns the count
	// of distinct nativeSliceIDs observed under that gpuSliceID (for Hardware Split Honeypot).
	RecordNativeAnchorForGPU(ctx context.Context, gpuSliceID, nativeSliceID string) (int, error)
	// RecordSubnetGPU records a (ipSubnet, gpuSliceID) pair within a 7-day rolling window and
	// returns the number of distinct gpuSliceIDs observed on that subnet.
	RecordSubnetGPU(ctx context.Context, ipSubnet, gpuSliceID string, window time.Duration) (int, error)
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

// Verifier implements the PrismID Challenge-Response, AEAD opening, 5-layer anti-forgery,
// and orthogonal spectral slice derivation engine.
type Verifier struct {
	cfg   Config
	store ChallengeStore
}

// NewVerifier creates a new PrismID Verifier with safe defaults.
func NewVerifier(cfg Config, store ChallengeStore) *Verifier {
	if len(cfg.HMACSecret) == 0 {
		cfg.HMACSecret = []byte("prismid-default-hmac-secret-change-in-production")
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
		cfg.NowFunc = time.Now
	}
	if store == nil {
		store = NewMemoryChallengeStore()
	}
	return &Verifier{cfg: cfg, store: store}
}

// IssueChallenge generates a cryptographically random 60s single-use nonce and a 4-float
// dynamic WebGL fragment shader seed.
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

// VerifyAndDerive executes the 5-layer anti-forgery verification pipeline and derives
// the 3 orthogonal hardware spectral slices (d_nat_*/d_web_*, d_gpu_*, d_sys_*).
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
	spoofTrapTriggered := false

	// Layer 2: Cross-Thread Web Worker + OffscreenCanvas Lie Detection
	effectiveStaticWebGLHash := strings.TrimSpace(payload.WebGL.StaticWebGLFpHash)
	effectiveGPURenderer := strings.TrimSpace(payload.WebGL.GPURenderer)
	effectiveCPUCores := payload.System.CPUCores
	effectivePlatform := strings.TrimSpace(payload.System.Platform)

	if payload.Lies.WorkerUnavailable {
		spoofFlags = appendUniqueFlag(spoofFlags, "worker_unavailable")
	} else {
		workerLie := payload.Lies.WorkerLieDetected
		if wRenderer := strings.TrimSpace(payload.Lies.WorkerGPURenderer); wRenderer != "" && !strings.EqualFold(wRenderer, effectiveGPURenderer) {
			workerLie = true
			effectiveGPURenderer = wRenderer
		}
		if wHash := strings.TrimSpace(payload.Lies.WorkerStaticWebGLFpHash); wHash != "" && !strings.EqualFold(wHash, effectiveStaticWebGLHash) {
			workerLie = true
			// Crucial defense: override hooked main-thread WebGL hash with unhooked Worker OffscreenCanvas hash!
			effectiveStaticWebGLHash = wHash
		}
		if payload.Lies.WorkerCPUCores > 0 && payload.System.CPUCores > 0 && payload.Lies.WorkerCPUCores != payload.System.CPUCores {
			workerLie = true
			effectiveCPUCores = payload.Lies.WorkerCPUCores
		}
		if wPlat := strings.TrimSpace(payload.Lies.WorkerPlatform); wPlat != "" && effectivePlatform != "" && !strings.EqualFold(wPlat, effectivePlatform) {
			workerLie = true
			effectivePlatform = wPlat
		}
		if wUA := strings.TrimSpace(payload.Lies.WorkerUserAgent); wUA != "" && strings.TrimSpace(payload.System.UserAgent) != "" && wUA != strings.TrimSpace(payload.System.UserAgent) {
			workerLie = true
		}
		if workerLie {
			spoofFlags = appendUniqueFlag(spoofFlags, "worker_lie_detected")
			spoofTrapTriggered = true
		}
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

	// Derive the 3 Orthogonal Spectral Slices:
	// 1. GpuAudioSliceID (d_gpu_*): 100% decoupled from IP and self-reported gpu_renderer text!
	gpuAudioSliceID := "d_gpu_" + v.hmacHex32(strings.Join([]string{
		strings.ToLower(effectiveStaticWebGLHash),
		strings.ToLower(strings.TrimSpace(payload.WebGL.WebGLLimitsVector)),
		strings.ToLower(strings.TrimSpace(payload.AudioCompressorHash)),
	}, "|"))

	// 2. ExactSliceID (d_nat_* for Desktop with NativeAnchor, or d_web_* for Browser Web)
	isNative := false
	var exactSliceID string
	if payload.NativeAnchor != nil && strings.TrimSpace(payload.NativeAnchor.HWUUID) != "" {
		isNative = true
		exactSliceID = "d_nat_" + v.hmacHex32(strings.Join([]string{
			strings.ToLower(strings.TrimSpace(payload.NativeAnchor.Platform)),
			strings.ToUpper(strings.TrimSpace(payload.NativeAnchor.HWUUID)),
			strings.ToUpper(strings.TrimSpace(payload.NativeAnchor.SerialNumber)),
			strings.ToLower(strings.TrimSpace(payload.NativeAnchor.KeychainAnchor)),
		}, "|"))
	} else {
		exactSliceID = "d_web_" + v.hmacHex32(strings.Join([]string{
			strings.ToLower(effectiveStaticWebGLHash),
			strings.ToLower(strings.TrimSpace(payload.WebGL.WebGLLimitsVector)),
			strings.ToLower(strings.TrimSpace(payload.AudioCompressorHash)),
			strings.ToLower(strings.TrimSpace(payload.System.Canvas2DHash)),
			strings.ToLower(strings.TrimSpace(payload.System.FontsBitmapHash)),
			strings.ToLower(strings.TrimSpace(payload.System.ScreenSpec)),
			strings.TrimSpace(payload.System.Timezone),
		}, "|"))
	}

	// 3. SysNetSliceID (d_sys_*): OS family + CPU cores + Timezone + /24 IP subnet
	// Strictly excludes deviceMemory and screen.width/height for Chrome <-> WKWebView and dual-monitor stability!
	ipSubnet := ExtractIPSubnet(clientIP)
	osFamily := NormalizeOSFamily(effectivePlatform, payload.NativeAnchor)
	if effectiveCPUCores <= 0 && payload.NativeAnchor != nil && payload.NativeAnchor.CPUCores > 0 {
		effectiveCPUCores = payload.NativeAnchor.CPUCores
	}
	sysNetSliceID := "d_sys_" + v.hmacHex32(strings.Join([]string{
		osFamily,
		strconv.Itoa(effectiveCPUCores),
		strings.TrimSpace(payload.System.Timezone),
		ipSubnet,
	}, "|"))

	// Layer 3B: Hardware Split Honeypot (same d_gpu_* claiming >= 2 distinct d_nat_* motherboard UUIDs)
	if isNative {
		distinctNatCount, err := v.store.RecordNativeAnchorForGPU(ctx, gpuAudioSliceID, exactSliceID)
		if err == nil && distinctNatCount >= 2 {
			spoofFlags = appendUniqueFlag(spoofFlags, "native_uuid_split_trap")
			spoofTrapTriggered = true
		}
	}

	// Layer 4: Virtual GPU / Software Renderer & VM Veto
	isVirtualGPU, vmReason := IsVirtualOrSoftwareGPU(payload.WebGL.GPUVendor, effectiveGPURenderer, payload.NativeAnchor)
	if isVirtualGPU {
		spoofFlags = appendUniqueFlag(spoofFlags, vmReason)
	}

	// Layer 5: 7-Day /24 IP Subnet Hardware Mutation Capacity Breaker
	var crowdSliceID string
	if ipSubnet != "" && ipSubnet != "unknown" && !isVirtualGPU {
		distinctGPUs, err := v.store.RecordSubnetGPU(ctx, ipSubnet, gpuAudioSliceID, v.cfg.SubnetWindow)
		if err == nil && distinctGPUs > v.cfg.MaxDistinctGPUsPerSubnet {
			crowdSliceID = "d_ip24_crowd_" + v.hmacHex32("crowd|"+ipSubnet)
			spoofFlags = appendUniqueFlag(spoofFlags, "subnet_hardware_crowd_breaker")
		}
	}

	// Compute authoritative Confidence score:
	// - Virtual GPU / VM is strictly capped at 0.30 (< 0.60 authoritative threshold) so it stays pending.
	// - Genuine Native Desktop starts at 0.99; Genuine Web starts at 0.95.
	// - Even when spoof traps (Worker lie / UUID split) trigger, we keep Confidence >= 0.80 so the
	//   attacker's account enters the authoritative graph and gets linked to existing accounts (turning Red!).
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

	return &VerifyResult{
		Accepted:           true,
		Confidence:         confidence,
		ExactSliceID:       exactSliceID,
		GpuAudioSliceID:    gpuAudioSliceID,
		SysNetSliceID:      sysNetSliceID,
		CrowdSliceID:       crowdSliceID,
		IPSubnet:           ipSubnet,
		IsNative:           isNative,
		IsVirtualGPU:       isVirtualGPU,
		SpoofTrapTriggered: spoofTrapTriggered,
		SpoofFlags:         spoofFlags,
		DecryptedPayload:   &payload,
	}, nil
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

func appendUniqueFlag(flags []string, flag string) []string {
	for _, f := range flags {
		if f == flag {
			return flags
		}
	}
	return append(flags, flag)
}

// MemoryChallengeStore is a thread-safe in-memory implementation of ChallengeStore
// suitable for standalone servers, unit tests, and single-node deployments.
type MemoryChallengeStore struct {
	mu          sync.Mutex
	challenges  map[string]Challenge
	gpuToNative map[string]map[string]struct{}
	subnetToGPU map[string]map[string]time.Time
}

// NewMemoryChallengeStore creates an initialized MemoryChallengeStore.
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{
		challenges:  make(map[string]Challenge),
		gpuToNative: make(map[string]map[string]struct{}),
		subnetToGPU: make(map[string]map[string]time.Time),
	}
}

func (m *MemoryChallengeStore) SaveChallenge(_ context.Context, ch Challenge, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	nowMs := time.Now().UnixMilli()
	if len(m.challenges) > 4096 {
		for k, v := range m.challenges {
			if nowMs > v.ExpiresAt {
				delete(m.challenges, k)
			}
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
	return &ch, nil
}

func (m *MemoryChallengeStore) RecordNativeAnchorForGPU(_ context.Context, gpuSliceID, nativeSliceID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.gpuToNative[gpuSliceID]
	if !ok {
		set = make(map[string]struct{})
		m.gpuToNative[gpuSliceID] = set
	}
	set[nativeSliceID] = struct{}{}
	return len(set), nil
}

func (m *MemoryChallengeStore) RecordSubnetGPU(_ context.Context, ipSubnet, gpuSliceID string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-window)
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
	set[gpuSliceID] = now
	return len(set), nil
}
