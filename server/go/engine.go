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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Standard error codes returned when verification rejects a request.
const (
	ErrCodeChallengeInvalid      = "CHALLENGE_NONCE_INVALID_OR_REPLAYED"
	ErrCodeChallengeRateLimited  = "CHALLENGE_RATE_LIMITED"
	ErrCodeChallengeIPMismatch   = "CHALLENGE_IP_MISMATCH"
	ErrCodeTurnstileFailed       = "TURNSTILE_VERIFICATION_FAILED"
	ErrCodeAEADDecryptFailed     = "AEAD_DECRYPT_FAILED"
	ErrCodePayloadNonceMismatch  = "PAYLOAD_NONCE_MISMATCH"
	ErrCodeShaderPixelMismatch   = "SHADER_SPOT_PIXEL_MATH_MISMATCH"
	ErrCodeGPURegisterViolation  = "GPU_REGISTER_LAW_VIOLATION"
	ErrCodeIncompleteHardwareSig = "INCOMPLETE_HARDWARE_SIGNALS"
	ErrCodeRebindForbidden       = "REBIND_FORBIDDEN"
	ErrCodeRebindInvalidKeyProof = "REBIND_INVALID_KEY_PROOF"
)

// AEADKeyDomainPrefix is the canonical salt prefix used to derive the 256-bit AES-GCM key
// from a single-use challenge nonce: Key = SHA256("prismid-v1-aead:" + nonce).
const AEADKeyDomainPrefix = "prismid-v1-aead:"

// AuthoritativeConfidenceThreshold is the minimum confidence weight required for a device slice
// observation to participate in risk association graphs.
// Note: Confidence values (0.99, 0.95, 0.85, 0.75, 0.30) are deterministic rule-tier weights,
// not calibrated statistical probabilities.
const AuthoritativeConfidenceThreshold = 0.60

// DisabledWebGLBoundConfidence is the authoritative rule weight assigned when a hardened privacy
// or enterprise browser disables WebGL (`webgl_available=false`, non-SwiftShader) while presenting
// a valid bound ECDSA P-256 device key + 5-silo beacon (or native anchor) and zero spoof flags (S2-18).
const DisabledWebGLBoundConfidence = 0.75

// VirtualGPUConfidence is the demoted rule weight assigned to virtual GPUs / software renderers.
const VirtualGPUConfidence = 0.30

// Default MemoryChallengeStore capacity and per-IP / per-subnet anti-DoS quotas (S2-16, P2-1, P3-4).
const (
	DefaultMaxChallenges         = 4096
	DefaultMaxChallengesPerIP    = 64
	DefaultMaxChallengesPerIPSub = 1024
	DefaultMaxBeaconBindings     = 65536
	DefaultMaxOwnersPerBeacon    = 256
	DefaultMaxBeaconsPerSubject  = 128
)

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
	WorkerWebGLAvailable    *bool    `json:"worker_webgl_available,omitempty"`
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
	AudioMuted              bool     `json:"audio_muted,omitempty"`
	StorageHealed           bool     `json:"storage_healed,omitempty"`
	StorageSilosMask        int      `json:"storage_silos_mask,omitempty"`
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
	Accepted         bool    `json:"accepted"`
	Confidence       float64 `json:"confidence"`
	DeviceKeySliceID string  `json:"device_key_slice_id,omitempty"`
	DeviceKeyBound   bool    `json:"device_key_bound,omitempty"`
	// Deprecated: legacy JSON alias mirroring DeviceKeyBound; proves ECDSA P-256 key possession, not hardware silicon attestation.
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
	SaveChallenge(ctx context.Context, ch Challenge, ttl time.Duration) error
	ConsumeChallenge(ctx context.Context, nonce string) (*Challenge, error)
	RecordNativeAnchorForGPU(ctx context.Context, anchorScopeKey, nativeSliceID string) (int, error)
	RecordSubnetGPU(ctx context.Context, ipSubnet, gpuSliceID string, window time.Duration) (int, error)
}

// DeviceKeyBindingStore enforces Trust-On-First-Use (TOFU) binding between a storage beacon
// (d_bcn_*) and an ECDSA P-256 public key (d_key_*), preventing stolen beacon replay from headless scripts.
type DeviceKeyBindingStore interface {
	CheckOrBindBeaconDeviceKey(ctx context.Context, beaconSliceID, deviceKeySliceID string) (bool, error)
}

// DeviceKeyRebindStore supports audited step-up-authenticated rebinding or clearing of a beacon's
// ECDSA P-256 device key after legitimate IndexedDB loss or profile migration.
type DeviceKeyRebindStore interface {
	RebindBeaconDeviceKey(ctx context.Context, beaconSliceID, newDeviceKeySliceID string) (previousDeviceKeySliceID string, err error)
	ClearBeaconDeviceKey(ctx context.Context, beaconSliceID string) (previousDeviceKeySliceID string, err error)
}

// DeviceKeyLookupStore inspects the currently bound `d_key_*` slice for a `d_bcn_*` slice to verify
// cryptographic key-continuity rotation proofs (`PreviousDeviceKey` in S2-12).
type DeviceKeyLookupStore interface {
	GetBoundBeaconDeviceKey(ctx context.Context, beaconSliceID string) (string, error)
}

// BeaconOwnerStore persists `(subjectID <-> beaconSliceID)` ownership independently of in-memory
// RiskGraph eviction or server restarts (fixing S1-1 recovery deadlock & S2-11 shared-beacon recovery).
type BeaconOwnerStore interface {
	RecordBeaconOwner(ctx context.Context, beaconSliceID, subjectID string) error
	GetBeaconOwners(ctx context.Context, beaconSliceID string) ([]string, error)
	RemoveSubjectBeaconOwnership(ctx context.Context, subjectID string) (orphanedBeacons []string, allSubjectBeacons []string, err error)
}

// KeyRebindRequest carries a challenge-bound ECDSA P-256 proof-of-possession for rebinding
// a subject's storage beacon to a replacement device key after step-up auth (loss recovery)
// or previous-key signature proof (routine key rotation, S2-12).
type KeyRebindRequest struct {
	ChallengeNonce    string          `json:"challenge_nonce"`
	SubjectID         string          `json:"subject_id,omitempty"`
	BeaconID          string          `json:"beacon_id"`
	DeviceKey         *DeviceKeyProof `json:"device_key"`
	PreviousDeviceKey *DeviceKeyProof `json:"previous_device_key,omitempty"`
	StepUpToken       string          `json:"step_up_token,omitempty"`
}

// KeyRebindResult is the sanitized response returned on successful device-key rebinding.
type KeyRebindResult struct {
	AuditID            string `json:"audit_id"`
	SubjectID          string `json:"subject_id"`
	BeaconSliceID      string `json:"beacon_slice_id"`
	DeviceKeySliceID   string `json:"device_key_slice_id"`
	Rebound            bool   `json:"rebound"`
	RetiredPreviousKey bool   `json:"retired_previous_key,omitempty"`
}

// KeyRebindAuditEvent is a structured security audit record emitted for sensitive state mutations
// (`rebind_key`, `clear_spoof`, `erase_subject`, and denied attempts — S2-20, S3-50).
type KeyRebindAuditEvent struct {
	AuditID             string    `json:"audit_id"`
	Timestamp           time.Time `json:"timestamp"`
	Action              string    `json:"action,omitempty"`
	SubjectID           string    `json:"subject_id"`
	BeaconSliceID       string    `json:"beacon_slice_id,omitempty"`
	NewDeviceKeySliceID string    `json:"new_device_key_slice_id,omitempty"`
	PreviousKeyPresent  bool      `json:"previous_key_present"`
	RetiredPreviousKey  bool      `json:"retired_previous_key,omitempty"`
	ClientIP            string    `json:"client_ip,omitempty"`
	Outcome             string    `json:"outcome"`
}

// Config configures the PrismID Verifier engine.
type Config struct {
	HMACSecret               []byte
	ChallengeTTL             time.Duration
	SpotPixelTolerance       int
	MaxDistinctGPUsPerSubnet int
	SubnetWindow             time.Duration
	RejectOnGPULawViolation  bool
	EnforceChallengeIP       bool
	RequireTurnstile         bool
	TurnstileVerifier        func(ctx context.Context, token, clientIP string) (bool, error)
	NowFunc                  func() time.Time
	OnKeyRebindAudit         func(KeyRebindAuditEvent)
	AuditStore               AuditStore
}

// Verifier implements the PrismID Challenge-Response, AEAD opening, consistency checks,
// and orthogonal spectral slice derivation engine.
type Verifier struct {
	cfg          Config
	store        ChallengeStore
	boundGraphMu sync.RWMutex
	boundGraph   *RiskGraph
	auditMu      sync.Mutex
	rebindAudits []KeyRebindAuditEvent
}

// NewVerifier creates a new PrismID Verifier with safe defaults.
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

// BindRiskGraph connects `graph` to the verifier's `ChallengeStore` so that:
//   - beacon ownership is durably recorded in `BeaconOwnerStore` (fixing S1-1),
//   - `RebindDeviceKeyWithProof` immediately retires superseded `d_key_*` hard edges in `graph` (fixing S1-3),
//   - `RemoveSubject` / `EraseSubject` purges TOFU bindings cleanly (fixing S2-21).
func (v *Verifier) BindRiskGraph(graph *RiskGraph) {
	v.boundGraphMu.Lock()
	v.boundGraph = graph
	v.boundGraphMu.Unlock()
	if graph != nil {
		graph.AttachStore(v.store)
	}
}

// BeaconOwnerCheck returns an ownership predicate suitable for `RebindDeviceKeyWithProof` that
// consults both `RiskGraph.SubjectOwnsBeacon` (allowing shared household owners in S2-11) and
// persistent `BeaconOwnerStore` (preventing S1-1 recovery deadlock after graph restarts/eviction).
func (v *Verifier) BeaconOwnerCheck(graph *RiskGraph) func(subjectID, beaconSliceID string) bool {
	return func(subjectID, beaconSliceID string) bool {
		subjectID = strings.TrimSpace(subjectID)
		beaconSliceID = strings.TrimSpace(beaconSliceID)
		if subjectID == "" || !strings.HasPrefix(beaconSliceID, "d_bcn_") {
			return false
		}
		if bos, ok := v.store.(BeaconOwnerStore); ok {
			if owners, err := bos.GetBeaconOwners(context.Background(), beaconSliceID); err == nil && len(owners) > 0 {
				for _, o := range owners {
					if o == subjectID {
						return true
					}
				}
				return false
			}
		}
		if graph != nil {
			return graph.SubjectOwnsBeacon(subjectID, beaconSliceID)
		}
		return false
	}
}

// RecordVerifiedBeaconOwner persists `(subjectID, res.BeaconSliceID)` into `BeaconOwnerStore`
// ONLY when `res` is an accepted, non-recovery, authoritative (`Confidence >= minConf`), clean
// (`!SpoofTrapTriggered && !IsVirtualGPU`) observation (DeepSeek P3-1).
func (v *Verifier) RecordVerifiedBeaconOwner(ctx context.Context, subjectID string, res *VerifyResult) bool {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" || res == nil || !res.Accepted || res.DeviceKeyRecoveryRequired {
		return false
	}
	minConf := AuthoritativeConfidenceThreshold
	v.boundGraphMu.RLock()
	if v.boundGraph != nil && v.boundGraph.minConf > 0 {
		minConf = v.boundGraph.minConf
	}
	v.boundGraphMu.RUnlock()
	if res.Confidence < minConf || res.SpoofTrapTriggered || res.IsVirtualGPU {
		return false
	}
	bcn := strings.TrimSpace(res.BeaconSliceID)
	if !strings.HasPrefix(bcn, "d_bcn_") {
		return false
	}
	if bos, ok := v.store.(BeaconOwnerStore); ok {
		return bos.RecordBeaconOwner(ctx, bcn, subjectID) == nil
	}
	return false
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
		var vErr *VerificationError
		if errors.As(err, &vErr) {
			return nil, vErr
		}
		return nil, fmt.Errorf("save challenge: %w", err)
	}
	return &ch, nil
}

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

	// Optional Turnstile / human-challenge verification BEFORE consuming the single-use nonce (S3-27, P2-2 fail-closed):
	tsToken := strings.TrimSpace(req.TurnstileToken)
	if v.cfg.RequireTurnstile {
		if v.cfg.TurnstileVerifier == nil {
			return nil, &VerificationError{
				Code:   ErrCodeTurnstileFailed,
				Detail: "turnstile verification is required but no TurnstileVerifier is configured",
			}
		}
		if tsToken == "" {
			return nil, &VerificationError{Code: ErrCodeTurnstileFailed, Detail: "turnstile token is required"}
		}
	}
	if v.cfg.TurnstileVerifier != nil && (v.cfg.RequireTurnstile || tsToken != "") {
		okTS, tsErr := v.cfg.TurnstileVerifier(ctx, tsToken, strings.TrimSpace(clientIP))
		if tsErr != nil {
			return nil, &VerificationError{Code: ErrCodeTurnstileFailed, Detail: tsErr.Error()}
		}
		if !okTS {
			return nil, &VerificationError{Code: ErrCodeTurnstileFailed, Detail: "turnstile token rejected"}
		}
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

	var privacySignals []string
	// Layer 1A-IP: Inspect Challenge.ClientIP binding (S3-28)
	chSubnet := ExtractIPSubnet(ch.ClientIP)
	reqSubnet := ExtractIPSubnet(clientIP)
	if chSubnet != "unknown" && reqSubnet != "unknown" && chSubnet != reqSubnet {
		if v.cfg.EnforceChallengeIP {
			return nil, &VerificationError{
				Code:   ErrCodeChallengeIPMismatch,
				Detail: "identify client subnet does not match challenge issuance subnet",
			}
		}
		privacySignals = appendUniqueFlag(privacySignals, "challenge_ip_subnet_changed")
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
		allWorkerEmpty := wHash == "" && wRenderer == "" && wPlat == "" && wUA == "" && payload.Lies.WorkerCPUCores == 0
		if payload.NativeAnchor == nil {
			if allWorkerEmpty {
				privacySignals = appendUniqueFlag(privacySignals, "worker_telemetry_missing")
			} else {
				if wUA == "" && strings.TrimSpace(payload.System.UserAgent) != "" {
					workerLie = true
					spoofFlags = appendUniqueFlag(spoofFlags, "worker_partial_telemetry_stripped")
				}
				if wHash == "" && (payload.WebGL.WebGLAvailable == nil || *payload.WebGL.WebGLAvailable) {
					if payload.Lies.WorkerWebGLAvailable != nil && *payload.Lies.WorkerWebGLAvailable {
						workerLie = true
						spoofFlags = appendUniqueFlag(spoofFlags, "worker_partial_telemetry_stripped")
					} else {
						privacySignals = appendUniqueFlag(privacySignals, "worker_webgl_unavailable")
					}
				}
			}
		}
		if workerLie {
			spoofFlags = appendUniqueFlag(spoofFlags, "worker_lie_detected")
			spoofTrapTriggered = true
		}
	}

	// Consistency checks on client-reported Canvas 2D telemetry (raises bar against extensions / naive boolean flips):
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

	// Consistency checks on client-reported WebAudio telemetry:
	audioNoiseInferred := payload.Lies.AudioNoiseInjected || payload.AudioSilentDelta != 0
	if copyHash := strings.TrimSpace(payload.AudioCopyHash); copyHash != "" &&
		!strings.EqualFold(copyHash, strings.TrimSpace(payload.AudioCompressorHash)) {
		audioNoiseInferred = true
	}
	if audioNoiseInferred {
		spoofFlags = appendUniqueFlag(spoofFlags, "audio_noise_injected")
		spoofTrapTriggered = true
	}
	if payload.Lies.AudioMuted {
		privacySignals = appendUniqueFlag(privacySignals, "audio_output_muted")
	}

	if strings.TrimSpace(payload.Lies.MathEngineSignature) == "unknown_tampered_math" {
		spoofFlags = appendUniqueFlag(spoofFlags, "math_engine_tampered")
		spoofTrapTriggered = true
	}
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
	canonicalLimits := canonicalizeWebGLLimits(payload.WebGL.WebGLLimitsVector)
	gpuAudioSliceID := "d_gpu_" + v.hmacHex32(strings.Join([]string{
		strings.ToLower(effectiveStaticWebGLHash),
		canonicalLimits,
		strings.ToLower(strings.TrimSpace(payload.AudioCompressorHash)),
	}, "|"))

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

	// 2B. BeaconSliceID (d_bcn_*): exact 32-char lowercase hex 128-bit storage beacon (S3-30)
	var beaconSliceID string
	if rawBcn := strings.ToLower(strings.TrimSpace(payload.BeaconID)); rawBcn != "" {
		if isValidHexBeacon(rawBcn) {
			beaconSliceID = "d_bcn_" + v.hmacHex32("bcn|"+rawBcn)
		} else {
			privacySignals = appendUniqueFlag(privacySignals, "invalid_beacon_format")
		}
	}

	// 2C. DeviceKeySliceID (d_key_*) + TOFU binding against BeaconSliceID
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

	// 3. SysNetSliceID (d_sys_*)
	ipSubnet := reqSubnet
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

	// Layer 4: Virtual GPU / Software Renderer & Disabled-WebGL Differentiation (S2-18)
	// Hardened Firefox (`webgl.disabled=true`) or enterprise group-policy browsers report
	// `webgl_available=false` with non-SwiftShader renderer strings; distinguish them from
	// SwiftShader/llvmpipe headless farms!
	isVirtualGPU, vmReason := IsVirtualOrSoftwareGPU(payload.WebGL.GPUVendor, effectiveGPURenderer, payload.NativeAnchor)
	webglExplicitlyUnavailable := payload.WebGL.WebGLAvailable != nil && !*payload.WebGL.WebGLAvailable
	if webglExplicitlyUnavailable {
		privacySignals = appendUniqueFlag(privacySignals, "webgl_unavailable")
	}
	if isVirtualGPU {
		spoofFlags = appendUniqueFlag(spoofFlags, vmReason)
	}

	// Layer 5: 7-Day /24 IP Subnet Hardware Mutation Telemetry
	var crowdSliceID string
	subnetCrowdTriggered := false
	if ipSubnet != "" && ipSubnet != "unknown" && !isVirtualGPU && !webglExplicitlyUnavailable && !deviceKeyRecoveryRequired {
		distinctGPUs, err := v.store.RecordSubnetGPU(ctx, ipSubnet, gpuAudioSliceID, v.cfg.SubnetWindow)
		if err == nil && distinctGPUs > v.cfg.MaxDistinctGPUsPerSubnet {
			crowdSliceID = "d_ip24_crowd_" + v.hmacHex32("crowd|"+ipSubnet)
			subnetCrowdTriggered = true
			privacySignals = appendUniqueFlag(privacySignals, "subnet_high_gpu_diversity")
		}
	}

	confidence := 0.95
	if isNative {
		confidence = 0.99
	}
	if spoofTrapTriggered {
		confidence = 0.85
	}
	if webglExplicitlyUnavailable && !isVirtualGPU {
		if (deviceKeyBound && beaconSliceID != "" && !deviceKeyRecoveryRequired && !spoofTrapTriggered) || (isNative && !spoofTrapTriggered) {
			confidence = DisabledWebGLBoundConfidence // 0.75 >= 0.60 -> authoritative green
		} else {
			confidence = VirtualGPUConfidence // 0.30 -> pending for anonymous stateless no-WebGL
		}
	}
	if isVirtualGPU {
		confidence = VirtualGPUConfidence
	}
	if deviceKeyRecoveryRequired {
		confidence = VirtualGPUConfidence
	}

	return &VerifyResult{
		Accepted:                  true,
		Confidence:                confidence,
		DeviceKeySliceID:          deviceKeySliceID,
		DeviceKeyBound:            deviceKeyBound,
		DeviceKeyAttested:         deviceKeyBound,
		DeviceKeyRecoveryRequired: deviceKeyRecoveryRequired,
		RiskPending:               deviceKeyRecoveryRequired || confidence < AuthoritativeConfidenceThreshold,
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

// VerifyECDSAP256DeviceKey verifies a challenge-bound ECDSA P-256 signature over
// "prismid-v2-sig|<nonce>|<beacon_id>|<static_webgl_fp_hash>|<audio_compressor_hash>".
func VerifyECDSAP256DeviceKey(proof *DeviceKeyProof, nonce, beaconID, staticWebGLHash, audioHash string) (bool, string) {
	transcript := strings.Join([]string{
		"prismid-v2-sig",
		strings.TrimSpace(nonce),
		strings.ToLower(strings.TrimSpace(beaconID)),
		strings.ToLower(strings.TrimSpace(staticWebGLHash)),
		strings.ToLower(strings.TrimSpace(audioHash)),
	}, "|")
	return verifyECDSAP256Transcript(proof, transcript)
}

// VerifyECDSAP256RebindProof verifies a domain-separated ECDSA P-256 proof-of-possession signature
// over "prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>".
func VerifyECDSAP256RebindProof(proof *DeviceKeyProof, nonce, subjectID, beaconID string) (bool, string) {
	if strings.TrimSpace(nonce) == "" || strings.TrimSpace(subjectID) == "" || strings.TrimSpace(beaconID) == "" {
		return false, ""
	}
	transcript := strings.Join([]string{
		"prismid-v2-rebind",
		strings.TrimSpace(nonce),
		strings.TrimSpace(subjectID),
		strings.ToLower(strings.TrimSpace(beaconID)),
	}, "|")
	return verifyECDSAP256Transcript(proof, transcript)
}

// VerifyECDSAP256PrevKeyRotationProof verifies a domain-separated ECDSA P-256 continuity signature
// by the PREVIOUS device key over "prismid-v2-rebind-prev|<nonce>|<subject_id>|<beacon_id>" (S2-12).
func VerifyECDSAP256PrevKeyRotationProof(proof *DeviceKeyProof, nonce, subjectID, beaconID string) (bool, string) {
	if strings.TrimSpace(nonce) == "" || strings.TrimSpace(subjectID) == "" || strings.TrimSpace(beaconID) == "" {
		return false, ""
	}
	transcript := strings.Join([]string{
		"prismid-v2-rebind-prev",
		strings.TrimSpace(nonce),
		strings.TrimSpace(subjectID),
		strings.ToLower(strings.TrimSpace(beaconID)),
	}, "|")
	return verifyECDSAP256Transcript(proof, transcript)
}

// HasValidPreviousKeyProof verifies whether `req.PreviousDeviceKey` proves possession of the
// ECDSA P-256 private key currently bound to `req.BeaconID` in the store (enabling cryptographic
// key-continuity rotation without step-up MFA in S2-12).
func (v *Verifier) HasValidPreviousKeyProof(ctx context.Context, req KeyRebindRequest) bool {
	if req.PreviousDeviceKey == nil {
		return false
	}
	ls, ok := v.store.(DeviceKeyLookupStore)
	if !ok {
		return false
	}
	bcnSlice, err := v.DeriveBeaconSliceID(req.BeaconID)
	if err != nil {
		return false
	}
	boundKeySlice, err := ls.GetBoundBeaconDeviceKey(ctx, bcnSlice)
	if err != nil || boundKeySlice == "" {
		return false
	}
	okSig, prevPubHex := VerifyECDSAP256PrevKeyRotationProof(
		req.PreviousDeviceKey,
		req.ChallengeNonce,
		req.SubjectID,
		req.BeaconID,
	)
	if !okSig || prevPubHex == "" {
		return false
	}
	derivedPrevKey := "d_key_" + v.hmacHex32("key|"+prevPubHex)
	return hmac.Equal([]byte(derivedPrevKey), []byte(boundKeySlice))
}

func verifyECDSAP256Transcript(proof *DeviceKeyProof, transcript string) (bool, string) {
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

// isValidHexBeacon enforces exact 32-character (128-bit) lowercase hex beacon format (S3-30).
func isValidHexBeacon(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
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
	case "", "webkit webgl", "mozilla", "webgl", "unknown", "webgl disabled", "unavailable":
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

// MemoryChallengeStore is a thread-safe, capacity-bounded, snapshot-serializable implementation of
// ChallengeStore, DeviceKeyBindingStore, DeviceKeyRebindStore, DeviceKeyLookupStore, and BeaconOwnerStore.
type MemoryChallengeStore struct {
	mu                sync.Mutex
	nowFunc           func() time.Time
	maxChallenges     int
	maxPerIP          int
	maxPerSubnet      int
	maxBeaconBindings int
	challenges        map[string]Challenge
	gpuToNative       map[string]map[string]struct{}
	subnetToGPU       map[string]map[string]time.Time
	beaconToKey       map[string]string
	beaconSeenAt      map[string]int64
	beaconAccessSeq   int64
	beaconOwners      map[string]map[string]int64
	subjectBeacons    map[string]map[string]int64
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
		nowFunc:           nowFunc,
		maxChallenges:     DefaultMaxChallenges,
		maxPerIP:          DefaultMaxChallengesPerIP,
		maxPerSubnet:      DefaultMaxChallengesPerIPSub,
		maxBeaconBindings: DefaultMaxBeaconBindings,
		challenges:        make(map[string]Challenge),
		gpuToNative:       make(map[string]map[string]struct{}),
		subnetToGPU:       make(map[string]map[string]time.Time),
		beaconToKey:       make(map[string]string),
		beaconSeenAt:      make(map[string]int64),
		beaconOwners:      make(map[string]map[string]int64),
		subjectBeacons:    make(map[string]map[string]int64),
	}
}

// SetChallengeQuotas configures total, per-IP, and per-subnet active challenge quotas (0 disables a sub-quota).
func (m *MemoryChallengeStore) SetChallengeQuotas(maxTotal, maxPerIP, maxPerSubnet int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if maxTotal > 0 {
		m.maxChallenges = maxTotal
	}
	m.maxPerIP = maxPerIP
	m.maxPerSubnet = maxPerSubnet
}

func (m *MemoryChallengeStore) touchBeaconLocked(beaconSliceID string) {
	m.beaconAccessSeq++
	m.beaconSeenAt[beaconSliceID] = m.beaconAccessSeq
}

func (m *MemoryChallengeStore) evictLRUBeaconBindingLocked() {
	var oldestKey string
	var oldestSeq int64 = math.MaxInt64
	// Prefer evicting beacons without active registered owners first; otherwise evict strict LRU:
	for k := range m.beaconToKey {
		if len(m.beaconOwners[k]) > 0 {
			continue
		}
		seq := m.beaconSeenAt[k]
		if oldestKey == "" || seq < oldestSeq || (seq == oldestSeq && k < oldestKey) {
			oldestKey = k
			oldestSeq = seq
		}
	}
	if oldestKey == "" {
		for k := range m.beaconToKey {
			seq := m.beaconSeenAt[k]
			if oldestKey == "" || seq < oldestSeq || (seq == oldestSeq && k < oldestKey) {
				oldestKey = k
				oldestSeq = seq
			}
		}
	}
	if oldestKey != "" {
		delete(m.beaconToKey, oldestKey)
		delete(m.beaconSeenAt, oldestKey)
	}
}

func normalizeChallengeHost(rawIP string) string {
	trimmed := strings.TrimSpace(rawIP)
	if trimmed == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip.String()
	}
	return trimmed
}

func (m *MemoryChallengeStore) SaveChallenge(_ context.Context, ch Challenge, _ time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	nowMs := m.nowFunc().UnixMilli()

	exactIP := normalizeChallengeHost(ch.ClientIP)
	sub := ExtractIPSubnet(exactIP)

	// Sweep expired challenges and count active nonces for this IP and /24 (/48) subnet WITHOUT evicting
	// active neighbors' challenges (DeepSeek P2-1: return 429 CHALLENGE_RATE_LIMITED instead of silent eviction!).
	ipCount := 0
	subCount := 0
	if (m.maxPerIP > 0 && exactIP != "") || (m.maxPerSubnet > 0 && sub != "unknown") || len(m.challenges) >= m.maxChallenges {
		for k, v := range m.challenges {
			if nowMs > v.ExpiresAt {
				delete(m.challenges, k)
				continue
			}
			vIP := normalizeChallengeHost(v.ClientIP)
			if exactIP != "" && vIP == exactIP {
				ipCount++
			}
			if sub != "unknown" && ExtractIPSubnet(vIP) == sub {
				subCount++
			}
		}
	}

	if m.maxPerIP > 0 && exactIP != "" && ipCount >= m.maxPerIP {
		return &VerificationError{
			Code:   ErrCodeChallengeRateLimited,
			Detail: "too many active challenges for client IP",
		}
	}
	if m.maxPerSubnet > 0 && sub != "unknown" && subCount >= m.maxPerSubnet {
		return &VerificationError{
			Code:   ErrCodeChallengeRateLimited,
			Detail: "too many active challenges for client subnet",
		}
	}
	if m.maxChallenges > 0 && len(m.challenges) >= m.maxChallenges {
		return &VerificationError{
			Code:   ErrCodeChallengeRateLimited,
			Detail: "global active challenge capacity reached",
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

// CheckOrBindBeaconDeviceKey enforces TOFU binding with deterministic LRU eviction (S2-16).
func (m *MemoryChallengeStore) CheckOrBindBeaconDeviceKey(_ context.Context, beaconSliceID, deviceKeySliceID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if beaconSliceID == "" {
		return true, nil
	}
	boundKey, exists := m.beaconToKey[beaconSliceID]
	if !exists {
		if deviceKeySliceID != "" {
			for len(m.beaconToKey) >= m.maxBeaconBindings {
				m.evictLRUBeaconBindingLocked()
			}
			m.beaconToKey[beaconSliceID] = deviceKeySliceID
			m.touchBeaconLocked(beaconSliceID)
		}
		return true, nil
	}
	m.touchBeaconLocked(beaconSliceID)
	if deviceKeySliceID == "" || deviceKeySliceID != boundKey {
		return false, nil
	}
	return true, nil
}

// GetBoundBeaconDeviceKey returns the `d_key_*` slice bound to `beaconSliceID` (empty if unbound).
func (m *MemoryChallengeStore) GetBoundBeaconDeviceKey(_ context.Context, beaconSliceID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.beaconToKey[beaconSliceID], nil
}

// RebindBeaconDeviceKey atomically replaces the ECDSA P-256 device key slice bound to beaconSliceID.
func (m *MemoryChallengeStore) RebindBeaconDeviceKey(_ context.Context, beaconSliceID, newDeviceKeySliceID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if beaconSliceID == "" || newDeviceKeySliceID == "" {
		return "", errors.New("beacon_slice_id and new_device_key_slice_id are required")
	}
	prev, exists := m.beaconToKey[beaconSliceID]
	if !exists {
		for len(m.beaconToKey) >= m.maxBeaconBindings {
			m.evictLRUBeaconBindingLocked()
		}
	}
	m.beaconToKey[beaconSliceID] = newDeviceKeySliceID
	m.touchBeaconLocked(beaconSliceID)
	return prev, nil
}

// ClearBeaconDeviceKey removes any existing TOFU device-key binding for beaconSliceID.
func (m *MemoryChallengeStore) ClearBeaconDeviceKey(_ context.Context, beaconSliceID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if beaconSliceID == "" {
		return "", errors.New("beacon_slice_id is required")
	}
	prev := m.beaconToKey[beaconSliceID]
	delete(m.beaconToKey, beaconSliceID)
	delete(m.beaconSeenAt, beaconSliceID)
	return prev, nil
}

// RecordBeaconOwner records persistent `(beaconSliceID <-> subjectID)` ownership (S1-1, S2-11, P3-4).
func (m *MemoryChallengeStore) RecordBeaconOwner(_ context.Context, beaconSliceID, subjectID string) error {
	beaconSliceID = strings.TrimSpace(beaconSliceID)
	subjectID = strings.TrimSpace(subjectID)
	if beaconSliceID == "" || subjectID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	nowMs := m.nowFunc().UnixMilli()
	if _, exists := m.beaconOwners[beaconSliceID]; !exists && len(m.beaconOwners) >= m.maxBeaconBindings {
		for bcn := range m.beaconOwners {
			if _, bound := m.beaconToKey[bcn]; !bound {
				for sid := range m.beaconOwners[bcn] {
					delete(m.subjectBeacons[sid], bcn)
				}
				delete(m.beaconOwners, bcn)
				break
			}
		}
	}
	if m.beaconOwners[beaconSliceID] == nil {
		m.beaconOwners[beaconSliceID] = make(map[string]int64)
	}
	omap := m.beaconOwners[beaconSliceID]
	if _, exists := omap[subjectID]; !exists && len(omap) >= DefaultMaxOwnersPerBeacon {
		var oldestSid string
		var oldestTs int64 = math.MaxInt64
		for sid, ts := range omap {
			if oldestSid == "" || ts < oldestTs || (ts == oldestTs && sid < oldestSid) {
				oldestSid = sid
				oldestTs = ts
			}
		}
		if oldestSid != "" {
			delete(omap, oldestSid)
			delete(m.subjectBeacons[oldestSid], beaconSliceID)
		}
	}
	omap[subjectID] = nowMs

	if m.subjectBeacons[subjectID] == nil {
		m.subjectBeacons[subjectID] = make(map[string]int64)
	}
	bmap := m.subjectBeacons[subjectID]
	if _, exists := bmap[beaconSliceID]; !exists && len(bmap) >= DefaultMaxBeaconsPerSubject {
		var oldestBcn string
		var oldestTs int64 = math.MaxInt64
		for bcn, ts := range bmap {
			if oldestBcn == "" || ts < oldestTs || (ts == oldestTs && bcn < oldestBcn) {
				oldestBcn = bcn
				oldestTs = ts
			}
		}
		if oldestBcn != "" {
			delete(bmap, oldestBcn)
			if om, ok := m.beaconOwners[oldestBcn]; ok {
				delete(om, subjectID)
			}
		}
	}
	bmap[beaconSliceID] = nowMs
	return nil
}

// GetBeaconOwners returns sorted subject IDs recorded as owners of `beaconSliceID`.
func (m *MemoryChallengeStore) GetBeaconOwners(_ context.Context, beaconSliceID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	omap := m.beaconOwners[strings.TrimSpace(beaconSliceID)]
	if len(omap) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(omap))
	for sid := range omap {
		out = append(out, sid)
	}
	sort.Strings(out)
	return out, nil
}

// RemoveSubjectBeaconOwnership removes `subjectID` from all beacon ownership sets and returns
// both orphaned beacons (zero remaining owners) and all beacons that were associated with `subjectID`.
func (m *MemoryChallengeStore) RemoveSubjectBeaconOwnership(_ context.Context, subjectID string) ([]string, []string, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bset := m.subjectBeacons[subjectID]
	if len(bset) == 0 {
		return nil, nil, nil
	}
	var orphaned []string
	var all []string
	for bcn := range bset {
		all = append(all, bcn)
		if omap, ok := m.beaconOwners[bcn]; ok {
			delete(omap, subjectID)
			if len(omap) == 0 {
				delete(m.beaconOwners, bcn)
				orphaned = append(orphaned, bcn)
			}
		}
	}
	delete(m.subjectBeacons, subjectID)
	sort.Strings(orphaned)
	sort.Strings(all)
	return orphaned, all, nil
}

// ExportSnapshot exports durable TOFU/ownership/anti-spoof state of MemoryChallengeStore (S1-4, S2-16).
func (m *MemoryChallengeStore) ExportSnapshot() ChallengeStoreSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	b2k := make(map[string]string, len(m.beaconToKey))
	for k, v := range m.beaconToKey {
		b2k[k] = v
	}
	seen := make(map[string]int64, len(m.beaconSeenAt))
	for k, v := range m.beaconSeenAt {
		seen[k] = v
	}
	owners := make(map[string]map[string]int64, len(m.beaconOwners))
	for bcn, omap := range m.beaconOwners {
		cp := make(map[string]int64, len(omap))
		for sid, ts := range omap {
			cp[sid] = ts
		}
		owners[bcn] = cp
	}
	g2n := make(map[string][]string, len(m.gpuToNative))
	for scope, nset := range m.gpuToNative {
		list := make([]string, 0, len(nset))
		for nat := range nset {
			list = append(list, nat)
		}
		sort.Strings(list)
		g2n[scope] = list
	}
	s2g := make(map[string]map[string]int64, len(m.subnetToGPU))
	for sub, gmap := range m.subnetToGPU {
		cp := make(map[string]int64, len(gmap))
		for g, ts := range gmap {
			cp[g] = ts.UnixMilli()
		}
		s2g[sub] = cp
	}
	return ChallengeStoreSnapshot{
		Version:      1,
		SavedAt:      m.nowFunc().UTC(),
		BeaconToKey:  b2k,
		BeaconSeenAt: seen,
		BeaconOwners: owners,
		GPUToNative:  g2n,
		SubnetToGPU:  s2g,
	}
}

// ImportSnapshot restores durable TOFU/ownership/anti-spoof state into MemoryChallengeStore.
func (m *MemoryChallengeStore) ImportSnapshot(snap ChallengeStoreSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.beaconToKey = make(map[string]string, len(snap.BeaconToKey))
	m.beaconSeenAt = make(map[string]int64, len(snap.BeaconToKey))
	var maxSeq int64
	for k, v := range snap.BeaconToKey {
		m.beaconToKey[k] = v
		seq := snap.BeaconSeenAt[k]
		if seq > maxSeq {
			maxSeq = seq
		}
		m.beaconSeenAt[k] = seq
	}
	m.beaconAccessSeq = maxSeq

	m.beaconOwners = make(map[string]map[string]int64, len(snap.BeaconOwners))
	m.subjectBeacons = make(map[string]map[string]int64)
	for bcn, omap := range snap.BeaconOwners {
		cp := make(map[string]int64, len(omap))
		for sid, ts := range omap {
			cp[sid] = ts
			if m.subjectBeacons[sid] == nil {
				m.subjectBeacons[sid] = make(map[string]int64)
			}
			m.subjectBeacons[sid][bcn] = ts
		}
		m.beaconOwners[bcn] = cp
	}

	m.gpuToNative = make(map[string]map[string]struct{}, len(snap.GPUToNative))
	for scope, list := range snap.GPUToNative {
		set := make(map[string]struct{}, len(list))
		for _, nat := range list {
			set[nat] = struct{}{}
		}
		m.gpuToNative[scope] = set
	}

	m.subnetToGPU = make(map[string]map[string]time.Time, len(snap.SubnetToGPU))
	for sub, gmap := range snap.SubnetToGPU {
		set := make(map[string]time.Time, len(gmap))
		for g, ms := range gmap {
			set[g] = time.UnixMilli(ms).UTC()
		}
		m.subnetToGPU[sub] = set
	}
	return nil
}

func (m *MemoryChallengeStore) applyIdentifyForWALReplay(res *VerifyResult, subjectID string, ownerRecorded bool, at time.Time) {
	if res == nil || !res.Accepted {
		return
	}
	ctx := context.Background()
	bcn := strings.TrimSpace(res.BeaconSliceID)
	key := strings.TrimSpace(res.DeviceKeySliceID)
	if !res.DeviceKeyRecoveryRequired && res.DeviceKeyBound && strings.HasPrefix(bcn, "d_bcn_") && strings.HasPrefix(key, "d_key_") {
		_, _ = m.CheckOrBindBeaconDeviceKey(ctx, bcn, key)
	}
	if ownerRecorded && subjectID != "" && strings.HasPrefix(bcn, "d_bcn_") && !res.DeviceKeyRecoveryRequired && !res.SpoofTrapTriggered && !res.IsVirtualGPU {
		_ = m.RecordBeaconOwner(ctx, bcn, subjectID)
	}
	if res.IsNative && strings.HasPrefix(res.ExactSliceID, "d_nat_") {
		if strings.HasPrefix(res.KeychainSliceID, "d_kch_") {
			_, _ = m.RecordNativeAnchorForGPU(ctx, "kch:"+res.KeychainSliceID, res.ExactSliceID)
		}
		if strings.HasPrefix(bcn, "d_bcn_") {
			_, _ = m.RecordNativeAnchorForGPU(ctx, "bcn:"+bcn, res.ExactSliceID)
		}
	}
	if res.IPSubnet != "" && res.IPSubnet != "unknown" && strings.HasPrefix(res.GpuAudioSliceID, "d_gpu_") {
		m.mu.Lock()
		if m.subnetToGPU[res.IPSubnet] == nil && len(m.subnetToGPU) < 16384 {
			m.subnetToGPU[res.IPSubnet] = make(map[string]time.Time)
		}
		if gmap := m.subnetToGPU[res.IPSubnet]; gmap != nil && len(gmap) < 64 {
			if at.IsZero() {
				at = m.nowFunc().UTC()
			}
			gmap[res.GpuAudioSliceID] = at
		}
		m.mu.Unlock()
	}
}

func (v *Verifier) normalizeBeaconSliceInput(beaconOrSlice string) (string, error) {
	trimmed := strings.TrimSpace(beaconOrSlice)
	if strings.HasPrefix(trimmed, "d_bcn_") && len(trimmed) > len("d_bcn_") {
		return trimmed, nil
	}
	if low := strings.ToLower(trimmed); isValidHexBeacon(low) {
		return "d_bcn_" + v.hmacHex32("bcn|"+low), nil
	}
	return "", errors.New("invalid beacon identifier: expected d_bcn_* slice ID or 32-char hex beacon_id")
}

// RebindDeviceKey updates the TOFU binding for a storage beacon directly without challenge PoP,
// step-up token, or ownership checks.
//
// Deprecated: Use RebindDeviceKeyWithProof instead (DeepSeek S2-13); direct calls bypass ownership
// and ECDSA proof-of-possession verification and are recorded as `unsafe_direct_rebind` in audit logs.
func (v *Verifier) RebindDeviceKey(ctx context.Context, beaconOrSlice, newDeviceKeySliceID string) (string, error) {
	bcnSlice, err := v.normalizeBeaconSliceInput(beaconOrSlice)
	if err != nil {
		return "", err
	}
	keySlice := strings.TrimSpace(newDeviceKeySliceID)
	if !strings.HasPrefix(keySlice, "d_key_") || len(keySlice) <= len("d_key_") {
		return "", errors.New("invalid new_device_key_slice_id: expected d_key_* slice ID")
	}
	rs, ok := v.store.(DeviceKeyRebindStore)
	if !ok {
		return "", errors.New("configured ChallengeStore does not implement DeviceKeyRebindStore")
	}
	prev, err := rs.RebindBeaconDeviceKey(ctx, bcnSlice, keySlice)
	if err == nil {
		v.appendRebindAudit(KeyRebindAuditEvent{
			Action:              "unsafe_direct_rebind",
			BeaconSliceID:       bcnSlice,
			NewDeviceKeySliceID: keySlice,
			PreviousKeyPresent:  prev != "",
			Outcome:             "unsafe_direct_rebind",
		})
	}
	return prev, err
}

// ClearDeviceKeyBinding clears the TOFU device-key binding for a storage beacon directly without
// challenge PoP or ownership checks.
//
// Deprecated: Prefer RebindDeviceKeyWithProof for key rotation/recovery or Verifier.EraseSubject
// for GDPR erasure (DeepSeek S2-13); direct calls are recorded as `unsafe_direct_clear` in audit logs.
func (v *Verifier) ClearDeviceKeyBinding(ctx context.Context, beaconOrSlice string) (string, error) {
	bcnSlice, err := v.normalizeBeaconSliceInput(beaconOrSlice)
	if err != nil {
		return "", err
	}
	rs, ok := v.store.(DeviceKeyRebindStore)
	if !ok {
		return "", errors.New("configured ChallengeStore does not implement DeviceKeyRebindStore")
	}
	prev, err := rs.ClearBeaconDeviceKey(ctx, bcnSlice)
	if err == nil {
		v.appendRebindAudit(KeyRebindAuditEvent{
			Action:             "unsafe_direct_clear",
			BeaconSliceID:      bcnSlice,
			PreviousKeyPresent: prev != "",
			Outcome:            "unsafe_direct_clear",
		})
	}
	return prev, err
}

func (v *Verifier) appendRebindAudit(ev KeyRebindAuditEvent) KeyRebindAuditEvent {
	var idBytes [8]byte
	_, _ = rand.Read(idBytes[:])
	ev.AuditID = "aud_" + hex.EncodeToString(idBytes[:])
	ev.Timestamp = v.cfg.NowFunc().UTC()
	if ev.Action == "" {
		ev.Action = "rebind_key"
	}

	v.auditMu.Lock()
	if len(v.rebindAudits) >= 4096 {
		copy(v.rebindAudits, v.rebindAudits[1:])
		v.rebindAudits[len(v.rebindAudits)-1] = ev
	} else {
		v.rebindAudits = append(v.rebindAudits, ev)
	}
	v.auditMu.Unlock()

	if v.cfg.AuditStore != nil {
		_ = v.cfg.AuditStore.AppendAuditEvent(context.Background(), ev)
	}
	if v.cfg.OnKeyRebindAudit != nil {
		v.cfg.OnKeyRebindAudit(ev)
	}
	return ev
}

// RecordDeniedRebindAudit records a failed/forbidden key-rebind attempt in the verifier's audit log.
func (v *Verifier) RecordDeniedRebindAudit(subjectID, beaconSliceID, clientIP, outcome string) KeyRebindAuditEvent {
	return v.appendRebindAudit(KeyRebindAuditEvent{
		Action:        "rebind_key",
		SubjectID:     strings.TrimSpace(subjectID),
		BeaconSliceID: strings.TrimSpace(beaconSliceID),
		ClientIP:      strings.TrimSpace(clientIP),
		Outcome:       outcome,
	})
}

// RecordClearSpoofAudit records an allowed or denied step-up spoof-clearance event (DeepSeek S2-20).
func (v *Verifier) RecordClearSpoofAudit(subjectID, clientIP, outcome string) KeyRebindAuditEvent {
	return v.appendRebindAudit(KeyRebindAuditEvent{
		Action:    "clear_spoof",
		SubjectID: strings.TrimSpace(subjectID),
		ClientIP:  strings.TrimSpace(clientIP),
		Outcome:   outcome,
	})
}

// ClearSubjectSpoofAudited clears active spoof state on `graph` for `subjectID` and emits a
// durable structured security audit event (DeepSeek S2-20).
func (v *Verifier) ClearSubjectSpoofAudited(graph *RiskGraph, subjectID, clientIP string, clearedAt time.Time) bool {
	if graph == nil {
		v.RecordClearSpoofAudit(subjectID, clientIP, "clear_spoof_no_graph")
		return false
	}
	cleared := graph.ClearSubjectSpoofAfterStepUp(subjectID, clearedAt)
	if cleared {
		v.RecordClearSpoofAudit(subjectID, clientIP, "spoof_cleared")
	} else {
		v.RecordClearSpoofAudit(subjectID, clientIP, "spoof_clear_noop")
	}
	return cleared
}

// RebindAuditEvents returns a snapshot copy of recorded security audit events.
func (v *Verifier) RebindAuditEvents() []KeyRebindAuditEvent {
	v.auditMu.Lock()
	defer v.auditMu.Unlock()
	out := make([]KeyRebindAuditEvent, len(v.rebindAudits))
	copy(out, v.rebindAudits)
	return out
}

// DeriveBeaconSliceID computes the canonical HMAC-SHA256 d_bcn_* slice ID from a raw 32-char hex beacon_id.
func (v *Verifier) DeriveBeaconSliceID(beaconID string) (string, error) {
	low := strings.ToLower(strings.TrimSpace(beaconID))
	if !isValidHexBeacon(low) {
		return "", errors.New("invalid beacon_id: expected 32-character hex string")
	}
	return "d_bcn_" + v.hmacHex32("bcn|"+low), nil
}

// RebindDeviceKeyWithProof executes an audited, ownership-verified, challenge-signed TOFU key rebind:
//  1. Verifies exact 32-hex beacon_id and checks ownership via persistent BeaconOwnerStore + ownerCheck BEFORE consuming any nonce.
//  2. Atomically consumes the single-use challenge_nonce.
//  3. Verifies the replacement ECDSA P-256 private key's signature over "prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>".
//  4. Derives d_key_*, updates the beacon's TOFU binding, persists ownership, and immediately retires the superseded d_key_* hard edge on any bound RiskGraph (S1-1, S1-3).
func (v *Verifier) RebindDeviceKeyWithProof(
	ctx context.Context,
	req KeyRebindRequest,
	ownerCheck func(subjectID, beaconSliceID string) bool,
	clientIP string,
) (*KeyRebindResult, error) {
	subjectID := strings.TrimSpace(req.SubjectID)
	if subjectID == "" {
		v.RecordDeniedRebindAudit("", "", clientIP, "denied_missing_subject")
		return nil, &VerificationError{Code: ErrCodeRebindForbidden, Detail: "subject_id is required"}
	}
	bcnLow := strings.ToLower(strings.TrimSpace(req.BeaconID))
	if !isValidHexBeacon(bcnLow) {
		v.RecordDeniedRebindAudit(subjectID, "", clientIP, "denied_invalid_beacon")
		return nil, &VerificationError{Code: ErrCodeRebindInvalidKeyProof, Detail: "beacon_id must be a 32-character hex string"}
	}
	beaconSliceID := "d_bcn_" + v.hmacHex32("bcn|"+bcnLow)

	// Persistent BeaconOwnerStore guard (S1-1): if durable owners exist, subjectID must be among them.
	if bos, ok := v.store.(BeaconOwnerStore); ok {
		if owners, err := bos.GetBeaconOwners(ctx, beaconSliceID); err == nil && len(owners) > 0 {
			found := false
			for _, o := range owners {
				if o == subjectID {
					found = true
					break
				}
			}
			if !found {
				v.RecordDeniedRebindAudit(subjectID, beaconSliceID, clientIP, "denied_not_owner")
				return nil, &VerificationError{Code: ErrCodeRebindForbidden, Detail: "beacon is not owned by authenticated subject"}
			}
		}
	}

	if ownerCheck != nil && !ownerCheck(subjectID, beaconSliceID) {
		v.RecordDeniedRebindAudit(subjectID, beaconSliceID, clientIP, "denied_not_owner")
		return nil, &VerificationError{Code: ErrCodeRebindForbidden, Detail: "beacon is not owned by authenticated subject"}
	}

	nonce := strings.TrimSpace(req.ChallengeNonce)
	if nonce == "" {
		v.RecordDeniedRebindAudit(subjectID, beaconSliceID, clientIP, "denied_invalid_nonce")
		return nil, &VerificationError{Code: ErrCodeChallengeInvalid, Detail: "challenge_nonce is required"}
	}
	ch, err := v.store.ConsumeChallenge(ctx, nonce)
	if err != nil || ch == nil || v.cfg.NowFunc().UnixMilli() > ch.ExpiresAt {
		v.RecordDeniedRebindAudit(subjectID, beaconSliceID, clientIP, "denied_invalid_nonce")
		return nil, &VerificationError{Code: ErrCodeChallengeInvalid, Detail: "challenge_nonce invalid, expired, or already replayed"}
	}

	okSig, pubKeyHex := VerifyECDSAP256RebindProof(req.DeviceKey, nonce, subjectID, bcnLow)
	if !okSig || pubKeyHex == "" {
		v.RecordDeniedRebindAudit(subjectID, beaconSliceID, clientIP, "denied_invalid_pop")
		return nil, &VerificationError{Code: ErrCodeRebindInvalidKeyProof, Detail: "invalid ECDSA P-256 proof-of-possession over rebind transcript"}
	}

	newKeySliceID := "d_key_" + v.hmacHex32("key|"+pubKeyHex)
	rs, ok := v.store.(DeviceKeyRebindStore)
	if !ok {
		return nil, errors.New("configured ChallengeStore does not implement DeviceKeyRebindStore")
	}
	prevKey, err := rs.RebindBeaconDeviceKey(ctx, beaconSliceID, newKeySliceID)
	if err != nil {
		return nil, err
	}
	if bos, ok := v.store.(BeaconOwnerStore); ok {
		_ = bos.RecordBeaconOwner(ctx, beaconSliceID, subjectID)
	}

	retiredGraphEdge := false
	v.boundGraphMu.RLock()
	bg := v.boundGraph
	v.boundGraphMu.RUnlock()
	if bg != nil {
		retiredGraphEdge = bg.RetireSubjectDeviceKey(subjectID, beaconSliceID, prevKey, newKeySliceID)
	}

	aud := v.appendRebindAudit(KeyRebindAuditEvent{
		Action:              "rebind_key",
		SubjectID:           subjectID,
		BeaconSliceID:       beaconSliceID,
		NewDeviceKeySliceID: newKeySliceID,
		PreviousKeyPresent:  prevKey != "",
		RetiredPreviousKey:  retiredGraphEdge || (prevKey != "" && prevKey != newKeySliceID),
		ClientIP:            strings.TrimSpace(clientIP),
		Outcome:             "rebound",
	})
	return &KeyRebindResult{
		AuditID:            aud.AuditID,
		SubjectID:          subjectID,
		BeaconSliceID:      beaconSliceID,
		DeviceKeySliceID:   newKeySliceID,
		Rebound:            true,
		RetiredPreviousKey: aud.RetiredPreviousKey,
	}, nil
}

// ForgetBeacons clears stored TOFU device-key bindings for the given d_bcn_* slices.
func (v *Verifier) ForgetBeacons(ctx context.Context, beaconSliceIDs ...string) int {
	rs, ok := v.store.(DeviceKeyRebindStore)
	if !ok {
		return 0
	}
	purged := 0
	for _, bcn := range beaconSliceIDs {
		bcn = strings.TrimSpace(bcn)
		if strings.HasPrefix(bcn, "d_bcn_") {
			if prev, err := rs.ClearBeaconDeviceKey(ctx, bcn); err == nil && prev != "" {
				purged++
			}
		}
	}
	return purged
}

// EraseSubject performs complete GDPR/CCPA erasure across BOTH the RiskGraph and the Verifier's
// persistent ChallengeStore / BeaconOwnerStore (clearing all subject edges, ownership entries, and
// TOFU key bindings on both exclusive and shared beacons — DeepSeek S2-21) and emits an audit event.
func (v *Verifier) EraseSubject(ctx context.Context, graph *RiskGraph, subjectID, clientIP string) (bool, int) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false, 0
	}
	beaconSet := make(map[string]struct{})
	removed := false
	if graph != nil {
		r, beacons := graph.RemoveSubjectAndCollectBeacons(subjectID)
		if r {
			removed = true
		}
		for _, b := range beacons {
			beaconSet[b] = struct{}{}
		}
	}
	if bos, ok := v.store.(BeaconOwnerStore); ok {
		if _, ownerBeacons, err := bos.RemoveSubjectBeaconOwnership(ctx, subjectID); err == nil && len(ownerBeacons) > 0 {
			removed = true
			for _, b := range ownerBeacons {
				beaconSet[b] = struct{}{}
			}
		}
	}
	allBeacons := make([]string, 0, len(beaconSet))
	for b := range beaconSet {
		allBeacons = append(allBeacons, b)
	}
	sort.Strings(allBeacons)
	purged := v.ForgetBeacons(ctx, allBeacons...)

	v.appendRebindAudit(KeyRebindAuditEvent{
		Action:             "erase_subject",
		SubjectID:          subjectID,
		PreviousKeyPresent: purged > 0,
		ClientIP:           strings.TrimSpace(clientIP),
		Outcome:            "subject_erased",
	})
	return removed, purged
}
