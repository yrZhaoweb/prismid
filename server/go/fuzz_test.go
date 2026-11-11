package prismid

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func jsonMarshalHelper(v any) ([]byte, error) {
	return json.Marshal(v)
}

// FuzzVerifyAndDerive fuzzes AEAD decryption, JSON unmarshaling, beacon hex validation,
// device-key ECDSA parsing, and shader spot-pixel verification against arbitrary malformed inputs (S3-57).
func FuzzVerifyAndDerive(f *testing.F) {
	f.Add("0123456789abcdef0123456789abcdef", `{"v":1,"nonce":"0123456789abcdef0123456789abcdef"}`, "203.0.113.10")
	f.Add("short", `{invalid json`, "invalid-ip")
	f.Add("ffffffffffffffffffffffffffffffff", `{"v":1,"nonce":"ffffffffffffffffffffffffffffffff","beacon_id":"short","webgl":{"static_webgl_fp_hash":"a","webgl_limits_vector":"1|2","spot_pixels":[[0,0,0,255]]},"audio_compressor_hash":"b"}`, "::1")

	f.Fuzz(func(t *testing.T, rawNonce, rawJSON, clientIP string) {
		if len(rawNonce) == 0 || len(rawNonce) > 256 || len(rawJSON) > 16384 {
			return
		}
		ctx := context.Background()
		store := NewMemoryChallengeStore()
		v := NewVerifier(Config{HMACSecret: []byte("fuzz-secret-key-32-bytes-0000000")}, store)

		now := time.Now().UTC()
		_ = store.SaveChallenge(ctx, Challenge{
			Nonce:        rawNonce,
			RenderSeed:   [4]float64{2.1, 3.2, 4.3, 5.4},
			SamplePoints: DefaultSamplePoints,
			IssuedAt:     now.UnixMilli(),
			ExpiresAt:    now.Add(time.Minute).UnixMilli(),
			ClientIP:     clientIP,
		}, time.Minute)

		sealed, err := SealPayload(rawNonce, []byte("123456789012"), []byte(rawJSON))
		if err != nil {
			return
		}
		_, _ = v.VerifyAndDerive(ctx, IdentifyRequest{
			ChallengeNonce: rawNonce,
			SealedPayload:  sealed,
		}, clientIP)
	})
}

// FuzzRecordVerification fuzzes RiskGraph.RecordVerification against arbitrary short/malformed
// slice IDs, confidence weights, and flags to guarantee zero panics (S1-8, S3-31, S3-57).
func FuzzRecordVerification(f *testing.F) {
	f.Add("user_1", "short", "tiny", "d_bcn_1", "d_key_1", true, true)
	f.Add("", "d_gpu_", "d_sys_", "", "", false, false)
	f.Add("u|pipe.dot", "d_gpu_abcdef", "d_sys_123456", "d_bcn_xyz", "d_key_old", false, true)

	f.Fuzz(func(t *testing.T, subjectID, gpuSlice, sysSlice, bcnSlice, keySlice string, spoof, recovery bool) {
		g := NewRiskGraph(AuthoritativeConfidenceThreshold)
		res := &VerifyResult{
			Accepted:                  true,
			Confidence:                0.95,
			DeviceKeySliceID:          keySlice,
			DeviceKeyBound:            keySlice != "",
			DeviceKeyRecoveryRequired: recovery,
			ExactSliceID:              "d_web_fuzz",
			BeaconSliceID:             bcnSlice,
			GpuAudioSliceID:           gpuSlice,
			SysNetSliceID:             sysSlice,
			SpoofTrapTriggered:        spoof,
		}
		_ = g.RecordVerification(subjectID, time.Now().UTC(), res)
		_ = g.EvaluateSubject(subjectID)
	})
}
