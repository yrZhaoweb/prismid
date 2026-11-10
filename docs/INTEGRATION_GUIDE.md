# PrismID Full-Stack Integration Guide (`INTEGRATION_GUIDE.md`)

This guide shows how to integrate **PrismID v1.0.1** into a Web application (`prismid-js`), a Tauri 2 Desktop application (`prismid-native`), and a Go + PostgreSQL + Redis backend (`prismid-go`).

---

## 1. Browser Web Application Integration (`prismid-js`)

Install `prismid-js` (`>= 1.0.1`):

```bash
npm install prismid-js
```

Initialize the client in your frontend application:

```ts
import { createPrismClient } from 'prismid-js'

export const prismClient = createPrismClient({
  baseUrl: '', // Same-origin or custom API gateway host
  getAccessToken: () => localStorage.getItem('access_token'),
  requestTimeoutMs: 5000, // Bounded network & provider deadline (default: 5000ms)
})

// Trigger after user login, signup, or before promotional claim:
const result = await prismClient.identify()
if (result && result.accepted) {
  console.log('Verified slices:', result.beacon_slice_id, result.gpu_audio_slice_id)
}
```

---

## 2. Tauri 2 Desktop Application Integration (`prismid-native` + `prismid-js`)

### 2.1 Rust Side (`src-tauri/Cargo.toml` & `src-tauri/src/lib.rs`)

Add `prismid-native` (`1.0.1`) to `src-tauri/Cargo.toml`:

```toml
[dependencies]
prismid-native = { git = "https://github.com/yrZhaoweb/prismid", version = "1.0.1" }
```

Expose a Tauri command in `src-tauri/src/lib.rs`:

```rust
#[tauri::command]
fn collect_native_hardware_anchor() -> prismid_native::NativeHardwareAnchor {
    prismid_native::collect_native_anchor().clone()
}
```

### 2.2 Desktop WebView Side

Pass `nativeAnchorProvider` to `createPrismClient`:

```ts
import { createPrismClient } from 'prismid-js'
import { invoke } from '@tauri-apps/api/core'

export const prismClient = createPrismClient({
  baseUrl: 'https://api.example.com',
  getAccessToken: () => sessionStore.accessToken,
  nativeAnchorProvider: () => invoke('collect_native_hardware_anchor'),
})

await prismClient.identify()
```

---

## 3. Go Backend Verification & Connected-Component Graph (`prismid-go`)

### 3.1 Embed `prismid.Verifier` Behind Your Authenticated Gateway

> [!IMPORTANT]
> **Production Authentication & IP Boundary**:
> - Extract `userID` (`subjectID`) strictly from your server-side authenticated JWT or session middleware—never from unauthenticated query parameters.
> - Pass `clientIP` from a trusted reverse proxy header (`X-Forwarded-For` / `CF-Connecting-IP`) only when the request originates from your trusted ingress proxy CIDRs.

```go
import (
    "context"
    "os"
    "time"
    prismid "github.com/yrZhaoweb/prismid/server/go"
)

verifier := prismid.NewVerifier(prismid.Config{
    HMACSecret:               []byte(os.Getenv("PRISMID_HMAC_SECRET")),
    ChallengeTTL:             60 * time.Second,
    SpotPixelTolerance:       2,
    MaxDistinctGPUsPerSubnet: 3,
    SubnetWindow:             7 * 24 * time.Hour,
}, challengeStore)

// 1. Issue challenge on POST /api/v1/risk/challenge
ch, err := verifier.IssueChallenge(ctx, trustedClientIP)

// 2. Verify & derive orthogonal slices on POST /api/v1/risk/identify
res, err := verifier.VerifyAndDerive(ctx, identifyReq, trustedClientIP)
// res.SliceNodes() returns:
//   - res.ExactSliceID    (d_nat_* hard slice on Desktop, or d_web_* soft slice on Web)
//   - res.KeychainSliceID (d_kch_* hard slice on Desktop when OS Keychain/Registry anchor is present)
//   - res.BeaconSliceID   (d_bcn_* hard slice on Web when 128-bit 5-silo beacon is present)
//   - res.GpuAudioSliceID (d_gpu_* soft model slice — 100% IP-free & extension-drift-free)
//   - res.SysNetSliceID   (d_sys_* soft subnet/OS slice — dual-monitor & WKWebView safe)
```

### 3.2 Reference PostgreSQL Schema & Hard-vs-Soft Slice Query Contract

Persist observations into `devices` and `user_devices`, storing `spoof_trap_triggered` and `beacon_slice_id` alongside each edge so your SQL queries or `prismid.EvaluateSubjectComponent` respect the **Hard Identity vs. Soft Model Slice** rules:

```sql
CREATE TABLE IF NOT EXISTS devices (
    id              BIGSERIAL PRIMARY KEY,
    visitor_id      VARCHAR(255) NOT NULL UNIQUE,
    confidence      DOUBLE PRECISION NOT NULL DEFAULT 0.95,
    node_type       VARCHAR(32),
    ip_subnet       VARCHAR(64),
    signals_summary JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_devices (
    user_id              BIGINT NOT NULL,
    device_id            BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    beacon_slice_id      VARCHAR(80),
    native_slice_id      VARCHAR(80),
    spoof_trap_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS user_devices_device_id_idx ON user_devices(device_id);
```

> [!WARNING]
> **Do NOT join accounts unconditionally on soft slices (`d_gpu_*`, `d_web_*`, `d_sys_*`) in SQL — even when `spoof_trap_triggered = TRUE`!**
> Because `d_gpu_*` is a hardware model signature shared by same-model laptops, unconditional SQL joins must be restricted strictly to **Per-Device Hard Identity Slices** (`d_key_%`, `d_nat_%`, `d_kch_%`, `d_bcn_%`). Joining `d_gpu_*` on `spoof_trap_triggered = TRUE` would allow a privacy-browser user to contaminate clean users of the same laptop model. For conditional soft-slice burst and spoof evaluation (with 24h spoof TTL, 3-clean-visit decay, and 7d observation-time soft-edge TTL), load the local neighborhood rows into `[]prismid.GraphEdge` and call `prismid.EvaluateSubjectComponent(edges, targetUserID, 0.60)`.

```sql
-- Unconditional Per-Device Hard Identity Edges (0% Model-Collision False Merges):
SELECT ud.user_id, d.visitor_id AS slice_id
FROM user_devices ud
JOIN devices d ON d.id = ud.device_id
WHERE d.confidence >= 0.60
  AND (
    d.visitor_id LIKE 'd_key_%'
    OR d.visitor_id LIKE 'd_nat_%'
    OR d.visitor_id LIKE 'd_kch_%'
    OR d.visitor_id LIKE 'd_bcn_%'
  );
```


## 4. Authentication, Key Recovery, Spoof Decay, and Incomplete Graph Results

- **Expiring Bearer Auth & Rate Limiting**: Authenticate before invoking `IssueChallenge` or the stateful `VerifyAndDerive`. When `-demo-mode=false`, `cmd/prismid-server` strictly enforces expiring v2 HMAC-SHA256 signed tokens (`SignSubjectBearerToken` / `SignSubjectBearerTokenWithExpiry`, default 24h TTL; legacy non-expiring static tokens are rejected unless `-allow-legacy-tokens=true`) and per-IP token-bucket rate limiting (`-rate-limit`), returning `401` before nonce consumption or binding writes and `429` on abuse floods.
- **Transactional IndexedDB Key Binding**: The Web SDK signs only with a key confirmed in a committed IndexedDB transaction. Concurrent initialization is shared within a page and uses an atomic read/conditional insert across pages. Blocked, timed-out, or aborted storage does not establish a binding with a temporary key.
- **Audited, Ownership-Verified TOFU Key Recovery (`RebindDeviceKeyWithProof` / `POST /api/v1/risk/rebind-key`)**: When a previously bound beacon has no matching device-key proof (e.g. IndexedDB cleared or browser profile migrated), `VerifyAndDerive` returns `device_key_recovery_required=true`, `risk_pending=true`, and `confidence=0.30` (`risk_status="unknown"`), leaving the prior TOFU binding intact. To recover safely without cross-account hijacking or oracle leaks:
  1. Verify out-of-band step-up authentication (Passkey / WebAuthn / OTP) on your backend and mint a short-lived domain-separated step-up token (`SignStepUpToken(subjectID, beaconSliceID, secret)`, 5m TTL).
  2. Have the client obtain a fresh `challenge_nonce` (`POST /api/v1/risk/challenge`), sign `"prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>"` using `signRebindWithDeviceKey({ nonce, subjectId, beaconId })` from `prismid-js`, and submit `{ challenge_nonce, beacon_id, device_key, step_up_token }` to `POST /api/v1/risk/rebind-key` (or call `verifier.RebindDeviceKeyWithProof(ctx, req, riskGraph.SubjectOwnsBeaconExclusively, clientIP)` in Go).
  3. The server checks exclusive `d_bcn_*` ownership **before** consuming the nonce, verifies ECDSA P-256 key possession, logs a structured `KeyRebindAuditEvent` (`OnKeyRebindAudit` / `verifier.RebindAuditEvents()`), and omits `previous_device_key_slice_id` from responses.
- **Anti-Wash Spoof Decay & Step-Up Clearance (`POST /api/v1/risk/clear-spoof`)**: Single-account tampering signals (`canvas_noise_injected`, transient Worker mismatch) represent a bounded risk window rather than an irrevocable permanent ban, while blocking rapid client/cross-device washing: `CleanStreak` increments **only** when clean visits arrive from the **exact same strongest hard anchor** (`d_key_*`, `d_nat_*`, or `d_bcn_*`) spaced at least `DefaultMinCleanStreakInterval` (`1h`) apart (or after `DefaultSpoofEdgeTTL = 24h`, or immediately after MFA step-up via `POST /api/v1/risk/clear-spoof` / `riskGraph.ClearSubjectSpoofAfterStepUp`), while permanently retaining `+1.5` `HistoricalSpoof` residual log-odds (`LogOddsScore = -0.5` rather than `-2.0`).
- **Complete GDPR Erasure (`DELETE /api/v1/risk/subject`)**: `RiskGraph.RemoveSubjectAndCollectBeacons` paired with `Verifier.ForgetBeacons` deletes both graph edges and `beaconToKey` TOFU bindings for exclusively owned beacons.
- **Hard-Slice Loss Markers vs. Soft-Slice Observation Pruning**: Soft-slice edges (`d_gpu_*`, `d_web_*`, `d_sys_*`, `d_gpusys_*`) track `ObservedAt` and expire/prune after `DefaultSoftEdgeTTL` (7 days). Eviction loss markers (`incompleteSlices` $\to$ `truncated=true, risk_pending=true`) apply specifically when a **per-device hard identity slice** (`d_key_*`, `d_nat_*`, `d_kch_*`, `d_bcn_*`) or a subject's hard history is evicted, ensuring popular laptop models exceeding `MaxSubjectsPerSlice = 256` on `d_gpu_*` never falsely mark unrelated users `truncated`. When the global subject cache (`DefaultMaxGraphSubjects = 50000`) is full, new subjects receive `truncated=true, risk_pending=true` rather than evicting existing subject history.
