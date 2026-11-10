# PrismID Full-Stack Integration Guide (`INTEGRATION_GUIDE.md`)

This guide shows how to integrate **PrismID v1.0.0** into a Web application (`prismid-js`), a Tauri 2 Desktop application (`prismid-native`), and a Go + PostgreSQL + Redis backend (`prismid-go`).

---

## 1. Browser Web Application Integration (`prismid-js`)

Install `prismid-js` (`>= 1.0.0`):

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

Add `prismid-native` (`1.0.0`) to `src-tauri/Cargo.toml`:

```toml
[dependencies]
prismid-native = { git = "https://github.com/yrZhaoweb/prismid", version = "1.0.0" }
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
> **Do NOT join accounts unconditionally on soft slices (`d_gpu_*`, `d_web_*`, `d_sys_*`) in SQL!**
> Because `d_gpu_*` is a hardware model signature shared by same-model laptops, unconditional SQL joins must be restricted to **Per-Device Hard Identity Slices** (`d_nat_%`, `d_kch_%`, `d_bcn_%`) or observations where `spoof_trap_triggered = TRUE`. For full conditional soft-slice burst evaluation, load the 3-hop neighborhood rows into `[]prismid.GraphEdge` and call `prismid.EvaluateSubjectComponent(edges, targetUserID, 0.60)`.

```sql
-- Unconditional Per-Device Hard Identity Edges (0% Model-Collision False Merges):
SELECT ud.user_id, d.visitor_id AS slice_id
FROM user_devices ud
JOIN devices d ON d.id = ud.device_id
WHERE d.confidence >= 0.60
  AND (
    d.visitor_id LIKE 'd_nat_%'
    OR d.visitor_id LIKE 'd_kch_%'
    OR d.visitor_id LIKE 'd_bcn_%'
    OR ud.spoof_trap_triggered = TRUE
  );
```


## 4. Authentication, Key Recovery, and Incomplete Graph Results

- Authenticate before invoking `IssueChallenge` or the stateful `VerifyAndDerive`. The standalone server requires a signed Bearer on both endpoints when `-demo-mode=false`; absent or invalid authentication returns 401 before nonce consumption or any binding/statistics writes. Demo mode retains the local playground behavior.
- The Web SDK signs only with a key confirmed in a committed IndexedDB transaction. Concurrent initialization is shared within a page and uses an atomic read/conditional insert across pages. Blocked, timed-out, or aborted storage does not establish a binding with a temporary key.
- When a previously bound beacon has no matching device-key proof, the result includes `device_key_recovery_required=true`, `risk_pending=true`, and a non-authoritative confidence. `RecordVerification` returns `risk_status="unknown"` for that request and leaves the old identity history and TOFU binding unchanged. Restore the original key or perform an independent authenticated step-up in the integrating application; the library does not silently authorize replacement keys. Recovery/pending responses do not activate the SDK success cooldown.
- `truncated=true` with `risk_pending=true` means cached evidence was lost or the traversal/cache limit was reached. The graph withholds `earliest_subject_id`, returns unknown for otherwise green/yellow results, and may retain red when remaining evidence already proves a risk. Do not interpret a pending result as a clean identity.
- Per-slice or per-subject eviction retains bounded loss markers, including markers for evicted slices observed again later. When the global subject cache is full, new subjects receive an incomplete/pending result instead of deleting existing history. Loss markers are conservative for the lifetime of the in-memory graph; their own capacity exhaustion makes all graph results incomplete. Use authoritative persistent observations and rebuild the cache to recover full-history conclusions.
