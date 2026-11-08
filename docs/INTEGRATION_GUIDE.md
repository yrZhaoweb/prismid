# PrismID Full-Stack Integration Guide (`INTEGRATION_GUIDE.md`)

This guide demonstrates how to integrate **PrismID** into any standalone or existing Web application, Tauri 2 Desktop application, and Go + PostgreSQL + Redis backend.

---

## 1. Browser Web Application Integration (`prismid-js`)

Install `prismid-js` in your frontend workspace:

```ts
import { createPrismClient } from 'prismid-js'

export const prismClient = createPrismClient({
  baseUrl: '', // Same-origin or custom API host
  getAccessToken: () => localStorage.getItem('access_token'),
})

// Trigger after user login, signup, or before promotional claim:
const result = await prismClient.identify()
```

---

## 2. Tauri 2 Desktop Application Integration (`prismid-native` + `prismid-js`)

### 2.1 Rust Side (`src-tauri/Cargo.toml` & `src-tauri/src/lib.rs`)

Add `prismid-native` to `src-tauri/Cargo.toml`:

```toml
[dependencies]
prismid-native = { git = "https://github.com/yrZhaoweb/prismid", version = "0.1.0" }
```

Expose a single Tauri command in `src-tauri/src/lib.rs`:

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

### 3.1 Embed `prismid.Verifier` in Your Go Service

```go
import (
    "context"
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
ch, err := verifier.IssueChallenge(ctx, clientIP)

// 2. Verify & derive 3 orthogonal slices on POST /api/v1/risk/identify
res, err := verifier.VerifyAndDerive(ctx, identifyReq, clientIP)
// res.SliceNodes() returns:
//   - res.ExactSliceID    (d_nat_* or d_web_*)
//   - res.GpuAudioSliceID (d_gpu_* — 100% IP-free & renderer-text-free!)
//   - res.SysNetSliceID   (d_sys_* — OS + CPU + TZ + /24 IP, dual-monitor safe)
//   - res.CrowdSliceID    (d_ip24_crowd_* when >3 distinct GPUs hit same /24 subnet)
```

### 3.2 Reference PostgreSQL Schema & Connected-Component Risk Snapshot

Persist all slices returned by `res.SliceNodes()` into `devices` and link them to the authenticated user in `user_devices`:

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
    user_id    BIGINT NOT NULL,
    device_id  BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS user_devices_device_id_idx ON user_devices(device_id);
```

Because `d_nat_*/d_web_*`, `d_gpu_*`, and `d_sys_*` are stored as rows in `devices` with `confidence >= 0.60` (while virtual GPUs like `SwiftShader` are stored with `confidence = 0.30`), a single SQL edge definition automatically connects all accounts sharing **any** orthogonal slice:

```sql
SELECT ud.user_id, d.visitor_id AS slice_id
FROM user_devices ud
JOIN devices d ON d.id = ud.device_id
WHERE d.confidence >= 0.60;
```
