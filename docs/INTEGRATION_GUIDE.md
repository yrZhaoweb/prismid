# PrismID Full-Stack Integration Guide (`INTEGRATION_GUIDE.md` — `v1.2.1`)

This guide shows how to integrate **PrismID v1.2.1** into a Web application (`prismid-js`), a Tauri 2 Desktop application (`prismid-native`), and a Go backend (`prismid-go`) in single-node or multi-instance deployments.

---

## 1. Browser Web Application Integration (`prismid-js`)

Install `prismid-js` (`>= 1.2.1`):

```bash
npm install prismid-js
```

Initialize the client in your frontend application:

```ts
import { createPrismClient, resetDeviceKeyCache } from 'prismid-js'

export const prismClient = createPrismClient({
  baseUrl: '', // Same-origin or custom API gateway host
  getAccessToken: () => sessionStorage.getItem('prismid_bearer_token'),
  requestTimeoutMs: 5000,  // Bounded HTTP header + body deadline (default: 5000ms)
  probeTimeoutMs: 800,     // Per-probe browser signal budget (default: 800ms)
  providerTimeoutMs: 2500, // Decoupled budget for external Turnstile / Tauri IPC providers
  tenantId: undefined,     // Optional X-PrismID-Tenant-ID when -enable-multi-tenant is enabled
  onError: (err) => {
    console.warn('[PrismID]', err.code, err.status, err.message)
  },
})

// 1. Standard evaluation (returns VerifyResponse | null; check prismClient.getLastError() on null):
const result = await prismClient.identify()
if (result?.accepted) {
  console.log('Risk status:', result.risk_status, 'Slices:', result.beacon_slice_id, result.device_key_slice_id)
} else if (result?.skipped) {
  // Server returned { should_collect: false } (e.g. pre-consent GDPR gate): no probes or silos were touched.
}

// 2. Structured outcome without null ambiguity:
const detailed = await prismClient.identifyDetailed()
if (!detailed.ok) {
  console.error('PrismID identify failed:', detailed.error.code, detailed.error.message)
}

// 3. Proactive key rotation (no MFA needed — signs continuity proof with existing IndexedDB key):
await prismClient.rebindKey({ rotate: true })

// 4. Lost-key recovery after backend MFA step-up mints a single-use stepup_v2 token:
// await prismClient.rebindKey({ stepUpToken })

// 5. Clear single-account spoof cooldown after MFA step-up:
// await prismClient.clearSpoof({ stepUpToken: clearSpoofStepUpToken })

// 6. Right-to-erasure / logout cleanup:
// await prismClient.deleteSubject()
// resetDeviceKeyCache()
```

---

## 2. Tauri 2 Desktop Application Integration (`prismid-native` + `prismid-js`)

### 2.1 Rust Side (`src-tauri/Cargo.toml` & `src-tauri/src/lib.rs`)

Add `prismid-native` (`1.2.1`) to `src-tauri/Cargo.toml`:

```toml
[dependencies]
prismid-native = { git = "https://github.com/yrZhaoweb/prismid", version = "1.2.1" }
```

Expose a Tauri command in `src-tauri/src/lib.rs` (note: set `PRISMID_DISABLE_KEYCHAIN=1` if running inside a headless CI daemon where macOS Login Keychain should be skipped in favor of the `0600` file anchor):

```rust
#[tauri::command]
fn collect_native_hardware_anchor() -> prismid_native::NativeHardwareAnchor {
    prismid_native::collect_native_anchor().clone()
}
```

### 2.2 Desktop WebView Side

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

## 3. Go Backend Verification, Persistence & Risk Graph (`prismid-go`)

### 3.1 Embed `prismid.Verifier` + `RiskGraph` with Durable State & Audit Stores

> [!IMPORTANT]
> **Production Authentication, Proxy & Multi-Instance Boundary**:
> - Extract `subjectID` strictly from your server-side authenticated JWT/session middleware.
> - Pass `clientIP` and JA4/HTTP2 headers (`X-PrismID-JA4` / `CF-JA4`, `X-PrismID-H2-Fingerprint`) via `prismid.ParseTrustedProxyCIDRs(...)` + `prismid.ExtractRealClientIP(...)` (`-trusted-proxy-cidrs` on `prismid-server`) so client-forged `X-Forwarded-For` prefixes and direct-peer headers are stripped right-to-left.
> - **Single-Node vs. Multi-Instance**: `FileStateStore` + `FileAuditStore` provide `0600` crash-safe persistence for a **single Go instance**. For multi-replica horizontal scaling behind a load balancer, pass `-redis-url redis://...` (built-in zero-dependency `prismid.NewRedisStore`, implementing cluster-safe `ChallengeStore`, TOFU `SET NX EX`, `DistributedReplayGuard`, and pipelined 2-hop `GraphBackend`) or attach `prismid.NewSQLGraphStore(db, prismid.SQLDialectPostgres)` (`database/sql` PostgreSQL/SQLite backend).

```go
import (
    "context"
    "log"
    "os"
    "time"
    prismid "github.com/yrZhaoweb/prismid/server/go"
)

ctx := context.Background()
memStore := prismid.NewMemoryChallengeStore()
stateStore, err := prismid.NewFileStateStore("/var/lib/prismid/state.json")
if err != nil {
    log.Fatal(err)
}
stateStore.SetErrorHandler(func(err error) {
    log.Printf("[WARN] prismid state persistence error: %v", err)
})
auditStore, err := prismid.NewFileAuditStore("/var/lib/prismid/audit.jsonl")
if err != nil {
    log.Fatal(err)
}

riskGraph := prismid.NewRiskGraphWithOptions(prismid.GraphOptions{
    HardAnchorPolicy: prismid.HardAnchorPolicySharedStepUp, // 2-3 clean Web users -> yellow+pending; use HardAnchorPolicyStrict1To1 for strict 1:1 promos
    MaxSubjects:      prismid.DefaultMaxGraphSubjects,
    Store:            memStore,
})
if _, _, err := stateStore.RestoreInto(ctx, riskGraph, memStore); err != nil {
    log.Fatalf("restore prismid state: %v", err)
}
stateStore.StartBackgroundWorker(riskGraph, memStore, nil, 250*time.Millisecond, 30*time.Second)
defer stateStore.FlushAndClose(ctx, riskGraph, memStore, nil)

verifier := prismid.NewVerifier(prismid.Config{
    HMACSecret:               []byte(os.Getenv("PRISMID_HMAC_SECRET")),
    ChallengeTTL:             60 * time.Second,
    EnforceChallengeIP:       false, // Set true if clients never switch dual-stack/carrier IP mid-handshake
    SpotPixelTolerance:       2,
    MaxDistinctGPUsPerSubnet: 3,
    SubnetWindow:             7 * 24 * time.Hour,
    AuditStore:               auditStore,
}, memStore)
verifier.BindRiskGraph(riskGraph) // Auto-wires co-owner checks & retires old d_key_* edges on rebind!

// 1. Issue challenge on POST /api/v1/risk/challenge (returns ErrCodeChallengeRateLimited -> HTTP 429 on quota saturation)
ch, err := verifier.IssueChallenge(ctx, trustedClientIP)

// 2. Verify & record into RiskGraph on POST /api/v1/risk/identify (O(1) ~400B WAL append, ~3.5µs)
res, err := verifier.VerifyAndDerive(ctx, identifyReq, trustedClientIP)
if err == nil && res.Accepted {
    ownerRecorded := verifier.RecordVerifiedBeaconOwner(ctx, authenticatedSubjectID, res)
    nowUTC := time.Now().UTC()
    snap := riskGraph.RecordVerification(authenticatedSubjectID, nowUTC, res)
    _ = stateStore.AppendWAL(prismid.StateWALRecord{
        Op:            prismid.WALOpIdentify,
        At:            nowUTC,
        SubjectID:     authenticatedSubjectID,
        OwnerRecorded: ownerRecorded,
        VerifyResult:  res,
    }, false)
    _ = snap
}
```

### 3.2 Reference PostgreSQL Schema & Hard-vs-Soft Slice Query Contract

For horizontally scaled multi-instance services, persist observations in PostgreSQL and load the local neighborhood into `prismid.EvaluateSubjectComponentWithPolicy`:

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
    observed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS user_devices_device_id_idx ON user_devices(device_id);
```

> [!WARNING]
> **Never join accounts unconditionally on soft slices (`d_gpu_*`, `d_web_*`, `d_sys_*`) in SQL — even when `spoof_trap_triggered = TRUE`!**
> Restrict SQL identity joins to **Per-Device Hard Identity Slices** (`d_key_%`, `d_nat_%`, `d_kch_%`, `d_bcn_%`), delete retired `d_key_old` rows on key rotation, and pass candidate neighborhood edges into `prismid.EvaluateSubjectComponentWithPolicy(edges, targetUserID, 0.60, prismid.HardAnchorPolicySharedStepUp)` in Go.

---

## 4. Dual-Path Key Rebinding, Single-Use Step-Up, Audited Spoof Clearance & Admin APIs

- **Secure Standalone Defaults (`cmd/prismid-server`)**: Defaults to `-demo-mode=false` and `-addr=127.0.0.1:8090`, supports separate rotatable secrets (`-auth-secret`, `-auth-secret-prev`, `-stepup-secret`, `-stepup-secret-prev`), and exposes `-admin-secret` endpoints:
  - `POST /api/v1/risk/admin/mint-bearer` — Mints expiring v2 subject bearer tokens (`<subject_id>.<exp>.<hmac>`).
  - `POST /api/v1/risk/admin/mint-step-up` — Mints **single-use** `stepup_v2.<jti>.<exp>.<hmac>` tokens for `d_bcn_*` key recovery or `"clear_spoof"`.
  - `POST /api/v1/risk/admin/revoke-token` — Revokes a bearer token or subject session window immediately (persisted across restarts via `ReplayGuardSnapshot` in `-state-file`).
  - `POST /api/v1/risk/admin/prune-graph` — Prunes expired soft/spoof edges on demand and compacts `-state-file`.
  - `POST /api/v1/risk/admin/flush-state` — Compacts `<state-file>.wal` into `<state-file>` atomically on demand and reports `persist_errors`.
- **Dual-Path Key Rebinding (`RebindDeviceKeyWithProof` / `POST /api/v1/risk/rebind-key`)**:
  1. **Proactive Two-Phase Rotation (No MFA Needed, MitM-Safe)**: Client calls `prismClient.rebindKey({ rotate: true })`, preparing the new keypair via `prepareDeviceKeyRotation`, signing `"prismid-v2-rebind-prev|<nonce>|<subject_id>|<beacon_id>|<new_pub_key>"` with the previous key and `"prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>"` with the new key, and committing to `IndexedDB` only after HTTP 200. Server verifies continuity and `<new_pub_key>` binding against the currently bound `d_key_*`, updates TOFU, retires `d_key_old` from `RiskGraph`, and records a `KeyRebindAuditEvent` (`Action: "rebind_key_rotation"`).
  2. **Lost-Key Recovery (Single-Use Step-Up MFA)**: Backend verifies MFA (WebAuthn/Passkey/OTP) and mints a `stepup_v2` token via `SignStepUpToken(subjectID, beaconSliceID, stepUpSecret)`. Server checks co-owner membership (`riskGraph.SubjectOwnsBeacon` — works across shared family browsers and survives restarts via persistent `BeaconOwnerStore`), consumes the `stepup_v2` JTI **once** (replays return `403`), retires stale `d_key_*` edges for that subject, and audits `Action: "rebind_key"`.
- **Audited Spoof Clearance (`ClearSubjectSpoofAudited` / `POST /api/v1/risk/clear-spoof`)**: Consumes a single-use `stepup_v2` token targeting `"clear_spoof"`, clears active spoof edges while retaining `+1.5` `HistoricalSpoof` log-odds, and writes an audit event (`Action: "clear_spoof"`) to `AuditStore` and `OnKeyRebindAudit`.
- **Complete GDPR Erasure (`Verifier.EraseSubject` / `DELETE /api/v1/risk/subject`)**: Purges all subject graph edges, persistent `BeaconOwnerStore` entries, and `beaconToKey` TOFU bindings (including beacons previously shared on multi-user profiles).
