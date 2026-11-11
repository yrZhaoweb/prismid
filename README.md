# PrismID (`prismid` v1.2.0)

> **Open-source orthogonal hardware signal collection, non-extractable WebCrypto ECDSA P-256 device key binding, raw-measurement consistency checks, and multi-slice risk correlation SDK for Web (`prismid-js`), Tauri / Rust Desktop (`prismid-native`), and Go (`prismid-go`).**
>
> **零商业调用成本、支持 Browser Web + Tauri Desktop (Rust) + Go Server 的全栈设备风控信号采集、WebCrypto 非导出私钥签名锚点、原始测量一致性校验与正交切片关联开源引擎（MIT License）。**

---

## Why PrismID? / 为什么选择 PrismID？

Traditional open-source fingerprinting libraries hash ~20 browser attributes on the client side into a single string (`visitorId`) and send it to the backend. In adversarial scenarios, that approach suffers from three structural weaknesses:
1. **SHA-256 Avalanche Fragility**: Modifying a single attribute (such as Canvas 2D noise or screen dimensions) changes the entire hash.
2. **Residential Proxy Evasion**: Mixing IP addresses into the device hash allows attackers to rotate `/24` proxy subnets to obtain a fresh ID on every request.
3. **Shared-Model False Positives**: Treating model-level hardware hashes (such as WebGL/Audio hashes shared by stock MacBook Pro M3 laptops) as unique device IDs falsely merges innocent users in offices or across cities.

**PrismID v1.2.0** addresses these challenges with a clear separation between **Per-Device Hard Identity Anchors** and **Shared-Model Environment Velocity Signals**:

1. **Per-Device Hard Identity Slices (`d_key_*`, `d_nat_*`, `d_kch_*`, `d_bcn_*`)**:
   - `d_key_*` (**Non-Extractable WebCrypto ECDSA P-256 Key Binding + Dual-Path TOFU Rebind & Key Retirement**): Reads existing `IndexedDB` `_prismid_key_v1` key material before generating a new `ECDSA P-256` keypair (`extractable: false`) and signs every challenge transcript (`prismid-v2-sig|<nonce>|<beacon_id>|<static_webgl_fp_hash>|<audio_compressor_hash>`). The Go server verifies the P-256 signature (`device_key_bound: true`, Web `confidence = 0.95` — proves possession of a bound keypair rather than hardware silicon attestation) and enforces **Trust-On-First-Use (TOFU)** binding between `d_bcn_*` and `d_key_*`. Rebinding via `Verifier.RebindDeviceKeyWithProof` / `POST /api/v1/risk/rebind-key` supports two cryptographic paths and **retires the superseded `d_key_old` edge** from `RiskGraph` on rotation:
     - **Path A — Proactive Two-Phase Key Rotation (No MFA Required, MitM-Safe)**: Prepares a candidate keypair in memory via `prepareDeviceKeyRotation`, signs the 5-segment `<new_pub_key>`-bound transcript `"prismid-v2-rebind-prev|<nonce>|<subject_id>|<beacon_id>|<new_pub_key>"` with the still-held previous private key alongside the new key's PoP, and commits the new key to `IndexedDB` **only after** `POST /api/v1/risk/rebind-key` returns HTTP 200 (`prism.rebindKey({ rotate: true })`) — preventing both MitM replacement-key substitution and local key loss on network failure.
     - **Path B — Lost-Key Recovery (Single-Use Step-Up MFA)**: Verifies co-owner `d_bcn_*` membership (`RiskGraph.SubjectOwnsBeacon`, backed by persistent `BeaconOwnerStore` / `RedisStore` / `SQLGraphStore` so server restarts or cache eviction do not deadlock recovery, and supporting shared family browsers), consumes a **single-use** `stepup_v2.<jti>.<exp>.<hmac>` token, verifies ECDSA P-256 PoP over `"prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>"`, and writes an append-only `KeyRebindAuditEvent`.
   - **Configurable Shared-Browser Policy (`HardAnchorPolicy`)**: By default (`HardAnchorPolicySharedStepUp`), 2–3 clean accounts sharing a Web browser profile (`d_bcn_*` / `d_key_*`, such as a family PC or school lab) elevate to `yellow + risk_pending: true` (`shared_hard_anchor_step_up`) for step-up verification rather than immediately turning `red`; $\ge 4$ accounts on one profile or any spoofed/Desktop-native (`d_nat_*` / `d_kch_*`) multi-account cluster escalates to `red`. Integrators can select `strict_1to1`, `step_up_all`, or `disabled` (`disabled` turns off hard-anchor cross-account merging while keeping soft-slice `BurstSuspicion` velocity step-up active).
   - `d_nat_*` & `d_kch_*` (**Sub-Millisecond Zero-Subprocess Desktop Native Hardware & OS Anchor**): Uses direct in-process `IOKit.framework` + `sysctlbyname` FFI on macOS (`~1.1ms` cold, zero subprocesses) and direct Win32 `advapi32` Registry (`KEY_WOW64_64KEY`) + `kernel32` `GetSystemFirmwareTable('RSMB')` raw SMBIOS DSP0134 parsing + `BCryptGenRandom` on Windows (zero PowerShell/WMI console flashes, with `CREATE_NO_WINDOW` hidden fallback and VBS/WSL2-safe hypervisor detection).
   - `d_bcn_*` (**Web 128-bit 5-Silo Self-Healing Beacon — Decoupled from GPU Drift**): Persisted across 5 browser storage silos (`localStorage`, `sessionStorage`, `IndexedDB`, `CacheStorage`, and `document.cookie` with `; Secure` on HTTPS) under bounded 350ms deadlines. Derived via `HMAC(Secret, "bcn|" + beacon_id)` so browser or GPU driver updates do not break longitudinal recall.
2. **Server-Side Raw Measurement Consistency & Cross-Thread Lie Checks (`prismid-js` + `prismid-go`)**:
   - **Raises the Bar Against Extensions & Unmodified-SDK Hooks**: Rather than relying solely on client boolean flags, `prismid-js` reports raw control-zone RGBA bytes (`canvas_control_rgba`, `canvas_readback_delta`), raw `copyFromChannel` digest (`audio_copy_hash`, `audio_silent_delta`, distinguishing muted all-zero audio via `audio_output_muted`), and dedicated `64x64` non-antialiased Worker `OffscreenCanvas` telemetry (`worker_*`). This catches browser extensions, anti-detect wrappers running the unmodified SDK, and naive proxy edits that flip `lies.*` booleans to `false` without synthesizing matching raw values. **Important boundary**: because all telemetry originates on the client, a modified SDK or custom out-of-browser script can synthesize coherent raw fields — see Threat Model below.
   - **Cross-Browser Verified (`Chromium V8` + `Firefox SpiderMonkey` + `WebKit Safari JSC`)**: Distinguishes privacy-hardened browsers with WebGL disabled (`webgl_disabled_by_client`, `confidence = 0.75` when key-bound) from headless `SwiftShader`/`llvmpipe` farms (`confidence = 0.30`), accounts for Firefox's sanitized WebGL `MAX_TEXTURE_SIZE = 8192` on Apple Silicon, and avoids calling `Reflect.setPrototypeOf` on frozen intrinsics.
3. **Deterministic, Persistable Orthogonal Risk Graph (`prismid-go`)**:
   - **Colleague Isolation & Anti-Wash Spoof Decay (`DefaultSpoofEdgeTTL = 24h`, `DefaultCleanObservationsToClearSpoof = 3`, `DefaultMinCleanStreakInterval = 1h`, `DefaultSoftEdgeTTL = 7d`)**: Accounts with distinct, un-spoofed hard anchors (`d_bcn_A != d_bcn_B` or `d_nat_A != d_nat_B`) are not merged into the same identity component by shared model/network soft slices (`d_gpu_*`, `d_web_*`, `d_sys_*`, `d_gpusys_*`). Clean visits increment `CleanStreak` when arriving from the same hard anchor (or same `d_web_*`/`d_gpu_*` soft slice for stateless sessions without beacons) spaced $\ge 1\text{h}$ apart, or clear immediately via audited `POST /api/v1/risk/clear-spoof` while retaining `+1.5` `HistoricalSpoof` residual log-odds.
   - **Deterministic $O(|E|\log|E|)$ Canonical Sort + Distributed `RedisStore` / `SQLGraphStore` & O(1) WAL Persistence**: Canonical sorting by `(SubjectCreatedAt, SubjectID, SliceID)` yields identical components regardless of edge arrival order. Includes zero-dependency pooled RESP2 `RedisStore` (`-redis-url` — Redis Cluster-compatible single-use `GETDEL` nonces, `SET NX EX` TOFU bindings, `DistributedReplayGuard`, and pipelined 2-hop `GraphBackend`), standard-library `database/sql` `SQLGraphStore` (`postgres` & `sqlite` dialects), and `FileStateStore` / `FileAuditStore` (`-state-file`, `-audit-log`) for single-node durability.
   - **Commercial Gateway & SaaS Controls**: Right-to-left `X-Forwarded-For` hop stripping via `-trusted-proxy-cidrs`, network-layer TLS `JA4` + Akamai `HTTP/2` fingerprint consistency checks (`VerifyTransportConsistency` against Python/Go TLS impersonators), non-blocking `-shadow-mode` rollout (`shadow_risk_status` + `risk_status: "green"`), cryptographic multi-tenant namespace isolation (`-enable-multi-tenant` / `X-PrismID-Tenant-ID`), and zero-dependency Prometheus `/metrics` exposition.
   - **3-Tier Capacity Eviction & Complete GDPR Erasure**: Prioritizes evicting isolated clean singletons first and unlinked single-account spoof floods second when `DefaultMaxGraphSubjects` (`50,000`) fills—preventing self-reported `canvas_noise_injected=true` floods from locking out legitimate signups—prunes expired soft edges on insert, and purges all subject edges, persistent beacon ownership, and `beaconToKey` TOFU bindings (including co-owned beacons) on `DELETE /api/v1/risk/subject`.

---

## Security Threat Model & Trust Boundaries / 安全边界与威胁模型说明

To integrate PrismID responsibly in production, understand what client-side telemetry can and cannot prove:

| Boundary | What PrismID Provides | What Requires Server / Gateway Enforcement |
|---|---|---|
| **Challenge, Nonce Quota & AEAD Envelope** | Single-use `nonce` (`GETDEL` semantics) blocks packet replay, explicit per-IP (`DefaultMaxChallengesPerIP = 64`) and per-`/24` (`DefaultMaxChallengesPerIPSub = 1024`) quotas return HTTP `429` (`CHALLENGE_RATE_LIMITED`) without evicting active neighbor nonces, and AES-256-GCM (`Key = SHA256("prismid-v1-aead:" + nonce)`) obfuscates wire payloads against passive inspection. | Because `nonce`, `render_seed`, and the GLSL math formula are visible to the client, a custom out-of-browser client can compute expected pixels on CPU and synthesize coherent raw fields. Do **not** treat the shader challenge or raw-measurement checks as hardware-attested silicon proof or as a substitute for TLS, WAF rate-limiting, or Turnstile (`-require-turnstile` + `-turnstile-secret`, which fails closed if secret is omitted). |
| **TOFU Beacon & Key Ownership Boundary** | `d_key_*` private keys are non-extractable in normal browsers (`extractable: false`). Proactive key rotation requires a cryptographic signature from the previous key (`previous_device_key`), and lost-key recovery requires both persistent `d_bcn_*` co-ownership and a single-use `stepup_v2` MFA token. | Raw `beacon_id` is stored in client storage silos. An attacker with XSS or local disk access who steals raw `beacon_id` before TOFU first-bind (or pairs a known `beacon_id` with compromised MFA) falls outside TOFU guarantees. Enforce strict CSP and strong phishing-resistant MFA (WebAuthn/Passkey) before minting step-up tokens. |
| **Shared Devices & Anti-Wash Spoof Decay** | Default `shared_step_up` policy elevates 2–3 clean accounts on a shared browser profile to `yellow + risk_pending` rather than immediate `red`. Spoof decay requires 3 clean sessions $\ge 1\text{h}$ apart on the same anchor (or 24h TTL / audited `clear-spoof`). | Route `yellow + risk_pending` and single-account (`len(component_subjects) == 1`) noise-only `red` verdicts to step-up verification rather than irreversible account termination, or opt into `strict_1to1` for strict one-account-per-device promos. |
| **Standalone & Clustered HTTP Server (`cmd/prismid-server`)** | Defaults to `-demo-mode=false` and loopback `-addr=127.0.0.1:8090`, enforces expiring v2 HMAC bearer tokens, supports `-redis-url` horizontal multi-replica clustering, `-trusted-proxy-cidrs` right-to-left XFF & JA4/H2 header verification, `-shadow-mode`, `-enable-multi-tenant`, Prometheus `GET /metrics`, O(1) WAL `-state-file` / `-audit-log` durability, and `-admin-secret` endpoints. | Always configure `-trusted-proxy-cidrs` when running behind Nginx/Envoy/Cloudflare so untrusted direct peers cannot spoof `X-Forwarded-For` or `X-TLS-JA4` headers, and pass `-redis-url` when running $\ge 2$ replicas behind a load balancer. |
| **Privacy & Consent Compliance** | `/api/v1/risk/should-collect` gates probe & storage access (`{ accepted: false, skipped: true, code: "COLLECTION_SKIPPED" }`), and `DELETE /api/v1/risk/subject` purges graph edges, persistent ownership, and TOFU key bindings. | In GDPR/ePrivacy jurisdictions, gate `prism.identify()` via `should-collect` or user consent where persistent storage access requires consent. |

---

## Repository Structure / 目录结构

```text
prismid/
├── README.md                        # Bilingual overview, threat model & quickstart (v1.1.0)
├── LICENSE                          # MIT License
├── Makefile                         # Unified test, lint, build & bench targets
├── docs/
│   ├── ARCHITECTURE.md              # Hard vs. soft slices, threat boundaries & 5-layer engine
│   ├── PROTOCOL_SPEC.md             # v1.1.0 byte-level wire protocol, rebind, clear-spoof & admin APIs
│   ├── ANTI_SPOOFING_MATRIX.md      # Adversarial attack vectors, defense matrix & boundaries
│   └── INTEGRATION_GUIDE.md         # Web, Tauri 2 Rust, Go, persistence & PostgreSQL guide
├── packages/
│   └── web-sdk/                     # Zero-dependency TypeScript Browser & WebView SDK (prismid-js v1.1.0)
│       ├── package.json
│       ├── README.md
│       ├── LICENSE
│       ├── scripts/bundle.mjs       # TypeScript AST-validated browser bundle builder
│       ├── src/
│       │   ├── index.ts             # createPrismClient (identify, identifyDetailed, rebindKey, clearSpoof, deleteSubject)
│       │   ├── probes/
│       │   │   ├── webgl.ts         # 11 canonical hardware register limits + 64x64 non-AA static hash + shader
│       │   │   ├── storageBeacon.ts # Bounded-timeout (350ms) 5-silo self-healing CSPRNG beacon
│       │   │   ├── workerLie.ts     # Inline Blob Web Worker + 64x64 OffscreenCanvas cross-thread probe
│       │   │   ├── audio.ts         # OfflineAudioContext compressor hash + muted-aware copyFromChannel
│       │   │   ├── fontsCanvas.ts   # Session-memoized font hash + 256-pixel spatial uniformity check
│       │   │   └── lieDetector.ts   # V8/SpiderMonkey/JSC math engine, extensible Proxy check & iframe probe
│       │   └── crypto/
│       │       ├── aead.ts          # WebCrypto AES-256-GCM sealing + strict CSPRNG fallback
│       │       └── deviceKey.ts     # Read-first ECDSA P-256 keystore, rotation proof & cache reset
│       └── test/                    # Unit, regression & real 3-browser (Chromium + Firefox + WebKit) E2E tests
├── crates/
│   └── prismid-native/              # Rust native hardware anchor crate & CLI (prismid-native v1.1.0)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs               # collect_native_anchor(), bounded cmd timeout, 0600 files & JSON escaping
│           ├── bin/main.rs          # prismid-anchor CLI binary
│           ├── macos.rs             # ioreg IOPlatformUUID + 0600 file fast-path + 120ms Keychain fallback
│           ├── windows.rs           # MachineGuid + BIOS/SMBIOS + VBS-safe Model VM check + BCryptGenRandom
│           └── linux.rs             # /etc/machine-id + product_uuid + Hypervisor check
└── server/
    └── go/                          # Go verification, persistence & orthogonal risk graph (prismid-go v1.1.0)
        ├── go.mod
        ├── engine.go                # Challenge issuer, per-/24 quota, AEAD opener, ECDSA P-256 & dual-path rebind
        ├── graph.go                 # Shared-step-up / strict hard-anchor graph, key retirement & soft eviction
        ├── persistence.go           # GraphStore, AuditStore, FileStateStore (0600) & FileAuditStore (JSONL)
        ├── shader_math.go           # GLSL-aligned (+0.5 pixel center) spot-pixel math verifier
        ├── gpu_laws.go              # GPU register laws (Firefox-sanitized-aware) & virtual GPU check
        ├── engine_test.go           # Unit & adversarial regression tests
        ├── fuzz_test.go             # Go native fuzz targets (FuzzRecordVerification & FuzzVerifyAndDerive)
        ├── internal/bench/          # 1,000-case synthetic rule-regression confusion matrix suite
        └── cmd/
            ├── prismid-server/      # Hardened HTTP server (-demo-mode=false default), single-use stepup_v2 & admin API
            └── prismid-bench/       # CLI runner for the 1,000-case synthetic rule regression report
```

---

## Quick Start / 快速开始

### 1. Run Go Verification, Race Tests & Standalone Server (`server/go`)

```bash
cd server/go
go test -race -shuffle=on ./...
go run ./cmd/prismid-bench

# Local interactive demo console (explicitly opt into -demo-mode on loopback):
go run ./cmd/prismid-server -demo-mode=true -addr 127.0.0.1:8090

# Single-instance production service with separated secrets, O(1) WAL state & JSONL audit log:
PRISMID_HMAC_SECRET="$(openssl rand -hex 32)" \
PRISMID_AUTH_SECRET="$(openssl rand -hex 32)" \
PRISMID_STEPUP_SECRET="$(openssl rand -hex 32)" \
PRISMID_ADMIN_SECRET="$(openssl rand -hex 32)" \
go run ./cmd/prismid-server \
  -demo-mode=false \
  -addr 127.0.0.1:8090 \
  -state-file ./prismid-state.json \
  -state-flush-interval 30s \
  -audit-log ./prismid-audit.jsonl
```

### 2. Install & Test Web SDK (`prismid-js`)

```bash
npm install prismid-js
```

Or from the repository:
```bash
cd packages/web-sdk
pnpm install
pnpm typecheck
pnpm build
pnpm test
```

### 3. Run Rust Native Crate & CLI (`crates/prismid-native`)

```bash
cd crates/prismid-native
cargo test --locked
cargo run --locked --bin prismid-anchor
```

---

## SDK Integration / 极简接入示例

### Browser Web Application (`prismid-js`)

```typescript
import { createPrismClient } from 'prismid-js'

const prism = createPrismClient({
  baseUrl: 'https://api.example.com',
  getAccessToken: () => sessionStorage.getItem('prismid_bearer_token'),
  requestTimeoutMs: 5000,
  probeTimeoutMs: 800,
  onError: (err) => console.warn('[PrismID]', err.code, err.message),
})

// Standard risk evaluation (or prism.identifyDetailed() for structured error reasons):
const result = await prism.identify()

// Proactive key rotation (no MFA needed) or MFA step-up recovery:
// await prism.rebindKey({ rotate: true })
// await prism.rebindKey({ stepUpToken })
```

### Desktop Application (Tauri 2 + `prismid-native` + `prismid-js`)

In Rust (`src-tauri/src/main.rs`):
```rust
#[tauri::command]
fn collect_native_hardware_anchor() -> prismid_native::NativeHardwareAnchor {
    prismid_native::collect_native_anchor().clone()
}
```

In Frontend WebView:
```typescript
import { createPrismClient } from 'prismid-js'
import { invoke } from '@tauri-apps/api/core'

const prism = createPrismClient({
  baseUrl: 'https://api.example.com',
  getAccessToken: () => session.accessToken,
  nativeAnchorProvider: () => invoke('collect_native_hardware_anchor'),
})

await prism.identify()
```

---

## Documentation / 详细技术文档

- [Architecture & Security Boundaries (`docs/ARCHITECTURE.md`)](./docs/ARCHITECTURE.md)
- [Cryptographic & Wire Protocol Specification (`docs/PROTOCOL_SPEC.md`)](./docs/PROTOCOL_SPEC.md)
- [Anti-Spoofing & Red-Blue Adversarial Matrix (`docs/ANTI_SPOOFING_MATRIX.md`)](./docs/ANTI_SPOOFING_MATRIX.md)
- [Full-Stack Integration Guide (`docs/INTEGRATION_GUIDE.md`)](./docs/INTEGRATION_GUIDE.md)

## License

Released under the [MIT License](./LICENSE).
