# PrismID (`prismid` v1.0.1)

> **Open-source orthogonal hardware signal collection, non-extractable WebCrypto ECDSA P-256 device key binding, raw-measurement server-side lie inference, and multi-slice risk correlation SDK for Web (`prismid-js`), Tauri / Rust Desktop (`prismid-native`), and Go (`prismid-go`).**
>
> **零商业调用成本、支持 Browser Web + Tauri Desktop (Rust) + Go Server 的全栈设备风控信号采集、WebCrypto 非导出私钥签名锚点、原始测量服务端测谎与正交切片关联开源引擎（MIT License）。**

---

## Why PrismID? / 为什么选择 PrismID？

Traditional open-source fingerprinting libraries hash ~20 browser attributes on the client side into a single string (`visitorId`) and send it to the backend. In adversarial scenarios, that approach suffers from three structural weaknesses:
1. **SHA-256 Avalanche Fragility**: Modifying a single attribute (such as Canvas 2D noise or screen dimensions) changes the entire hash.
2. **Residential Proxy Evasion**: Mixing IP addresses into the device hash allows attackers to rotate `/24` proxy subnets to obtain a fresh ID on every request.
3. **Shared-Model False Positives**: Treating model-level hardware hashes (such as WebGL/Audio hashes shared by all stock MacBook Pro M3 laptops) as unique device IDs falsely merges innocent users in offices or across cities.

**PrismID v1.0.1** addresses these challenges with a strict separation between **Per-Device Hard Identity Anchors** and **Shared-Model Environment Velocity Signals**:

1. **Per-Device Hard Identity Slices (`d_key_*`, `d_nat_*`, `d_kch_*`, `d_bcn_*`)**:
   - `d_key_*` (**Non-Extractable WebCrypto ECDSA P-256 Key Binding + TOFU & Ownership-Verified PoP Rebind**): Generates an `ECDSA P-256` keypair with `extractable: false` on the private key (persisted in `IndexedDB` `_prismid_key_v1` with bounded transaction timeout) and signs every challenge transcript (`prismid-v2-sig|<nonce>|<beacon_id>|<static_webgl_fp_hash>|<audio_compressor_hash>`). The Go server verifies the P-256 signature (`device_key_bound: true`, Web `confidence = 0.95` — proves possession of a bound keypair rather than hardware silicon attestation) and enforces **Trust-On-First-Use (TOFU)** binding between `d_bcn_*` and `d_key_*`. When a bound key is missing or rotated (`device_key_recovery_required`), authoritative identity is withheld (`risk_pending: true`, `confidence: 0.30`) without marking the account as an active spoof (`red`). Key recovery via `Verifier.RebindDeviceKeyWithProof` / `POST /api/v1/risk/rebind-key` enforces: (a) exclusive `d_bcn_*` ownership by the authenticated subject, (b) an independent domain-separated expiring `step_up_token`, (c) a single-use `challenge_nonce` + ECDSA P-256 proof-of-possession over `"prismid-v2-rebind|<nonce>|<subject_id>|<beacon_id>"`, and (d) structured audit logging without exposing prior key slices.
   - `d_nat_*` & `d_kch_*` (**Desktop Native Hardware & OS Keychain/Registry Anchor**): Combines motherboard UUID (`IOPlatformUUID` / `MachineGuid` + `Win32_BIOS.SerialNumber` + `SMBIOS UUID`) with an OS-persisted anchor (macOS Keychain / Windows `HKCU\Software\PrismID` Registry / user config vault).
   - `d_bcn_*` (**Web 128-bit 5-Silo Self-Healing Beacon — Decoupled from GPU Drift**): Persisted across 5 browser storage silos (`localStorage`, `sessionStorage`, `IndexedDB`, `CacheStorage`, and `document.cookie`) with bounded 350ms timeouts. Derived purely via `HMAC(Secret, "bcn|" + beacon_id)` so browser or GPU driver updates never break longitudinal user recall.
2. **Server-Side Raw Measurement Consistency & Cross-Thread Lie Detection (`prismid-js` + `prismid-go`)**:
   - **Raw Control-Pixel & Audio Channel Consistency Checks (Browser Extensions & Unmodified SDK Hooks)**: Rather than relying solely on client-computed boolean flags, `prismid-js` reports raw control-zone RGBA bytes (`canvas_control_rgba`, `canvas_readback_delta`), raw `copyFromChannel` digest (`audio_copy_hash`, `audio_silent_delta`), and raw Worker telemetry (`worker_*`). This catches in-browser noise extensions, anti-detect browser hooks running the unmodified SDK, and naive proxy/script edits that flip `lies.*` booleans to `false` without synthesizing matching raw values (while a fully custom out-of-browser client can synthesize raw fields — see Threat Model table below). Safari < 17 or GPU-blocklisted Workers where `OffscreenCanvas` WebGL is unavailable record non-penalizing `worker_webgl_unavailable` in `privacy_signals` without false `red` verdicts.
   - **Inline Blob Worker + `OffscreenCanvas` & ECMAScript `§10.1.2.1` Proxy Trap**: Compares `WorkerNavigator` and Worker `OffscreenCanvas` WebGL against the main thread and detects `new Proxy(...)` wrappers and `Object.defineProperty` overrides.
3. **Deterministic, Identity-Safe Orthogonal Risk Graph (`prismid-go`)**:
   - **Zero Colleague False Merges, Spoof-Isolation & Anti-Wash Spoof Decay (`DefaultSpoofEdgeTTL = 24h`, `DefaultCleanObservationsToClearSpoof = 3`, `DefaultMinCleanStreakInterval = 1h`, `DefaultSoftEdgeTTL = 7d`)**: Accounts possessing distinct, un-spoofed hard beacons (`d_bcn_A != d_bcn_B`) or distinct native anchors (`d_nat_A != d_nat_B`) are **never** merged into the same identity component by shared model/network soft slices (`d_gpu_*`, `d_web_*`, `d_sys_*`, `d_gpusys_*`), and are **never** marked `red` by soft slices alone. A spoofed observation never contaminates unrelated clean users of the same laptop model. Single-account tampering signals (`red` / `active_tampering_detected`) represent an **active/cooldown risk window** rather than an irrevocable ban, and are hardened against scripted/cross-device washing: `CleanStreak` increments **only** when a clean observation arrives from the **same strongest hard anchor** (`d_key_*`, `d_nat_*`, or `d_bcn_*`) spaced at least **1 hour** apart (or immediately after MFA via `POST /api/v1/risk/clear-spoof`), transitioning `red` $\to$ `yellow + pending` (`historical_tampering_cooldown`) $\to$ `green` (`historical_tampering_decayed`) while retaining permanent `+1.5` `HistoricalSpoof` residual log-odds (`LogOddsScore = -0.5` rather than `-2.0`). Soft-slice edges track `ObservedAt` and are pruned after 7 days.
   - **Soft-Slice Velocity Step-Up (`BurstSuspicion`)**: When $\ge 3$ distinct clean-beacon accounts share `d_gpusys_*` (within 6h) or `d_web_*` (within 25m), `RiskGraph` sets `BurstSuspicion = true`, `RiskPending = true`, and elevates `green` $\to$ `yellow` for step-up verification without falsely merging colleagues into a `red` component.
   - **100% Permutation-Invariant $O(N)$ Union-Find & Multi-Hop Hard-Slice Traversal**: Canonical sorting by `(SubjectCreatedAt, SubjectID, SliceID)` guarantees identical results across all edge permutations, and full multi-hop traversal across hard identity slices (up to `MaxComponentSize = 512`) prevents 3-hop chain truncation. Loss markers (`incompleteSlices`) are scoped to per-device hard slices so popular laptop models exceeding `MaxSubjectsPerSlice = 256` never poison unrelated users.
   - **Explainability, Ownership-Verified Key Rebinding & Complete GDPR Erasure**: Built-in `LogOddsScore`, timestamped `EvidenceChain` (`GET /api/v1/risk/explain`), audited ownership + step-up + ECDSA P-256 PoP key rebinding (`POST /api/v1/risk/rebind-key`), MFA spoof-cooldown clearance (`POST /api/v1/risk/clear-spoof`), and complete GDPR/CCPA erasure (`DELETE /api/v1/risk/subject`, purging both graph edges and `beaconToKey` TOFU bindings).

---

## Security Threat Model & Trust Boundaries / 安全边界与威胁模型说明

To integrate PrismID responsibly in production, understand what client-side telemetry can and cannot prove:

| Boundary | What PrismID Guarantees | What Requires Server / Gateway Enforcement |
|---|---|---|
| **Challenge & AEAD Envelope** | Single-use `nonce` (`GETDEL` semantics) blocks packet replay (`100%`). AES-256-GCM (`Key = SHA256("prismid-v1-aead:" + nonce)`) obfuscates wire payloads against passive inspection and naive scripts. | Because `nonce`, `render_seed`, and the GLSL math formula are visible to the client, an out-of-browser script can compute expected pixels on the CPU and seal custom JSON. Do **not** treat the shader challenge as hardware-attested silicon proof or as a replacement for TLS, WAF rate-limiting, or CAPTCHA/Turnstile. |
| **Privacy Browsers & Anti-Wash Spoof Decay** | Raw pixel/audio noise injection is detected (`canvas_noise_injected` / `audio_noise_injected`), isolating the session without poisoning same-model clean users; disabling Shields recovers `red` $\to$ `yellow` $\to$ `green` across 3 clean sessions on the **same hard anchor** spaced $\ge 1\text{h}$ apart (or after 24h TTL / MFA step-up), while retaining `+1.5` `HistoricalSpoof` residual log-odds. | Because single-account `red` reflects a 24h/3-session risk window (and multi-account hard-anchor links stay permanently `red`), route **single-account** (`len(component_subjects) == 1`) noise-only `red` verdicts to step-up verification (e.g. CAPTCHA / Passkey / OTP) and persist application-level enforcement decisions on your backend if permanent bans are required. |
| **Confidence Scores (`0.99 / 0.95 / 0.85 / 0.30`)** | Deterministic **rule-tier weights**: `0.99` (Native anchor), `0.95` (Clean Web), `0.85` (Spoof trap hit), `0.30` (Virtual/Software GPU like `SwiftShader`, below the `0.60` authoritative threshold). | These constants are rule-tier weights for graph filtering, **not** statistically calibrated probabilities of hardware authenticity. |
| **Standalone HTTP Server (`cmd/prismid-server`)** | Interactive local lab & reference service with per-IP token-bucket rate limiting (`-rate-limit`). When `-demo-mode=false`, strictly enforces expiring v2 HMAC-SHA256 tokens `Bearer <subject_id>.<exp_unix>.<hmac_hex>` (`SignSubjectBearerToken`, 24h TTL; legacy non-expiring tokens disabled by default via `-allow-legacy-tokens=false`). Exposes `GET /api/v1/risk/explain`, hardened `POST /api/v1/risk/rebind-key`, `POST /api/v1/risk/clear-spoof`, and `DELETE /api/v1/risk/subject`. | In production, embed `prismid.Verifier` behind your authenticated API gateway and back `ChallengeStore` / graph storage with Redis & PostgreSQL. |
| **Privacy & Consent Compliance** | Provides `/api/v1/risk/should-collect` gate before any probe or storage access runs, and `DELETE /api/v1/risk/subject` (`RiskGraph.RemoveSubject`) for right-to-erasure requests. | The 5-silo self-healing beacon writes persistent identifiers across browser storage APIs. In GDPR/ePrivacy jurisdictions, gate `prism.identify()` via `should-collect` or user consent for fraud-prevention/security purposes. |

---

## Repository Structure / 目录结构

```text
prismid/
├── README.md                        # Bilingual overview, threat model & quickstart
├── LICENSE                          # MIT License
├── docs/
│   ├── ARCHITECTURE.md              # Hard vs. soft slices, threat boundaries & 5-layer engine
│   ├── PROTOCOL_SPEC.md             # Challenge-Identify AEAD wire protocol & byte-level specification
│   ├── ANTI_SPOOFING_MATRIX.md      # Adversarial attack vectors, defense matrix & boundaries
│   └── INTEGRATION_GUIDE.md         # Web, Tauri 2 Rust, Go & PostgreSQL integration guide
├── packages/
│   └── web-sdk/                     # Zero-dependency TypeScript Browser & WebView SDK (prismid-js v1.0.1)
│       ├── package.json
│       ├── src/
│       │   ├── index.ts             # createPrismClient with full header+body deadline & strict schema check
│       │   ├── probes/
│       │   │   ├── webgl.ts         # 11 canonical hardware register limits + static 3D hash + dynamic shader
│       │   │   ├── storageBeacon.ts # Bounded-timeout (350ms) 5-silo self-healing storage beacon
│       │   │   ├── workerLie.ts     # Inline Blob Web Worker + OffscreenCanvas cross-thread lie detector
│       │   │   ├── audio.ts         # OfflineAudioContext compressor hash + raw copyFromChannel telemetry
│       │   │   ├── fontsCanvas.ts   # TextMetrics sub-pixel float boxes + raw control-pixel RGBA telemetry
│       │   │   └── lieDetector.ts   # Cyclic __proto__ Proxy detection + descriptor & iframe checks
│       │   └── crypto/
│       │       ├── aead.ts          # WebCrypto AES-256-GCM sealing + pure TypeScript fallback
│       │       └── deviceKey.ts     # Non-extractable WebCrypto ECDSA P-256 keypair + challenge signing
│       └── test/                    # Unit, regression & real Chrome E2E integration tests
├── crates/
│   └── prismid-native/              # Rust native hardware anchor crate (prismid-native v1.0.1)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs               # collect_native_anchor() + OnceLock cache + unit tests
│           ├── macos.rs             # ioreg IOPlatformUUID + Serial + macOS Keychain + hv_vmm_present
│           ├── windows.rs           # MachineGuid + BIOS Serial + SMBIOS UUID + HKCU Registry anchor
│           └── linux.rs             # /etc/machine-id + product_uuid + Hypervisor check
└── server/
    └── go/                          # Go verification & orthogonal slice risk graph engine (prismid-go v1.0.1)
        ├── go.mod
        ├── engine.go                # Challenge issuer, AEAD opener, ECDSA P-256 verifier & raw inference
        ├── graph.go                 # Deterministic O(N) Union-Find risk graph + EvidenceChain + RemoveSubject
        ├── shader_math.go           # GLSL-aligned (+0.5 pixel center) spot-pixel math verifier
        ├── gpu_laws.go              # GPU architecture register laws & SwiftShader/VMware virtual GPU check
        ├── engine_test.go           # Unit & audit regression tests (DeepSeek + GPT R1-R5 vectors)
        ├── internal/bench/          # 1,000-case synthetic rule-regression confusion matrix suite
        └── cmd/
            ├── prismid-server/      # Standalone HTTP server, /explain, DELETE /subject & demo console
            └── prismid-bench/       # CLI runner for the 1,000-case synthetic rule regression report
```

---

## Quick Start / 快速开始

### 1. Run Go Verification & Audit Regression Tests (`server/go`)

```bash
cd server/go
go test -v -race ./...
go run ./cmd/prismid-bench
go run ./cmd/prismid-server -addr :8090
```

### 2. Install & Test Web SDK (`prismid-js`)

```bash
npm install prismid-js
```

Or from the repository:
```bash
cd packages/web-sdk
npm install
npm test
npm run build
```

### 3. Run Rust Native Crate Tests (`crates/prismid-native`)

```bash
cd crates/prismid-native
cargo test
```

---

## 3-Line SDK Integration / 三行代码极简接入

### Browser Web Application (`prismid-js`)

```typescript
import { createPrismClient } from 'prismid-js'

const prism = createPrismClient({
  baseUrl: 'https://api.example.com',
  getAccessToken: () => localStorage.getItem('access_token'),
  requestTimeoutMs: 5000,
})

const result = await prism.identify()
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
