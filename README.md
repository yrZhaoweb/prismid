# PrismID (`prismid` v0.4.0)

> **Open-source orthogonal hardware signal collection, in-browser anti-tamper & cross-thread lie detection, and multi-slice risk correlation SDK for Web (`prismid-js`), Tauri / Rust Desktop (`prismid-native`), and Go (`prismid-go`).**
>
> **零商业调用成本、支持 Browser Web + Tauri Desktop (Rust) + Go Server 的全栈设备风控信号采集、浏览器内反篡改测谎与正交切片关联开源引擎（MIT License）。**

---

## Why PrismID? / 为什么选择 PrismID？

Traditional open-source fingerprinting libraries hash ~20 browser attributes on the client side into a single string (`visitorId`) and send it to the backend. In adversarial scenarios, that approach suffers from three structural weaknesses:
1. **SHA-256 Avalanche Fragility**: Modifying a single attribute (such as Canvas 2D noise or screen dimensions) changes the entire hash.
2. **Residential Proxy Evasion**: Mixing IP addresses into the device hash allows attackers to rotate `/24` proxy subnets to obtain a fresh ID on every request.
3. **Shared-Model False Positives**: Treating model-level hardware hashes (such as WebGL/Audio hashes shared by all stock MacBook Pro M3 laptops) as unique device IDs falsely merges innocent users in offices or across cities.

**PrismID v0.4.0** addresses these challenges with a clear separation between **Per-Device Identity Anchors** and **Shared-Model Environment Signals**:

1. **Per-Device Hard Identity Slices (`d_nat_*`, `d_kch_*`, `d_bcn_*`)**:
   - `d_nat_*` & `d_kch_*` (**Desktop Native Hardware & OS Keychain/Registry Anchor**): Combines motherboard UUID (`IOPlatformUUID` / `MachineGuid` + `Win32_BIOS.SerialNumber` + `SMBIOS UUID`) with an OS-persisted anchor (macOS Keychain / Windows `HKCU\Software\PrismID` Registry / user config vault).
   - `d_bcn_*` (**Web 128-bit 5-Silo Self-Healing Beacon — Decoupled from GPU Drift**): Persisted across `localStorage`, `IndexedDB`, `CacheStorage`, `OPFS`, `Cookie`, `sessionStorage`, and `window.name` with bounded 350ms timeouts. Derived purely via `HMAC(Secret, "bcn|" + beacon_id)` so browser or GPU driver updates never break longitudinal user recall.
2. **In-Browser Anti-Tamper & Cross-Thread Lie Detection (`prismid-js`)**:
   - **Inline Blob Worker + `OffscreenCanvas`**: Compares `WorkerNavigator` and Worker `OffscreenCanvas` WebGL against the main thread to catch extensions that only hook `window`.
   - **ECMAScript `§10.1.2.1` Cyclic `__proto__` Proxy Trap & Descriptor Checks**: Detects `new Proxy(...)` wrappers and `Object.defineProperty` overrides even when `Function.prototype.toString` is spoofed to return `[native code]`.
   - **In-Scene Canvas & Audio Exactness Traps**: Detects deterministic/random Canvas 2D `getImageData`/`toDataURL` noise (via transparent background + solid patch invariants) and `AudioBuffer.prototype.getChannelData` vs `copyFromChannel` tampering.
3. **Identity-Safe Orthogonal Risk Graph (`prismid-go`)**:
   - **Zero Model-Collision False Merges**: Two accounts with distinct, un-spoofed native anchors (`d_nat_*`) or distinct, un-spoofed Web beacons (`d_bcn_*`) are **never** merged pairwise by model-level `d_gpu_*` or subnet-level `d_gpusys_*` / `d_ip24_crowd_*`.
   - **Privacy-Friendly Storage Healing**: Single-user Cookie clearing or Safari ITP (`storage_healed`) is recorded in `privacy_signals` for telemetry and **never** marks a single user `red`; only when a resurrected `d_bcn_*` links multiple accounts does the graph flag abuse.
   - **Conditional Soft-Slice Promotion**: Model-level `d_gpu_*` (canonicalized across 11 hardware registers, stripping volatile extension lists) and `d_gpusys_*` promote to active graph links only when an active spoofing/lie/noise trap is triggered (`spoof_trap_triggered = true`), when beacons are stripped, or when an Incognito farming batch ($\ge 3$ accounts) arrives within the velocity window.

---

## Security Threat Model & Trust Boundaries / 安全边界与威胁模型说明

To integrate PrismID responsibly in production, understand what client-side telemetry can and cannot prove:

| Boundary | What PrismID Guarantees | What Requires Server / Gateway Enforcement |
|---|---|---|
| **Challenge & AEAD Envelope** | Single-use `nonce` (`GETDEL` semantics) blocks packet replay (`100%`). AES-256-GCM (`Key = SHA256("prismid-v1-aead:" + nonce)`) obfuscates wire payloads against passive inspection and naive scripts. | Because `nonce`, `render_seed`, and the GLSL math formula are visible to the client, an out-of-browser script can compute expected pixels on the CPU and seal custom JSON. Do **not** treat the shader challenge as hardware-attested silicon proof or as a replacement for TLS, WAF rate-limiting, or CAPTCHA/Turnstile. |
| **Confidence Scores (`0.99 / 0.95 / 0.85 / 0.30`)** | Deterministic **rule-tier weights**: `0.99` (Native anchor), `0.95` (Clean Web), `0.85` (Spoof trap hit), `0.30` (Virtual/Software GPU like `SwiftShader`, below the `0.60` authoritative threshold). | These constants are rule-tier weights for graph filtering, **not** statistically calibrated probabilities of hardware authenticity. |
| **Standalone HTTP Server (`cmd/prismid-server`)** | Interactive local lab & reference service. Supports `-demo-mode=false`, `-trust-proxy`, `-cors-origin`, 64 KiB body limits, and HTTP timeouts. | In production, embed `prismid.Verifier` behind your authenticated API gateway (extracting `subject_id` from verified JWT/sessions) and back `ChallengeStore` / graph storage with Redis & PostgreSQL. |
| **Privacy & Consent Compliance** | Provides `/api/v1/risk/should-collect` gate before any probe or storage access runs. | The 5-silo self-healing beacon writes persistent identifiers across browser storage APIs. In GDPR/ePrivacy jurisdictions, gate `prism.identify()` via `should-collect` or user consent for fraud-prevention/security purposes. |

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
│   └── web-sdk/                     # Zero-dependency TypeScript Browser & WebView SDK (prismid-js v0.4.0)
│       ├── package.json
│       ├── src/
│       │   ├── index.ts             # createPrismClient with AbortController deadlines & strict schema check
│       │   ├── probes/
│       │   │   ├── webgl.ts         # 11 canonical hardware register limits + static 3D hash + dynamic shader
│       │   │   ├── storageBeacon.ts # Bounded-timeout (350ms) 5-silo self-healing storage beacon
│       │   │   ├── workerLie.ts     # Inline Blob Web Worker + OffscreenCanvas cross-thread lie detector
│       │   │   ├── audio.ts         # OfflineAudioContext compressor hash + copyFromChannel trap
│       │   │   ├── fontsCanvas.ts   # TextMetrics sub-pixel float boxes + in-scene Canvas noise traps
│       │   │   └── lieDetector.ts   # Cyclic __proto__ Proxy detection + descriptor & iframe checks
│       │   └── crypto/
│       │       └── aead.ts          # WebCrypto AES-256-GCM sealing + pure TypeScript fallback
│       └── test/                    # Unit, regression & real Chrome E2E integration tests
├── crates/
│   └── prismid-native/              # Rust native hardware anchor crate (prismid-native v0.4.0)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs               # collect_native_anchor() + OnceLock cache + unit tests
│           ├── macos.rs             # ioreg IOPlatformUUID + Serial + macOS Keychain + hv_vmm_present
│           ├── windows.rs           # MachineGuid + BIOS Serial + SMBIOS UUID + HKCU Registry anchor
│           └── linux.rs             # /etc/machine-id + product_uuid + Hypervisor check
└── server/
    └── go/                          # Go verification & orthogonal slice risk graph engine (prismid-go v0.4.0)
        ├── go.mod
        ├── engine.go                # Challenge issuer, AEAD opener, 5-layer verifier & slice derivation
        ├── graph.go                 # Deduplicated, bounded-BFS connected-component risk graph
        ├── shader_math.go           # GLSL-aligned (+0.5 pixel center) spot-pixel math verifier
        ├── gpu_laws.go              # GPU architecture register laws & SwiftShader/VMware virtual GPU check
        ├── engine_test.go           # Unit & audit regression tests (DeepSeek + GPT reproduction vectors)
        ├── internal/bench/          # 1,000-case synthetic rule-regression confusion matrix suite
        └── cmd/
            ├── prismid-server/      # Standalone HTTP server & interactive demo console
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
