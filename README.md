# PrismID (`prismid`)

> **Zero-cost orthogonal hardware fingerprinting, WebGL shader challenge-response, and cross-thread lie detection SDK for Web (`prismid-js`), Tauri / Rust Desktop (`prismid-native`), and Go (`prismid-go`).**
>
> **零商业调用成本、支持 Browser Web + Tauri Desktop (Rust) + Go Server 的全栈抗篡改设备指纹与跨线程测谎开源引擎（MIT License）。**

---

## Why PrismID? / 为什么选择 PrismID？

Traditional open-source fingerprinting libraries hash 20+ browser attributes on the client side into a single string (`visitorId`) and send it to the backend. Attackers can trivially defeat this by:
1. Modifying a single JSON field in DevTools or a Python script to trigger the **SHA-256 avalanche effect**, generating infinite fake device IDs.
2. Routing traffic through low-cost **rotating residential proxies**, changing `/24` IP subnets on every request.
3. Using browser extensions or anti-detect browsers to hook `window.navigator` and `HTMLCanvasElement` on the main thread.

**PrismID** solves these problems using an optical prism architecture—refracting an untrusted client report into **3 orthogonal hardware spectral slices** backed by cryptographic proof-of-render:

1. **Challenge-Response Dynamic Shader Proof & AEAD Sealing**:
   - The client never computes its own device ID. It requests a 60-second single-use `nonce` and a 4-float `render_seed` (`[s0, s1, s2, s3]`), renders a deterministic mathematical fragment shader on the physical GPU, samples 8 coordinate pixels, and seals the entire payload with **AES-256-GCM (AEAD)** (`Key = SHA256("prismid-v1-aead:" + nonce)`, `AAD = ASCII(nonce)`).
2. **Cross-Thread Lie Detection (`Web Worker + OffscreenCanvas`)**:
   - Spawns an inline `Blob` Web Worker to independently query `WorkerNavigator` and render on an `OffscreenCanvas` WebGL context, bypassing main-thread DOM hooks, supplemented by **FDLIBM `Math` floating-point constants**, **`Function.prototype.toString.call` prototype chain integrity checks**, and **sub-pixel `TextMetrics` bounding boxes**.
3. **Orthogonal Spectral Slices (`d_nat_*/d_web_*`, `d_gpu_*`, `d_sys_*`) + Hardware Split Honeypot**:
   - `d_nat_*` / `d_web_*` (**Exact Device Slice**): Native motherboard UUID + Serial + OS Keychain anchor on desktop, or full browser profile vector on Web.
   - `d_gpu_*` (**Pure Physical GPU & Acoustic Slice — 100% Decoupled from IP & Renderer Text**): Derived exclusively from `StaticWebGLFpHash + WebGLLimitsVector + AudioCompressorHash`. Even if an attacker rotates across 1,000 residential proxy IPs, injects random Canvas 2D noise, or spoofs `UNMASKED_RENDERER_WEBGL` strings, `d_gpu_*` remains rock-solid on the same physical machine.
   - `d_sys_*` (**Cross-Context System & Subnet Slice**): Derived from `OS Platform + CPU Cores + Timezone + /24 IP Subnet` (deliberately excluding `deviceMemory` and `screen.width/height` for 100% consistency across Chrome Blink, macOS Safari `WKWebView`, and multi-monitor setups).

---

## Repository Structure / 目录结构

```text
prismid/
├── README.md                        # Bilingual overview & 3-line quickstart
├── LICENSE                          # MIT License
├── docs/
│   ├── ARCHITECTURE.md              # Orthogonal slices, shader challenge & cross-thread lie detection
│   ├── PROTOCOL_SPEC.md             # Challenge-Identify AEAD wire protocol & byte-level specification
│   └── ANTI_SPOOFING_MATRIX.md      # 8 adversarial attack vectors & defense matrix
├── packages/
│   └── web-sdk/                     # Zero-dependency TypeScript Browser & WebView SDK (prismid-js)
│       ├── package.json
│       ├── tsconfig.json
│       ├── src/
│       │   ├── index.ts             # createPrismClient({ baseUrl, getAccessToken, nativeAnchorProvider })
│       │   ├── probes/
│       │   │   ├── webgl.ts         # 12 hardware register limits + static 3D hash + dynamic render_seed spot pixels
│       │   │   ├── workerLie.ts     # Inline Blob Web Worker + OffscreenCanvas cross-thread lie detector
│       │   │   ├── audio.ts         # OfflineAudioContext Oscillator + DynamicsCompressor integral fingerprint
│       │   │   ├── fontsCanvas.ts   # TextMetrics sub-pixel float bounding boxes + Canvas 2D composite
│       │   │   └── lieDetector.ts   # Math FDLIBM constants + Function.prototype.toString.call + WebDriver/CDP
│       │   └── crypto/
│       │       └── aead.ts          # WebCrypto AES-256-GCM sealing + pure TypeScript non-HTTPS fallback
│       └── test/                    # Automated unit & cross-language integration tests
├── crates/
│   └── prismid-native/              # Rust native hardware anchor crate (for Tauri 2 / desktop apps)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs               # collect_native_anchor() + OnceLock in-memory cache
│           ├── macos.rs             # ioreg IOPlatformUUID + Serial + Keychain anchor + hv_vmm_present
│           ├── windows.rs           # MachineGuid + SMBIOS UUID + Credential Manager + Hypervisor check
│           └── linux.rs             # /etc/machine-id + product_uuid + Hypervisor check
└── server/
    └── go/                          # Standalone Go verification & orthogonal slice engine (prismid-go)
        ├── go.mod
        ├── engine.go                # Challenge issuer, AEAD opener, 5-layer anti-forgery & HMAC slice derivation
        ├── shader_math.go           # GLSL-aligned (+0.5 pixel center) spot-pixel math verifier
        ├── gpu_laws.go              # GPU architecture register laws & SwiftShader/VMware virtual GPU trap
        ├── engine_test.go           # Full unit tests covering all 8 adversarial attack vectors
        └── cmd/
            └── prismid-server/      # Standalone runnable HTTP server & interactive demo playground
                └── main.go
```

---

## Standalone Quick Start / 独立运行快速开始

PrismID is 100% self-contained and can run independently as a standalone verification server or be embedded as a library.

### 1. Run Standalone Go Server & Playground (`server/go`)

```bash
cd server/go
go test -v ./...
go run ./cmd/prismid-server -addr :8090
```

Once started, visit `http://localhost:8090` to open the built-in interactive inspection console, or call the HTTP endpoints directly:
- `GET  /api/v1/risk/should-collect`
- `POST /api/v1/risk/challenge`
- `POST /api/v1/risk/identify`

### 2. Run Web SDK Tests (`packages/web-sdk`)

```bash
cd packages/web-sdk
pnpm install
pnpm test
pnpm build
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

### Go Backend Engine (`prismid-go`)

```go
package main

import (
    "context"
    prismid "github.com/yrZhaoweb/prismid/server/go"
)

func main() {
    verifier := prismid.NewVerifier(prismid.Config{
        HMACSecret:   []byte("your-32-byte-hmac-secret-key-here"),
        ChallengeTTL: 60 * time.Second,
    }, prismid.NewMemoryChallengeStore())

    challenge, _ := verifier.IssueChallenge(context.Background(), "203.0.113.42")
    // Send challenge to client, then verify client's sealed response:
    result, err := verifier.VerifyAndDerive(context.Background(), identifyReq, "203.0.113.42")
}
```

---

## Documentation / 详细技术文档

- [Architecture Design (`docs/ARCHITECTURE.md`)](./docs/ARCHITECTURE.md)
- [Cryptographic & Wire Protocol Specification (`docs/PROTOCOL_SPEC.md`)](./docs/PROTOCOL_SPEC.md)
- [Anti-Spoofing & Red-Blue Adversarial Matrix (`docs/ANTI_SPOOFING_MATRIX.md`)](./docs/ANTI_SPOOFING_MATRIX.md)

## License

Released under the [MIT License](./LICENSE).
