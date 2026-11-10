# PrismID Anti-Spoofing & Adversarial Matrix (`ANTI_SPOOFING_MATRIX.md`)

This document catalogs the 8 primary adversarial vectors and privacy-preservation invariants verified in `prismid-go` (`engine_test.go` and `internal/bench/benchmark_accuracy.go`).

---

## 1. Red-Blue Adversarial Defense Matrix

| # | Vector | Scenario / Attacker Technique | PrismID Mechanism | Verification Outcome |
|---|---|---|---|---|
| **1** | **Genuine First-Time Device** | Standard browser or desktop client running on physical hardware. | Passes single-use `nonce`, AEAD decryption, GLSL spot-pixel math (`absDiff <= 2`), GPU register laws, and cross-thread Worker consistency. | `Accepted = true`, rule-tier weight `Confidence = 0.95` (Web) or `0.99` (Native), hard (`d_bcn_*`/`d_nat_*`/`d_kch_*`) and soft (`d_gpu_*`, `d_sys_*`) slices derived. |
| **2** | **Challenge Nonce Replay Attack** | Captures a valid `{ c: nonce, p: sealed_blob }` packet via proxy/F12 and replays it for a second account. | `ChallengeStore.ConsumeChallenge(nonce)` atomically deletes the nonce on first read (`GETDEL` semantics). | `Accepted = false`, `ErrorCode = CHALLENGE_NONCE_INVALID_OR_REPLAYED`. |
| **3** | **Random / Stale Pixel Script** | Submits random or stale `spot_pixels` that do not match the live 60-second `render_seed` `[s0,s1,s2,s3]`. | Server computes exact GLSL fragment shader values at the 8 challenge coordinates `(x+0.5)/256.0`. | `Accepted = false`, `ErrorCode = SHADER_SPOT_PIXEL_MISMATCH` (`SHADER_SPOT_PIXEL_MATH_MISMATCH`). |
| **4** | **Silent Anti-Detect Browser + Rotating Residential Proxy Pool** | Uses an anti-detect browser that injects Canvas 2D / Audio noise, sets all `lies.*` booleans to `false`, and rotates `/24` residential proxy IPs per account. | Server independently inspects raw `canvas_control_rgba`, `canvas_readback_delta`, `audio_copy_hash`, and `audio_silent_delta` (`SpoofTrapTriggered = true`), promoting the IP-free `d_gpu_*` slice in `RiskGraph`. | `d_web_*` and `d_sys_*` change, but `SpoofTrapTriggered = true` promotes `d_gpu_*`, linking the accounts and marking them `red`. |
| **5** | **Main-Thread Hook / ES6 Proxy Extension** | Injects JS on the main thread to override `navigator.*`, `Intl.DateTimeFormat`, or wrap `WebGLRenderingContext.prototype.getParameter` in a `new Proxy(...)`. | `workerLie.ts` compares main thread vs. inline `Blob` Web Worker + `OffscreenCanvas`; `lieDetector.ts` detects `Proxy` via ECMAScript `§10.1.2.1` cyclic `__proto__` check. | Flags `worker_lie_detected` / `prototype_lies`, substitutes Worker's unhooked GPU hash into `d_gpu_*`, and marks `SpoofTrapTriggered = true`. |
| **6** | **Impossible OS / GPU Register Combination** | Script spoofs `gpu_renderer` to `"Apple M3 Max"` while reporting `platform = "Win32"` or non-`[1,1]` `ALIASED_LINE_WIDTH_RANGE`. | `gpu_laws.go` checks hardware register invariants and V8/JSC/SpiderMonkey `Math` FDLIBM engine alignment. | Flags `gpu_register_law_violation` (`SpoofTrapTriggered = true`, or rejects when `RejectOnGPULawViolation = true`). |
| **7** | **Kernel/API Hook Spoofing Native Motherboard UUID** | Hooks `ioreg` / `wmic` on a desktop installation to return a fake `HWUUID` while the OS Keychain/Registry anchor (`d_kch_*`) or WebView beacon (`d_bcn_*`) persists. | **Per-Anchor UUID Split Trap (`native_uuid_split_trap`)**: Scoped to `d_kch_*` and `d_bcn_*` (never raw `d_gpu_*`, so two separate physical MacBooks of the same model never false-positive). | Triggers `native_uuid_split_trap` (`SpoofTrapTriggered = true`) and links both accounts via `d_kch_*` / `d_gpu_*`. |
| **8** | **Cloud Headless Browser (`SwiftShader` / `llvmpipe`) & VMware Clones** | Runs Puppeteer/Playwright inside Docker containers with software rendering (`Google SwiftShader`, `llvmpipe`) or VMware/VirtualBox/QEMU VMs. | `gpu_laws.go` + `prismid-native` hypervisor detector checks virtual GPU keywords and CPU hypervisor flags. | Sets `IsVirtualGPU = true` and assigns rule-tier weight `Confidence = 0.30` (`< 0.60`), keeping `RiskPending = true` (`RiskStatusUnknown`). |

---

## 2. False-Positive Prevention Invariants (Verified by Audit Regression Suite)

1. **Same-Model Colleagues & Cross-City Users (`F2`)**:
   - Two accounts with distinct, un-spoofed native anchors (`d_nat_*`) or distinct, un-spoofed Web beacons (`d_bcn_*`) are **never** merged pairwise by model-level `d_gpu_*` or subnet-level `d_gpusys_*` (whether 5 minutes or 48 hours apart).
2. **Single-User Cookie Clearing & Safari ITP (`F3`)**:
   - When `storageBeacon.ts` recovers a `beacon_id` after partial storage clearing (`storage_healed = true`), `prismid-go` records `"storage_healed"` in `PrivacySignals` without setting `SpoofTrapTriggered = true`. A single user clearing Cookies remains `green`; only a 2nd account sharing the resurrected `d_bcn_*` turns `red`.
3. **Browser & Driver Upgrades (`F7`)**:
   - `d_bcn_*` is derived purely from `HMAC(Secret, "bcn|" + beacon_id)` and `d_gpu_*` strips the volatile 12th WebGL extension hash segment, ensuring browser updates never break `d_bcn_*` continuity.
4. **Mobile CGNAT & Large Office `/24` Subnets (`DeepSeek #5A`)**:
   - `/24` subnet GPU diversity (`SubnetCrowdTriggered` / `d_ip24_crowd_*`) is emitted strictly as telemetry and excluded from `SliceNodes()`, ensuring 40+ unrelated users sharing a mobile CGNAT `/24` stay `green`.
