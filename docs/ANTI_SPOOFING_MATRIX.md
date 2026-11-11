# PrismID Anti-Spoofing & Adversarial Matrix (`ANTI_SPOOFING_MATRIX.md` — `v1.1.0`)

This document catalogs the adversarial vectors, explicit client-telemetry limits, and false-positive prevention invariants verified in `prismid-go` (`engine_test.go`, `v110_deepseek_review_test.go`, `fuzz_test.go`, and `internal/bench/benchmark_accuracy.go`) and `prismid-js` (`test/prismid.test.ts` across Chromium, Firefox, and WebKit).

---

## 1. Red-Blue Adversarial Defense Matrix

| # | Vector | Scenario / Attacker Technique | PrismID Mechanism | Verification Outcome |
|---|---|---|---|---|
| **1** | **Genuine First-Time Device** | Standard Chrome, Firefox, Safari, or Tauri desktop client running on physical hardware. | Passes single-use `nonce`, AEAD decryption, GLSL spot-pixel math (`absDiff <= 2`), cross-browser GPU register laws, read-first ECDSA P-256 TOFU key binding, and `64x64` non-AA Worker consistency. | `Accepted = true`, rule-tier weight `Confidence = 0.95` (Web) or `0.99` (Native), hard (`d_key_*`/`d_bcn_*`/`d_nat_*`/`d_kch_*`) and soft (`d_gpu_*`, `d_sys_*`) slices derived. |
| **2** | **Challenge Nonce / Step-Up Token Replay & `/24` Flood** | Replays a captured `{ c: nonce, p }` packet, replays a `stepup_v2` recovery token, or floods `/challenge` to evict active nonces. | `ConsumeChallenge(nonce)` (`GETDEL`), single-use `stepup_v2` JTI consumption, and `DefaultMaxChallengesPerIPSub = 64` per-`/24` quota. | `CHALLENGE_NONCE_INVALID_OR_REPLAYED`, `403 REBIND_FORBIDDEN` on step-up replay, or `CHALLENGE_RATE_LIMITED` (`429`). |
| **3** | **Random / Stale Pixel Script** | Submits random or stale `spot_pixels` that do not match the live 60-second `render_seed` `[s0,s1,s2,s3]`. | Server computes GLSL fragment shader values at the 8 challenge coordinates `(x+0.5)/256.0`. | `Accepted = false`, `ErrorCode = SHADER_SPOT_PIXEL_MISMATCH` (`SHADER_SPOT_PIXEL_MATH_MISMATCH`). |
| **4** | **Browser Noise Extension / Unmodified-SDK Hook + Proxy Rotation** | Runs a Canvas/Audio noise extension or intercepts the unmodified SDK payload to flip `lies.*` booleans to `false` without synthesizing coherent raw pixel/audio fields, while rotating `/24` proxies. | Server checks 256-pixel spatial uniformity (`canvas_control_rgba`, `canvas_readback_delta` $\le 2$) and `audio_copy_hash` (`SpoofTrapTriggered = true`). *(Note: custom out-of-browser clients that synthesize coherent raw fields are bounded via per-subnet velocity bursts and optional `TurnstileVerifier`.)* | Active spoof observations are flagged `red` and isolated within 24h without contaminating clean users of the same laptop model. |
| **5** | **Main-Thread Hook / ES6 Proxy Extension** | Overrides `navigator.*`, `Intl.DateTimeFormat`, `Math.*` transcendentals, or wraps extensible WebGL methods in `new Proxy(...)`. | `workerLie.ts` compares main thread vs. inline `Blob` Worker + `64x64` `OffscreenCanvas`; `lieDetector.ts` detects `Proxy` on extensible functions and `unknown_tampered_math`. | Flags `worker_lie_detected` / `prototype_lies` / `math_engine_tampered`, substitutes Worker's unhooked GPU hash into `d_gpu_*`, and marks `SpoofTrapTriggered = true`. |
| **6** | **Impossible OS / GPU Register Combination** | Spoofs `gpu_renderer` to `"Apple M3 Max"` while reporting `platform = "Win32"` or invalid `ALIASED_LINE_WIDTH_RANGE`. | `gpu_laws.go` checks hardware register invariants (accounting for Firefox's sanitized `"or similar"` `MAX_TEXTURE_SIZE = 8192`) and V8/JSC/SpiderMonkey `Math` engine alignment. | Flags `gpu_register_law_violation` (`SpoofTrapTriggered = true`, or rejects when `RejectOnGPULawViolation = true`). |
| **7** | **Kernel/API Hook Spoofing Native Motherboard UUID** | Hooks `ioreg` / `powershell` on a desktop install to return a fake `HWUUID` while `d_kch_*` or `d_bcn_*` persists. | **Per-Anchor UUID Split Trap (`native_uuid_split_trap`)**: Scoped strictly to `d_kch_*` and `d_bcn_*` (never shared `d_gpu_*`). | Triggers `native_uuid_split_trap` (`SpoofTrapTriggered = true`) and links both accounts via `d_kch_*` / `d_gpu_*`. |
| **8** | **Cloud Headless Browser (`SwiftShader` / `llvmpipe`) & VM Clones** | Runs headless containers with software rendering (`SwiftShader`, `llvmpipe`) or VMware/VirtualBox/QEMU VMs. | `gpu_laws.go` + `prismid-native` VM model detector (`Win32_ComputerSystem.Model`, `hv_vmm_present`, DMI). | Sets `IsVirtualGPU = true` and assigns `Confidence = 0.30` (`< 0.60`), keeping `RiskPending = true` (`RiskStatusUnknown`). |

---

## 2. False-Positive Prevention Invariants (Verified by Cross-Browser & Audit Suites)

1. **Same-Model Colleagues & Cross-City Users (`F2`)**:
   - Accounts with distinct, un-spoofed native anchors (`d_nat_*`) or distinct, un-spoofed Web beacons (`d_bcn_*`) are not merged into `ComponentSubjects` by model-level `d_gpu_*` or subnet-level `d_gpusys_*`.
2. **Shared Household / Lab Browsers vs. Cookie-Wiping Evasion (`F3` & `HardAnchorPolicy`)**:
   - Single-user partial storage recovery (`storage_healed = true`) records `"storage_healed"` + `StorageSilosMask` without setting `SpoofTrapTriggered = true` (`green`). Under default `HardAnchorPolicySharedStepUp`, 2–3 clean accounts sharing a family/lab browser profile elevate to `yellow + risk_pending: true` (`shared_hard_anchor_step_up`) rather than immediate `red`, whereas $\ge 4$ accounts or spoofed sessions escalate to `red` (`strict_1to1` available for strict 1:1 promotions).
3. **Key Rotation & Compromised-Key Retirement (`S1-3`)**:
   - Rebinding a `device_key` via `previous_device_key` rotation proof or `stepup_v2` MFA retires the superseded `d_key_old` edge from `RiskGraph` so rotated keys never permanently link an account to stale/stolen key slices.
4. **Hardened Privacy Browsers (Disabled WebGL / Muted Audio) & Windows 11 VBS (`S1-6`, `S2-17`, `S2-18`)**:
   - Browsers with WebGL disabled (`Unavailable / WebGL Disabled`) and a bound `d_key_*` receive `Confidence = 0.75` (`webgl_disabled_by_client`) rather than `0.30` virtual-GPU demotion; all-zero muted `OfflineAudioContext` output records `audio_output_muted` without false `audio_noise_injected`; bare-metal Windows 11 systems with VBS/Hyper-V/WSL2 (`HypervisorPresent = True`) remain `is_vm = false`.
5. **Mobile CGNAT & Large Office `/24` Subnets (`DeepSeek #5A`)**:
   - `/24` subnet GPU diversity (`SubnetCrowdTriggered` / `d_ip24_crowd_*`) is emitted strictly as telemetry and excluded from `SliceNodes()`, keeping unrelated users sharing a mobile CGNAT `/24` `green`.
