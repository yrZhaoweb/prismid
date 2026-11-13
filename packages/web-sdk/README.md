# prismid-js (`v1.2.1`)

Zero-dependency browser & Tauri WebView client SDK for **PrismID**: orthogonal hardware risk signals, dynamic stratified WebGL fragment-shader spot-pixel verification, non-extractable WebCrypto `ECDSA P-256` device keys (`d_key_*`) with two-phase MitM-safe key rotation, 5-silo self-healing storage beacons (`d_bcn_*`), cross-thread `Blob` Worker + `OffscreenCanvas` consistency checks, multi-tenant namespace headers (`X-PrismID-Tenant-ID`), and `AES-256-GCM` AEAD payload sealing.

## Installation

```bash
npm install prismid-js
# or
pnpm add prismid-js
```

## Quick Start

```ts
import { createPrismClient } from 'prismid-js'

const prism = createPrismClient({
  baseUrl: 'https://risk.example.com',
  getAccessToken: () => sessionStorage.getItem('access_token'),
  providerTimeoutMs: 2500, // Decoupled deadline for async Turnstile / Tauri native providers
  tenantId: undefined, // Optional multi-tenant isolation header (`X-PrismID-Tenant-ID`)
  // Optional MFA/Passkey callback for TOFU key recovery or spoof clearance:
  getStepUpToken: async (action, ctx) => requestStepUpFromBackend(action, ctx),
})

const { result, error } = await prism.identifyDetailed()
if (error) {
  console.warn('PrismID network/HTTP error:', error.kind, error.status, error.message)
} else if (result?.skipped) {
  // Server cooldown policy skipped collection (`accepted === false`, `skipped === true`)
} else if (result?.device_key_recovery_required) {
  // Complete single-use step-up recovery when IndexedDB was cleared:
  await prism.rebindKey()
}
```

## Lifecycle Helpers

- `prism.identify({ force })` / `prism.identifyDetailed({ force })` — runs `should-collect -> challenge -> probes -> AEAD seal -> identify`.
- `prism.getLastError()` — inspects structured HTTP (`401`/`403`/`409`/`429`), timeout, or network diagnostics.
- `prism.rebindKey({ stepUpToken, rotate })` — completes single-use step-up TOFU recovery or proactive key rotation (`rotate: true` signs a `previous_device_key` continuity proof without MFA when the prior key is still present).
- `prism.clearSpoof({ stepUpToken })` — clears sticky spoof cooldown after MFA step-up.
- `prism.deleteSubject()` — triggers GDPR/CCPA erasure (`DELETE /api/v1/risk/subject`) and resets local caches.
- `resetDeviceKeyCache()` — clears in-memory `CryptoKey` cache after in-session site-data clearing.

See the root repository documentation (`README.md`, `docs/PROTOCOL_SPEC.md`, and `docs/INTEGRATION_GUIDE.md`) for server deployment, shared-device policies (`shared_step_up` / `strict_1to1`), and trust boundaries.

## License

MIT — see [LICENSE](./LICENSE).
