/**
 * PrismID Web & WebView SDK (`prismid-js` v1.2.1)
 *
 * Provides 3-line integration for Browser Web apps and Tauri Desktop WebViews:
 *   1. Requests a 60s single-use challenge (`nonce` + `render_seed` [s0,s1,s2,s3])
 *   2. Executes WebGL shader spot-pixel sampling, non-extractable WebCrypto ECDSA P-256
 *      device key signing (`d_key_*`), inline Blob Worker + OffscreenCanvas cross-thread
 *      lie detection, 5-silo self-healing storage beacon, raw Canvas/Audio exactness
 *      measurements, sub-pixel TextMetrics font bounding boxes, and optional Rust NativeHardwareAnchor
 *   3. Seals the entire probe payload via AES-256-GCM (AEAD) and submits to `/api/v1/risk/identify`,
 *      plus high-level `rebindKey`, `clearSpoof`, and `deleteSubject` lifecycle helpers.
 */

import {
  AEAD_KEY_DOMAIN_PREFIX,
  aes256GcmEncryptPureTS,
  csprngBytes,
  deriveAEADKeyBytes,
  sealPayload,
  sha256Bytes,
  sha256Hex,
  toBase64RawURL,
} from './crypto/aead.js'
import {
  buildDeviceKeyTranscript,
  buildPreviousKeyRotationTranscript,
  buildRebindKeyTranscript,
  preloadDeviceKey,
  prepareDeviceKeyRotation,
  resetDeviceKeyCache,
  rotateDeviceKeyAndSignRebind,
  signChallengeWithDeviceKey,
  signRebindWithDeviceKey,
  type DeviceKeyProof,
  type PreparedKeyRotation,
} from './crypto/deviceKey.js'
import { collectAudioProbe, collectAudioProbeWithTrap, type AudioProbeResult } from './probes/audio.js'
import { collectFontsAndCanvasProbe, resetFontsProbeCache } from './probes/fontsCanvas.js'
import { collectLieDetectorProbe } from './probes/lieDetector.js'
import {
  collectAndHealStorageBeacon,
  SILO_MASK,
  type StorageBeaconResult,
} from './probes/storageBeacon.js'
import {
  collectWebGLProbe,
  computeExpectedSpotPixelMath,
  DEFAULT_SAMPLE_POINTS,
} from './probes/webgl.js'
import { collectWorkerLieProbe } from './probes/workerLie.js'

export {
  AEAD_KEY_DOMAIN_PREFIX,
  aes256GcmEncryptPureTS,
  buildDeviceKeyTranscript,
  buildPreviousKeyRotationTranscript,
  buildRebindKeyTranscript,
  collectAndHealStorageBeacon,
  collectAudioProbe,
  collectAudioProbeWithTrap,
  collectFontsAndCanvasProbe,
  collectLieDetectorProbe,
  collectWebGLProbe,
  collectWorkerLieProbe,
  computeExpectedSpotPixelMath,
  csprngBytes,
  DEFAULT_SAMPLE_POINTS,
  deriveAEADKeyBytes,
  preloadDeviceKey,
  prepareDeviceKeyRotation,
  resetDeviceKeyCache,
  resetFontsProbeCache,
  rotateDeviceKeyAndSignRebind,
  sealPayload,
  sha256Bytes,
  sha256Hex,
  signChallengeWithDeviceKey,
  signRebindWithDeviceKey,
  SILO_MASK,
  toBase64RawURL,
  type AudioProbeResult,
  type DeviceKeyProof,
  type PreparedKeyRotation,
  type StorageBeaconResult,
}

export const PRISM_PROBE_VERSION = 2
export const MAX_PRISM_WIRE_BYTES = 65_536

export function utf8ByteLength(text: string): number {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(text).byteLength
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.byteLength(text, 'utf8')
  }
  return text.length * 3
}

export function measureJsonWireBytes(payload: unknown): number {
  return utf8ByteLength(JSON.stringify(payload))
}

export interface NativeHardwareAnchor {
  platform: string
  hw_uuid: string
  serial_number: string
  keychain_anchor: string
  cpu_brand: string
  cpu_cores: number
  memory_bytes: number
  is_vm: boolean
  vm_vendor?: string
}

export interface ChallengeResponse {
  nonce: string
  render_seed: [number, number, number, number]
  sample_points?: [number, number][]
  issued_at: number
  expires_at: number
}

export interface IdentifyWireRequest {
  c: string
  p: string
  ts?: string
}

export interface RiskEvidenceItem {
  slice_id?: string
  category?: string
  description: string
  log_odds?: number
  observed_at?: string
  historical?: boolean
  /** @deprecated Legacy v1.0.0 type compatibility alias for `category`. */
  rule_name?: string
  /** @deprecated Legacy v1.0.0 type compatibility alias for `log_odds`. */
  log_odds_delta?: number
}

export interface IdentifyResponse {
  accepted: boolean
  /** True when `/should-collect` reported `should_collect: false` (`accepted` is `false`, never synthesized as `true`). */
  skipped?: boolean
  code?: string
  message?: string
  confidence?: number
  exact_slice_id?: string
  device_key_slice_id?: string
  device_key_bound?: boolean
  /** @deprecated Legacy alias mirroring `device_key_bound`; proves ECDSA P-256 key possession, not hardware silicon attestation. */
  device_key_attested?: boolean
  device_key_recovery_required?: boolean
  keychain_slice_id?: string
  beacon_slice_id?: string
  gpu_audio_slice_id?: string
  sys_net_slice_id?: string
  crowd_slice_id?: string
  subnet_crowd_triggered?: boolean
  is_native?: boolean
  is_virtual_gpu?: boolean
  spoof_trap_triggered?: boolean
  spoof_flags?: string[]
  privacy_signals?: string[]
  risk_status?: string
  risk_pending?: boolean
  truncated?: boolean
  burst_suspicion?: boolean
  log_odds_score?: number
  evidence_chain?: RiskEvidenceItem[]
}

export interface PrismClientError {
  kind: 'http' | 'network' | 'timeout' | 'aborted' | 'malformed_response'
  status?: number
  code?: string
  retryAfterMs?: number
  message: string
}

export interface RebindKeyResponse {
  accepted: boolean
  http_status?: number
  retry_after_ms?: number
  rebound?: boolean
  retired_previous_key?: boolean
  audit_id?: string
  code?: string
  error?: string
  subject_id?: string
  beacon_slice_id?: string
  device_key_slice_id?: string
}

export interface PrismCallOptions {
  force?: boolean
  signal?: AbortSignal
}

export interface PrismCollectOptions {
  signal?: AbortSignal
}

export interface PrismRebindOptions {
  subjectId?: string
  stepUpToken?: string
  rotate?: boolean
  beaconId?: string
  signal?: AbortSignal
}

export interface ClearSpoofResponse {
  accepted: boolean
  subject_id?: string
  cleared?: boolean
  error?: string
  component_snapshot?: unknown
}

export interface DeleteSubjectResponse {
  accepted: boolean
  subject_id?: string
  deleted?: boolean
  purged_key_bindings?: number
  error?: string
}

export interface ProbePayload {
  v: number
  nonce: string
  collected_at: number
  beacon_id?: string
  device_key?: DeviceKeyProof
  webgl: {
    gpu_vendor: string
    gpu_renderer: string
    webgl_limits_vector: string
    webgl_extensions_hash?: string
    webgl_available?: boolean
    static_webgl_fp_hash: string
    spot_pixels: [number, number, number, number][]
  }
  audio_compressor_hash: string
  audio_copy_hash?: string
  audio_silent_delta?: number
  audio_muted?: boolean
  system: {
    user_agent: string
    platform: string
    cpu_cores: number
    device_memory?: number
    timezone: string
    languages: string[]
    screen_spec: string
    display_gamut_spec?: string
    voices_hash?: string
    intl_hash?: string
    canvas_2d_hash: string
    fonts_bitmap_hash: string
    canvas_control_rgba?: number[]
    canvas_readback_delta?: number
  }
  lies: {
    worker_unavailable: boolean
    worker_webgl_available?: boolean
    worker_lie_detected: boolean
    worker_gpu_renderer?: string
    worker_static_webgl_fp_hash?: string
    worker_cpu_cores?: number
    worker_platform?: string
    worker_user_agent?: string
    worker_timezone?: string
    canvas_noise_injected?: boolean
    webgl_noise_injected?: boolean
    audio_noise_injected?: boolean
    storage_healed?: boolean
    storage_silos_mask?: number
    math_engine_signature: string
    math_constants_hash: string
    prototype_lies: string[]
    automation_flags: string[]
  }
  native_anchor?: NativeHardwareAnchor | null
}

export interface PrismClientOptions {
  /** Base API URL (default: `""` for same-origin requests). */
  baseUrl?: string
  /** Optional multi-tenant isolation identifier sent as `X-PrismID-Tenant-ID`. */
  tenantId?: string
  /** Returns the current user's bearer access token (if authenticated). Invoked at most once per request cycle. */
  getAccessToken?: () => string | null | undefined | Promise<string | null | undefined>
  /** Optional explicit subject ID resolver when bearer tokens are opaque session cookies/handles. */
  getSubjectId?: () => string | null | undefined | Promise<string | null | undefined>
  /**
   * Optional provider that triggers MFA/Passkey/OTP step-up and returns a single-use `step_up_token`
   * when calling `rebindKey()` or `clearSpoof()`.
   */
  getStepUpToken?: (
    action: 'rebind_key' | 'clear_spoof',
    context: { subjectId: string; beaconId?: string }
  ) => string | null | undefined | Promise<string | null | undefined>
  /** Optional Cloudflare Turnstile or CAPTCHA token provider. */
  getTurnstileToken?: () => Promise<string | undefined>
  /**
   * Optional desktop native hardware anchor provider (e.g. Tauri `invoke('collect_native_hardware_anchor')`).
   * Omit in browser Web apps to run in pure Web mode automatically.
   */
  nativeAnchorProvider?: () => Promise<NativeHardwareAnchor | null | undefined>
  /** Custom `fetch` implementation for testing or SSR environments. */
  fetchImpl?: typeof fetch
  /** Session cooldown in milliseconds to avoid redundant collections (default: 5 minutes). */
  cooldownMs?: number
  /** Per-request network (headers + body) & provider timeout in milliseconds (default: 5000ms). */
  requestTimeoutMs?: number
  /** Aggregate client-side probe collection budget in milliseconds (default: 800ms, S3-41). */
  probeTimeoutMs?: number
  /** Independent deadline in milliseconds for external providers (`nativeAnchorProvider` / `getTurnstileToken`; default: `min(requestTimeoutMs, max(probeTimeoutMs, 2500))`). */
  providerTimeoutMs?: number
  /** Optional error observer invoked whenever `identify()` encounters an HTTP, timeout, or network failure (S3-40). */
  onError?: (error: PrismClientError) => void
}

export interface PrismClient {
  /** Runs the full shouldCollect -> challenge -> probe -> AEAD seal -> identify flow. */
  identify: (options?: PrismCallOptions) => Promise<IdentifyResponse | null>
  /** Runs `identify` and returns both the structured response and any diagnostic error (`429`/`403`/timeout/network/aborted). */
  identifyDetailed: (options?: PrismCallOptions) => Promise<{
    result: IdentifyResponse | null
    error: PrismClientError | null
  }>
  /** Returns the most recent diagnostic error from `identify()` (or `null` if the last run succeeded). */
  getLastError: () => PrismClientError | null
  /** Collects all hardware probes for a given challenge and returns the sealed AEAD request. */
  collectAndSeal: (challenge: ChallengeResponse, options?: PrismCollectOptions) => Promise<{
    request: IdentifyWireRequest
    payload: ProbePayload
  }>
  /**
   * Completes TOFU device-key recovery (via single-use `stepUpToken`) or proactive key rotation
   * (`rotate: true`, using `previous_device_key` continuity signature without MFA when old key is still intact).
   */
  rebindKey: (options?: PrismRebindOptions) => Promise<RebindKeyResponse>
  /** Clears sticky spoof cooldown after step-up authentication (`/api/v1/risk/clear-spoof`). */
  clearSpoof: (options?: { stepUpToken?: string }) => Promise<ClearSpoofResponse>
  /** Executes GDPR/CCPA subject erasure (`DELETE /api/v1/risk/subject`). */
  deleteSubject: () => Promise<DeleteSubjectResponse>
  /** Clears the in-memory session cooldown cache and cached device key reference. */
  resetSessionCache: (options?: { includeDeviceKey?: boolean }) => void
}

function inferSubjectIdFromToken(token: string | null): string {
  if (!token) return ''
  const raw = token.startsWith('Bearer ') ? token.slice(7).trim() : token.trim()
  if (!raw) return ''
  // 1. PrismID signed bearer token: `<subject_id>.<exp_unix>.<64hex>`
  const prismMatch = /^(.+)\.\d{9,12}\.[0-9a-f]{64}$/i.exec(raw)
  if (prismMatch && prismMatch[1]) {
    return prismMatch[1]
  }
  // 2. Standard 3-segment JWT (`header.payload.signature`) with `sub` or `user_id` claim
  const parts = raw.split('.')
  if (parts.length === 3 && parts[0].startsWith('eyJ')) {
    try {
      const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
      const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4)
      const jsonStr =
        typeof atob === 'function'
          ? atob(padded)
          : Buffer.from(padded, 'base64').toString('utf8')
      const parsed = JSON.parse(jsonStr) as { sub?: unknown; user_id?: unknown }
      const rawSub = parsed.sub ?? parsed.user_id
      if (typeof rawSub === 'string' && rawSub.trim()) {
        return rawSub.trim()
      }
      if (typeof rawSub === 'number' && Number.isFinite(rawSub) && rawSub > 0) {
        return String(rawSub)
      }
    } catch {
      // fall through
    }
    return ''
  }
  return raw
}

function collectDisplayGamutSpec(): string {
  try {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return 'srgb|standard|fine'
    }
    const gamut = window.matchMedia('(color-gamut: rec2020)').matches
      ? 'rec2020'
      : window.matchMedia('(color-gamut: p3)').matches
        ? 'p3'
        : 'srgb'
    const hdr = window.matchMedia('(dynamic-range: high)').matches ? 'hdr' : 'standard'
    const ptr = window.matchMedia('(pointer: coarse)').matches ? 'coarse' : 'fine'
    return `${gamut}|${hdr}|${ptr}`
  } catch {
    return 'srgb|standard|fine'
  }
}

function collectIntlHash(): string {
  try {
    const dtf = Intl.DateTimeFormat().resolvedOptions()
    const nf = Intl.NumberFormat().resolvedOptions()
    const numSample = new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency: 'USD',
    }).format(123456.78)
    return sha256Hex(
      [
        dtf.locale || '',
        dtf.calendar || '',
        dtf.numberingSystem || '',
        dtf.timeZone || '',
        nf.locale || '',
        numSample,
      ].join('|')
    ).slice(0, 32)
  } catch {
    return ''
  }
}

function collectVoicesHash(): string {
  try {
    if (
      typeof speechSynthesis === 'undefined' ||
      typeof speechSynthesis.getVoices !== 'function'
    ) {
      return ''
    }
    const voices = speechSynthesis.getVoices() || []
    if (voices.length === 0) return ''
    const canonical = voices
      .map((v) => `${v.voiceURI}|${v.lang}|${v.localService ? 1 : 0}`)
      .sort()
      .join(';')
    return sha256Hex(canonical).slice(0, 32)
  } catch {
    return ''
  }
}

function collectSystemMetadata() {
  const nav = typeof navigator !== 'undefined' ? navigator : undefined
  const scr = typeof screen !== 'undefined' ? screen : undefined
  const dpr = typeof window !== 'undefined' && window.devicePixelRatio ? window.devicePixelRatio : 1

  const userAgent = nav ? String(nav.userAgent || '') : ''
  const platform = nav ? String(nav.platform || '') : ''
  const cpuCores = nav && nav.hardwareConcurrency ? Number(nav.hardwareConcurrency) : 1
  const deviceMemory =
    nav && 'deviceMemory' in nav && typeof (nav as unknown as { deviceMemory?: number }).deviceMemory === 'number'
      ? Number((nav as unknown as { deviceMemory?: number }).deviceMemory)
      : undefined

  let timezone = 'UTC'
  try {
    timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    timezone = 'UTC'
  }

  const languages = nav && Array.isArray(nav.languages) && nav.languages.length > 0
    ? Array.from(nav.languages)
    : nav && nav.language
      ? [nav.language]
      : ['en-US']

  const screenSpec = scr
    ? `${scr.width || 0}x${scr.height || 0}x${scr.colorDepth || 24}@${dpr}`
    : `0x0x24@${dpr}`

  return {
    userAgent,
    platform,
    cpuCores,
    deviceMemory,
    timezone,
    languages,
    screenSpec,
    displayGamutSpec: collectDisplayGamutSpec(),
    intlHash: collectIntlHash(),
    voicesHash: collectVoicesHash(),
  }
}

export function createPrismClient(options: PrismClientOptions = {}): PrismClient {
  const baseUrl = (options.baseUrl || '').replace(/\/+$/, '')
  const fetchFn = options.fetchImpl || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : undefined)
  const cooldownMs = options.cooldownMs ?? 5 * 60 * 1000
  const requestTimeoutMs = options.requestTimeoutMs ?? 5000
  const probeTimeoutMs = options.probeTimeoutMs ?? 800

  let lastIdentifiedToken: string | null = null
  let lastIdentifiedAt = 0
  let lastError: PrismClientError | null = null
  let inFlightPromise: Promise<{ result: IdentifyResponse | null; error: PrismClientError | null }> | null = null
  let inFlightToken: string | null = null
  let clientSessionEpoch = 0

  function recordError(err: PrismClientError): PrismClientError {
    lastError = err
    try {
      options.onError?.(err)
    } catch {
      // ignore observer exceptions
    }
    return err
  }

  function withDeadline<T>(promise: Promise<T>, timeoutMs: number, fallback: T): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<T>((resolve) => {
      timer = setTimeout(() => resolve(fallback), timeoutMs)
    })
    return Promise.race([promise, deadline]).finally(() => {
      if (timer !== undefined) clearTimeout(timer)
    })
  }

  function createAbortError(message = 'PrismID operation aborted'): Error & { isAborted: true } {
    const err = new Error(message) as Error & { isAborted: true }
    err.name = 'AbortError'
    err.isAborted = true
    return err
  }

  function throwIfAborted(signal?: AbortSignal): void {
    if (signal?.aborted) {
      throw createAbortError()
    }
  }

  function raceWithAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
    if (!signal) return promise
    if (signal.aborted) {
      return Promise.reject(createAbortError())
    }
    let onAbort: (() => void) | undefined
    const abortPromise = new Promise<never>((_, reject) => {
      onAbort = () => reject(createAbortError())
      signal.addEventListener('abort', onAbort, { once: true })
    })
    return Promise.race([promise, abortPromise]).finally(() => {
      if (onAbort) signal.removeEventListener('abort', onAbort)
    })
  }

  function parseRetryAfterMs(headers: Headers | undefined): number | undefined {
    if (!headers || typeof headers.get !== 'function') return undefined
    const raw = headers.get('retry-after') ?? headers.get('Retry-After')
    if (!raw) return undefined
    const trimmed = raw.trim()
    if (!trimmed) return undefined
    if (/^\d+$/.test(trimmed)) {
      const secs = Number(trimmed)
      return Number.isFinite(secs) && secs >= 0 ? secs * 1000 : undefined
    }
    const parsedAt = Date.parse(trimmed)
    if (Number.isFinite(parsedAt)) {
      return Math.max(0, parsedAt - Date.now())
    }
    return undefined
  }

  function extractWireError(raw: unknown): { code?: string; message?: string } {
    if (!raw || typeof raw !== 'object') return {}
    const rec = raw as Record<string, unknown>
    const nested =
      rec.data && typeof rec.data === 'object' ? (rec.data as Record<string, unknown>) : undefined
    const reasonStr =
      typeof rec.reason === 'string' && rec.reason.trim()
        ? rec.reason.trim()
        : nested && typeof nested.reason === 'string' && nested.reason.trim()
          ? nested.reason.trim()
          : undefined
    const codeStr =
      typeof rec.code === 'string' && rec.code.trim()
        ? rec.code.trim()
        : nested && typeof nested.code === 'string' && nested.code.trim()
          ? nested.code.trim()
          : undefined
    const messageStr =
      typeof rec.message === 'string' && rec.message.trim()
        ? rec.message.trim()
        : typeof rec.error === 'string' && rec.error.trim()
          ? rec.error.trim()
          : nested && typeof nested.message === 'string' && nested.message.trim()
            ? nested.message.trim()
            : nested && typeof nested.error === 'string' && nested.error.trim()
              ? nested.error.trim()
              : undefined
    return {
      code: reasonStr ?? codeStr,
      message: messageStr,
    }
  }

  // Covers both HTTP response headers AND full response body reading within a single deadline!
  async function fetchJsonWithDeadline<T>(
    url: string,
    init: RequestInit,
    externalSignal?: AbortSignal
  ): Promise<{ ok: boolean; status: number; retryAfterMs?: number; data: T | null }> {
    if (!fetchFn) throw new Error('fetch unavailable')
    throwIfAborted(externalSignal)

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined
    let timer: ReturnType<typeof setTimeout> | undefined
    let onExternalAbort: (() => void) | undefined

    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        if (controller) controller.abort()
        const err = new Error('request deadline exceeded')
        ;(err as Error & { isTimeout?: boolean }).isTimeout = true
        reject(err)
      }, requestTimeoutMs)
    })

    const externalAbortPromise = externalSignal
      ? new Promise<never>((_, reject) => {
          onExternalAbort = () => {
            if (controller) controller.abort()
            reject(createAbortError())
          }
          if (externalSignal.aborted) {
            onExternalAbort()
          } else {
            externalSignal.addEventListener('abort', onExternalAbort, { once: true })
          }
        })
      : undefined

    try {
      const work = (async () => {
        const res = await fetchFn(url, controller ? { ...init, signal: controller.signal } : init)
        throwIfAborted(externalSignal)
        const retryAfterMs = parseRetryAfterMs(res.headers)
        const text = await res.text()
        throwIfAborted(externalSignal)
        if (!text) {
          return { ok: res.ok, status: res.status, retryAfterMs, data: null }
        }
        try {
          return { ok: res.ok, status: res.status, retryAfterMs, data: JSON.parse(text) as T }
        } catch {
          return { ok: res.ok, status: res.status, retryAfterMs, data: null }
        }
      })()
      return await (externalAbortPromise
        ? Promise.race([work, timeoutPromise, externalAbortPromise])
        : Promise.race([work, timeoutPromise]))
    } finally {
      if (timer !== undefined) clearTimeout(timer)
      if (externalSignal && onExternalAbort) {
        externalSignal.removeEventListener('abort', onExternalAbort)
      }
    }
  }

  // Resolves access token AT MOST ONCE per client operation (S3-39).
  async function resolveAccessToken(signal?: AbortSignal): Promise<string | null> {
    throwIfAborted(signal)
    if (!options.getAccessToken) return null
    const tok = await raceWithAbort(
      withDeadline(
        Promise.resolve(options.getAccessToken()).catch(() => null),
        Math.min(requestTimeoutMs, 1500),
        null
      ),
      signal
    )
    throwIfAborted(signal)
    return tok ? String(tok) : null
  }

  function buildAuthHeadersFromToken(token: string | null): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (token) {
      headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`
    }
    const configuredTenant = options.tenantId?.trim()
    if (configuredTenant) {
      headers['X-PrismID-Tenant-ID'] = configuredTenant
    }
    return headers
  }

  async function collectAndSeal(
    challenge: ChallengeResponse,
    callOpts?: PrismCollectOptions
  ): Promise<{
    request: IdentifyWireRequest
    payload: ProbePayload
  }> {
    throwIfAborted(callOpts?.signal)
    const samplePoints =
      Array.isArray(challenge.sample_points) && challenge.sample_points.length > 0
        ? challenge.sample_points
        : DEFAULT_SAMPLE_POINTS

    // Enforce bounded per-probe budgets while keeping external providers (`nativeAnchorProvider`,
    // `getTurnstileToken`) decoupled from browser probes so a slow Turnstile challenge or cold
    // desktop IPC bridge NEVER discards completed `beacon_id` / `audio` / `worker` results.
    const aggregateBudgetMs = Math.max(120, Math.min(probeTimeoutMs, requestTimeoutMs))
    const audioBudgetMs = Math.min(400, Math.floor(aggregateBudgetMs * 0.65))
    const workerBudgetMs = Math.min(300, Math.floor(aggregateBudgetMs * 0.5))
    const storageBudgetMs = Math.min(350, Math.floor(aggregateBudgetMs * 0.55))
    const externalProviderTimeoutMs = Math.max(
      120,
      Math.min(requestTimeoutMs, options.providerTimeoutMs ?? Math.max(probeTimeoutMs, 2500))
    )
    const keyBudgetMs = Math.max(40, Math.min(requestTimeoutMs, Math.max(probeTimeoutMs, 1500)))
    const keySignDeadlineMs = Math.max(50, Math.min(requestTimeoutMs, keyBudgetMs * 2))

    // Start persistent deviceKey preload immediately in parallel WITHOUT coupling it into
    // `Promise.all` (so slow cold-disk IndexedDB initialization on Windows NTFS/Defender never
    // causes `withDeadline` to discard audio/worker/beacon probe results, while warm visits stay <1ms).
    void preloadDeviceKey(keyBudgetMs).catch(() => false)

    const sysMeta = collectSystemMetadata()
    const webgl = collectWebGLProbe(challenge.render_seed, samplePoints)
    const fontsCanvas = collectFontsAndCanvasProbe()
    const lieDetector = collectLieDetectorProbe()

    const fallbackAudio: AudioProbeResult = {
      audio_compressor_hash: sha256Hex('prismid-audio-aggregate-deadline'),
      audio_copy_hash: sha256Hex('prismid-audio-aggregate-deadline'),
      audio_silent_delta: 0,
      audio_noise_injected: false,
      audio_muted: false,
    }
    const fallbackWorker = {
      worker_unavailable: true,
      worker_webgl_available: false,
      worker_lie_detected: false,
      worker_gpu_renderer: '',
      worker_static_webgl_fp_hash: '',
      worker_cpu_cores: 0,
      worker_platform: '',
      worker_user_agent: '',
      worker_timezone: '',
    }
    const fallbackBeacon: StorageBeaconResult = {
      beacon_id: '',
      storage_healed: false,
      surviving_silos: [],
      surviving_silos_mask: 0,
    }

    const [audioRes, workerLie, storageBeacon, nativeAnchor, turnstileToken] = await raceWithAbort(
      Promise.all([
        withDeadline(
          collectAudioProbeWithTrap(audioBudgetMs).catch(() => fallbackAudio),
          aggregateBudgetMs,
          fallbackAudio
        ),
        withDeadline(
          collectWorkerLieProbe(
            {
              gpuRenderer: webgl.gpu_renderer,
              staticWebGLFpHash: webgl.static_webgl_fp_hash,
              webglAvailable: webgl.webgl_available,
              cpuCores: sysMeta.cpuCores,
              platform: sysMeta.platform,
              userAgent: sysMeta.userAgent,
              timezone: sysMeta.timezone,
            },
            workerBudgetMs
          ).catch(() => fallbackWorker),
          aggregateBudgetMs,
          fallbackWorker
        ),
        withDeadline(
          collectAndHealStorageBeacon(storageBudgetMs).catch(() => fallbackBeacon),
          aggregateBudgetMs,
          fallbackBeacon
        ),
        options.nativeAnchorProvider
          ? withDeadline(
              Promise.resolve(options.nativeAnchorProvider()).catch(() => null),
              externalProviderTimeoutMs,
              null
            )
          : Promise.resolve(null),
        options.getTurnstileToken
          ? withDeadline(
              Promise.resolve(options.getTurnstileToken()).catch(() => undefined),
              externalProviderTimeoutMs,
              undefined
            )
          : Promise.resolve(undefined),
      ]),
      callOpts?.signal
    )
    throwIfAborted(callOpts?.signal)

    const deviceKey = await raceWithAbort(
      withDeadline(
        signChallengeWithDeviceKey(
          {
            nonce: challenge.nonce,
            beaconId: storageBeacon.beacon_id,
            staticWebGLFpHash: webgl.static_webgl_fp_hash,
            audioCompressorHash: audioRes.audio_compressor_hash,
          },
          keyBudgetMs
        ),
        keySignDeadlineMs,
        undefined
      ),
      callOpts?.signal
    )
    throwIfAborted(callOpts?.signal)

    const payload: ProbePayload = {
      v: PRISM_PROBE_VERSION,
      nonce: challenge.nonce,
      collected_at: Date.now(),
      beacon_id: storageBeacon.beacon_id,
      ...(deviceKey ? { device_key: deviceKey } : {}),
      webgl: {
        gpu_vendor: webgl.gpu_vendor,
        gpu_renderer: webgl.gpu_renderer,
        webgl_limits_vector: webgl.webgl_limits_vector,
        webgl_extensions_hash: webgl.webgl_extensions_hash,
        webgl_available: webgl.webgl_available,
        static_webgl_fp_hash: webgl.static_webgl_fp_hash,
        spot_pixels: webgl.spot_pixels,
      },
      audio_compressor_hash: audioRes.audio_compressor_hash,
      audio_copy_hash: audioRes.audio_copy_hash,
      audio_silent_delta: audioRes.audio_silent_delta,
      ...(audioRes.audio_muted ? { audio_muted: true } : {}),
      system: {
        user_agent: sysMeta.userAgent,
        platform: sysMeta.platform,
        cpu_cores: sysMeta.cpuCores,
        ...(sysMeta.deviceMemory !== undefined ? { device_memory: sysMeta.deviceMemory } : {}),
        timezone: sysMeta.timezone,
        languages: sysMeta.languages,
        screen_spec: sysMeta.screenSpec,
        display_gamut_spec: sysMeta.displayGamutSpec,
        ...(sysMeta.voicesHash ? { voices_hash: sysMeta.voicesHash } : {}),
        ...(sysMeta.intlHash ? { intl_hash: sysMeta.intlHash } : {}),
        canvas_2d_hash: fontsCanvas.canvas_2d_hash,
        fonts_bitmap_hash: fontsCanvas.fonts_bitmap_hash,
        canvas_control_rgba: fontsCanvas.canvas_control_rgba,
        canvas_readback_delta: fontsCanvas.canvas_readback_delta,
      },
      lies: {
        worker_unavailable: workerLie.worker_unavailable,
        worker_webgl_available: workerLie.worker_webgl_available,
        worker_lie_detected: workerLie.worker_lie_detected,
        worker_gpu_renderer: workerLie.worker_gpu_renderer,
        worker_static_webgl_fp_hash: workerLie.worker_static_webgl_fp_hash,
        worker_cpu_cores: workerLie.worker_cpu_cores,
        worker_platform: workerLie.worker_platform,
        worker_user_agent: workerLie.worker_user_agent,
        worker_timezone: workerLie.worker_timezone,
        canvas_noise_injected: fontsCanvas.canvas_noise_injected,
        webgl_noise_injected: webgl.webgl_noise_injected,
        audio_noise_injected: audioRes.audio_noise_injected,
        storage_healed: storageBeacon.storage_healed,
        storage_silos_mask: storageBeacon.surviving_silos_mask,
        math_engine_signature: lieDetector.math_engine_signature,
        math_constants_hash: lieDetector.math_constants_hash,
        prototype_lies: lieDetector.prototype_lies,
        automation_flags: lieDetector.automation_flags,
      },
      ...(nativeAnchor ? { native_anchor: nativeAnchor } : {}),
    }

    const sealedBlob = await raceWithAbort(
      sealPayload(challenge.nonce, JSON.stringify(payload)),
      callOpts?.signal
    )
    throwIfAborted(callOpts?.signal)
    const request: IdentifyWireRequest = {
      c: challenge.nonce,
      p: sealedBlob,
      ...(turnstileToken ? { ts: turnstileToken } : {}),
    }

    return { request, payload }
  }

  async function identifyDetailed(callOpts?: PrismCallOptions): Promise<{
    result: IdentifyResponse | null
    error: PrismClientError | null
  }> {
    const signal = callOpts?.signal
    if (signal?.aborted) {
      return {
        result: null,
        error: { kind: 'aborted', code: 'ABORTED', message: 'PrismID operation aborted' },
      }
    }
    if (!fetchFn) {
      return {
        result: null,
        error: recordError({ kind: 'network', message: 'fetch implementation unavailable' }),
      }
    }

    let token: string | null = null
    try {
      // Resolve access token ONCE and reuse for cooldown check + HTTP Authorization header (S3-39).
      token = await resolveAccessToken(signal)
    } catch (caught) {
      if ((caught as { isAborted?: boolean })?.isAborted) {
        return {
          result: null,
          error: {
            kind: 'aborted',
            code: 'ABORTED',
            message: caught instanceof Error ? caught.message : 'PrismID operation aborted',
          },
        }
      }
      throw caught
    }

    const now = Date.now()
    if (
      !callOpts?.force &&
      lastIdentifiedAt > 0 &&
      lastIdentifiedToken === token &&
      now - lastIdentifiedAt < cooldownMs
    ) {
      return { result: null, error: null }
    }

    if (!signal && inFlightPromise && inFlightToken === token) {
      return inFlightPromise
    }

    const reqEpoch = clientSessionEpoch
    if (!signal) {
      inFlightToken = token
    }
    const currentFlight: Promise<{ result: IdentifyResponse | null; error: PrismClientError | null }> = (async (): Promise<{
      result: IdentifyResponse | null
      error: PrismClientError | null
    }> => {
      try {
        throwIfAborted(signal)
        lastError = null
        const headers = buildAuthHeadersFromToken(token)

        if (!callOpts?.force) {
          try {
            const scRes = await fetchJsonWithDeadline<{
              should_collect?: boolean
              data?: { should_collect?: boolean }
            }>(
              `${baseUrl}/api/v1/risk/should-collect`,
              {
                method: 'GET',
                headers,
              },
              signal
            )
            if (scRes.ok && scRes.data) {
              const shouldCollect =
                scRes.data.should_collect ?? scRes.data.data?.should_collect ?? true
              if (shouldCollect === false) {
                if (reqEpoch === clientSessionEpoch && !signal?.aborted) {
                  lastIdentifiedToken = token
                  lastIdentifiedAt = Date.now()
                }
                // Never synthesize `{ accepted: true }` when collection was skipped (S3-53).
                return {
                  result: {
                    accepted: false,
                    skipped: true,
                    code: 'COLLECTION_SKIPPED',
                    message: 'collection skipped by should-collect policy',
                  },
                  error: null,
                }
              }
            }
          } catch (caught) {
            if ((caught as { isAborted?: boolean })?.isAborted) {
              throw caught
            }
            // Proceed to challenge if should-collect endpoint is unreachable or unused
          }
        }

        const chRes = await fetchJsonWithDeadline<
          ChallengeResponse & { data?: ChallengeResponse; error?: string; code?: string | number; reason?: string; message?: string }
        >(
          `${baseUrl}/api/v1/risk/challenge`,
          {
            method: 'POST',
            headers,
            body: '{}',
          },
          signal
        )
        if (!chRes.ok || !chRes.data) {
          const chErr = extractWireError(chRes.data)
          const err = recordError({
            kind: chRes.ok ? 'malformed_response' : 'http',
            status: chRes.status,
            ...(chErr.code ? { code: chErr.code } : {}),
            ...(chRes.retryAfterMs !== undefined ? { retryAfterMs: chRes.retryAfterMs } : {}),
            message: chErr.message || `challenge HTTP ${chRes.status}`,
          })
          return { result: null, error: err }
        }
        const chRaw = chRes.data
        const challenge: ChallengeResponse = chRaw.nonce ? chRaw : (chRaw.data as ChallengeResponse)
        if (!challenge || !challenge.nonce || !Array.isArray(challenge.render_seed)) {
          const err = recordError({
            kind: 'malformed_response',
            status: chRes.status,
            message: 'invalid challenge schema',
          })
          return { result: null, error: err }
        }

        const { request } = await collectAndSeal(challenge, { signal })
        const bodyJson = JSON.stringify(request)
        if (utf8ByteLength(bodyJson) > MAX_PRISM_WIRE_BYTES) {
          const err = recordError({
            kind: 'http',
            status: 413,
            code: 'PAYLOAD_TOO_LARGE',
            message: `identify request exceeds ${MAX_PRISM_WIRE_BYTES}-byte wire limit`,
          })
          return { result: null, error: err }
        }

        const idRes = await fetchJsonWithDeadline<
          IdentifyResponse & { data?: IdentifyResponse; error?: string; reason?: string; code?: string | number }
        >(
          `${baseUrl}/api/v1/risk/identify`,
          {
            method: 'POST',
            headers,
            body: bodyJson,
          },
          signal
        )
        const idRaw = idRes.data
        if (!idRaw || typeof idRaw !== 'object') {
          const err = recordError({
            kind: idRes.ok ? 'malformed_response' : 'http',
            status: idRes.status,
            ...(idRes.retryAfterMs !== undefined ? { retryAfterMs: idRes.retryAfterMs } : {}),
            message: `identify HTTP ${idRes.status} without valid JSON body`,
          })
          return { result: null, error: err }
        }
        const idWireErr = extractWireError(idRaw)
        const rawCandidate =
          idRaw.data && typeof idRaw.data === 'object' ? idRaw.data : idRaw
        const candidate: IdentifyResponse | undefined =
          typeof rawCandidate.accepted === 'boolean' ? (rawCandidate as IdentifyResponse) : undefined

        // Strict schema check: never synthesize `{ accepted: true }` from an empty `{}` response!
        if (!candidate || typeof candidate.accepted !== 'boolean') {
          const err = recordError({
            kind: idRes.ok ? 'malformed_response' : 'http',
            status: idRes.status,
            ...(idWireErr.code ? { code: idWireErr.code } : {}),
            ...(idRes.retryAfterMs !== undefined ? { retryAfterMs: idRes.retryAfterMs } : {}),
            message: idWireErr.message || `identify HTTP ${idRes.status}`,
          })
          return { result: null, error: err }
        }
        if (!idRes.ok && candidate.accepted !== false) {
          const err = recordError({
            kind: 'http',
            status: idRes.status,
            ...(idWireErr.code ? { code: idWireErr.code } : {}),
            ...(idRes.retryAfterMs !== undefined ? { retryAfterMs: idRes.retryAfterMs } : {}),
            message: idWireErr.message || `identify HTTP ${idRes.status}`,
          })
          return { result: null, error: err }
        }
        if (!idRes.ok) {
          const err = recordError({
            kind: 'http',
            status: idRes.status,
            ...(idWireErr.code ? { code: idWireErr.code } : {}),
            ...(idRes.retryAfterMs !== undefined ? { retryAfterMs: idRes.retryAfterMs } : {}),
            message: idWireErr.message || `identify HTTP ${idRes.status}`,
          })
          const normalizedCandidate: IdentifyResponse = {
            ...candidate,
            accepted: false,
            ...(idWireErr.code ? { code: idWireErr.code } : {}),
          }
          // Preserve structured `accepted: false` rejection payloads (e.g. HTTP 409/403) when non-429/401,
          // while returning null on 401/429 gateway rejections without domain error code if no string code was set.
          if (idRes.status === 401 || idRes.status === 429) {
            if (!idWireErr.code) {
              return { result: null, error: err }
            }
          }
          return { result: normalizedCandidate, error: err }
        }

        if (
          reqEpoch === clientSessionEpoch &&
          !signal?.aborted &&
          candidate.accepted &&
          !candidate.risk_pending &&
          !candidate.device_key_recovery_required
        ) {
          lastIdentifiedToken = token
          lastIdentifiedAt = Date.now()
        }
        return { result: candidate, error: null }
      } catch (caught) {
        if ((caught as { isAborted?: boolean })?.isAborted) {
          return {
            result: null,
            error: {
              kind: 'aborted',
              code: 'ABORTED',
              message: caught instanceof Error ? caught.message : 'PrismID operation aborted',
            },
          }
        }
        const isTimeout = Boolean((caught as { isTimeout?: boolean })?.isTimeout)
        const err = recordError({
          kind: isTimeout ? 'timeout' : 'network',
          message: caught instanceof Error ? caught.message : 'network error',
        })
        return { result: null, error: err }
      }
    })().finally(() => {
      if (!signal && inFlightPromise === currentFlight) {
        inFlightPromise = null
        inFlightToken = null
      }
    })
    if (!signal) {
      inFlightPromise = currentFlight
    }

    return currentFlight
  }

  async function identify(callOpts?: PrismCallOptions): Promise<IdentifyResponse | null> {
    const { result } = await identifyDetailed(callOpts)
    return result
  }

  function getLastError(): PrismClientError | null {
    return lastError
  }

  async function rebindKey(rebindOpts?: PrismRebindOptions): Promise<RebindKeyResponse> {
    const signal = rebindOpts?.signal
    if (signal?.aborted) {
      return { accepted: false, code: 'ABORTED', error: 'PrismID operation aborted' }
    }
    if (!fetchFn) {
      return { accepted: false, error: 'fetch unavailable' }
    }
    try {
      const token = await resolveAccessToken(signal)
      const headers = buildAuthHeadersFromToken(token)

      let subjectId = (rebindOpts?.subjectId || '').trim()
      if (!subjectId && options.getSubjectId) {
        const resolvedSub = await raceWithAbort(
          withDeadline(
            Promise.resolve(options.getSubjectId()).catch(() => null),
            1500,
            null
          ),
          signal
        )
        if (resolvedSub) subjectId = String(resolvedSub).trim()
      }
      throwIfAborted(signal)
      if (!subjectId) {
        subjectId = inferSubjectIdFromToken(token)
      }
      if (!subjectId) {
        return { accepted: false, error: 'subjectId is required to sign rebind proof' }
      }

      const beaconId =
        rebindOpts?.beaconId?.trim().toLowerCase() ||
        (
          await raceWithAbort(
            collectAndHealStorageBeacon(Math.min(350, probeTimeoutMs)),
            signal
          )
        ).beacon_id
      throwIfAborted(signal)
      if (!beaconId) {
        return { accepted: false, error: 'storage beacon unavailable' }
      }

      const chRes = await fetchJsonWithDeadline<
        ChallengeResponse & { data?: ChallengeResponse; error?: string; reason?: string; code?: string | number; message?: string }
      >(
        `${baseUrl}/api/v1/risk/challenge`,
        {
          method: 'POST',
          headers,
          body: '{}',
        },
        signal
      )
      const chRaw = chRes.data
      const challenge = chRaw?.nonce ? chRaw : chRaw?.data
      if (!chRes.ok || !challenge?.nonce) {
        const chErr = extractWireError(chRaw)
        return {
          accepted: false,
          http_status: chRes.status,
          ...(chErr.code ? { code: chErr.code } : {}),
          ...(chRes.retryAfterMs !== undefined ? { retry_after_ms: chRes.retryAfterMs } : {}),
          error: chErr.message || `challenge HTTP ${chRes.status}`,
        }
      }

      const rebindKeyBudgetMs = Math.max(80, Math.min(requestTimeoutMs, Math.max(probeTimeoutMs, 1500)))
      let deviceKey: DeviceKeyProof | undefined
      let previousDeviceKey: DeviceKeyProof | undefined
      let preparedRotation: PreparedKeyRotation | undefined
      if (rebindOpts?.rotate) {
        preparedRotation = await raceWithAbort(
          prepareDeviceKeyRotation(
            {
              nonce: challenge.nonce,
              subjectId,
              beaconId,
            },
            rebindKeyBudgetMs
          ),
          signal
        )
        deviceKey = preparedRotation?.device_key
        previousDeviceKey = preparedRotation?.previous_device_key
      } else {
        deviceKey = await raceWithAbort(
          signRebindWithDeviceKey(
            {
              nonce: challenge.nonce,
              subjectId,
              beaconId,
            },
            rebindKeyBudgetMs
          ),
          signal
        )
      }
      throwIfAborted(signal)
      if (!deviceKey) {
        return { accepted: false, error: 'failed to initialize or sign with persistent WebCrypto device key' }
      }

      let stepUpToken = rebindOpts?.stepUpToken?.trim() || ''
      if (!stepUpToken && !previousDeviceKey && options.getStepUpToken) {
        const fetchedStepUp = await raceWithAbort(
          withDeadline(
            Promise.resolve(options.getStepUpToken('rebind_key', { subjectId, beaconId })).catch(() => null),
            requestTimeoutMs,
            null
          ),
          signal
        )
        if (fetchedStepUp) stepUpToken = String(fetchedStepUp).trim()
      }
      throwIfAborted(signal)

      const rebindBody = JSON.stringify({
        challenge_nonce: challenge.nonce,
        beacon_id: beaconId,
        step_up_token: stepUpToken || undefined,
        device_key: deviceKey,
        ...(previousDeviceKey ? { previous_device_key: previousDeviceKey } : {}),
      })
      if (utf8ByteLength(rebindBody) > MAX_PRISM_WIRE_BYTES) {
        return {
          accepted: false,
          http_status: 413,
          code: 'PAYLOAD_TOO_LARGE',
          error: `rebind-key request exceeds ${MAX_PRISM_WIRE_BYTES}-byte wire limit`,
        }
      }

      const rbRes = await fetchJsonWithDeadline<
        RebindKeyResponse & { data?: RebindKeyResponse; message?: string; reason?: string; error?: string; code?: string | number }
      >(
        `${baseUrl}/api/v1/risk/rebind-key`,
        {
          method: 'POST',
          headers: {
            ...headers,
            ...(stepUpToken ? { 'X-PrismID-StepUp-Token': stepUpToken } : {}),
          },
          body: rebindBody,
        },
        signal
      )
      if (!rbRes.data || typeof rbRes.data !== 'object') {
        return {
          accepted: false,
          http_status: rbRes.status,
          ...(rbRes.status === 409 ? { code: 'HTTP_409_CONFLICT' } : {}),
          ...(rbRes.retryAfterMs !== undefined ? { retry_after_ms: rbRes.retryAfterMs } : {}),
          error: `rebind-key HTTP ${rbRes.status}`,
        }
      }
      const rbPayload =
        rbRes.data.data && typeof rbRes.data.data === 'object'
          ? (rbRes.data.data as RebindKeyResponse)
          : (rbRes.data as RebindKeyResponse)
      const wireErr = extractWireError(rbRes.data)
      const accepted = rbRes.ok && rbPayload.accepted !== false && rbPayload.rebound !== false
      throwIfAborted(signal)
      if (accepted && preparedRotation) {
        const committed = await preparedRotation.commit(rebindKeyBudgetMs)
        if (!committed) {
          return {
            accepted: false,
            http_status: rbRes.status,
            error: 'server accepted key rotation, but IndexedDB commit failed',
          }
        }
      }
      throwIfAborted(signal)
      resetSessionCache()
      const { code: _ignoredRawCode, ...rbRest } = rbPayload as RebindKeyResponse & Record<string, unknown>
      const resolvedCode =
        wireErr.code ??
        (!accepted && rbRes.status === 409 ? 'HTTP_409_CONFLICT' : undefined)
      return {
        ...(rbRest as RebindKeyResponse),
        accepted,
        http_status: rbRes.status,
        ...(rbRes.retryAfterMs !== undefined ? { retry_after_ms: rbRes.retryAfterMs } : {}),
        ...(resolvedCode ? { code: resolvedCode } : {}),
        ...(accepted
          ? {}
          : { error: wireErr.message || `rebind-key HTTP ${rbRes.status}` }),
      }
    } catch (err) {
      if ((err as { isAborted?: boolean })?.isAborted) {
        return {
          accepted: false,
          code: 'ABORTED',
          error: err instanceof Error ? err.message : 'PrismID operation aborted',
        }
      }
      return {
        accepted: false,
        error: err instanceof Error ? err.message : 'rebindKey request failed',
      }
    }
  }

  async function clearSpoof(clearOpts?: { stepUpToken?: string }): Promise<ClearSpoofResponse> {
    if (!fetchFn) {
      return { accepted: false, error: 'fetch unavailable' }
    }
    try {
      const token = await resolveAccessToken()
      const headers = buildAuthHeadersFromToken(token)
      const subjectId = inferSubjectIdFromToken(token)

      let stepUpToken = clearOpts?.stepUpToken?.trim() || ''
      if (!stepUpToken && options.getStepUpToken) {
        const fetched = await withDeadline(
          Promise.resolve(options.getStepUpToken('clear_spoof', { subjectId })).catch(() => null),
          requestTimeoutMs,
          null
        )
        if (fetched) stepUpToken = String(fetched).trim()
      }

      const res = await fetchJsonWithDeadline<ClearSpoofResponse>(`${baseUrl}/api/v1/risk/clear-spoof`, {
        method: 'POST',
        headers: {
          ...headers,
          ...(stepUpToken ? { 'X-PrismID-StepUp-Token': stepUpToken } : {}),
        },
        body: JSON.stringify({ step_up_token: stepUpToken }),
      })
      if (!res.data) {
        return { accepted: false, error: `clear-spoof HTTP ${res.status}` }
      }
      resetSessionCache()
      return {
        ...res.data,
        accepted: res.ok && res.data.accepted !== false,
      }
    } catch (err) {
      return {
        accepted: false,
        error: err instanceof Error ? err.message : 'clearSpoof request failed',
      }
    }
  }

  async function deleteSubject(): Promise<DeleteSubjectResponse> {
    if (!fetchFn) {
      return { accepted: false, error: 'fetch unavailable' }
    }
    try {
      const token = await resolveAccessToken()
      const headers = buildAuthHeadersFromToken(token)
      const res = await fetchJsonWithDeadline<DeleteSubjectResponse>(`${baseUrl}/api/v1/risk/subject`, {
        method: 'DELETE',
        headers,
      })
      if (!res.data) {
        return { accepted: false, error: `delete-subject HTTP ${res.status}` }
      }
      resetSessionCache({ includeDeviceKey: true })
      return {
        ...res.data,
        accepted: res.ok && res.data.accepted !== false,
      }
    } catch (err) {
      return {
        accepted: false,
        error: err instanceof Error ? err.message : 'deleteSubject request failed',
      }
    }
  }

  function resetSessionCache(resetOpts?: { includeDeviceKey?: boolean }): void {
    clientSessionEpoch += 1
    lastIdentifiedToken = null
    lastIdentifiedAt = 0
    inFlightPromise = null
    inFlightToken = null
    if (resetOpts?.includeDeviceKey) {
      resetDeviceKeyCache()
    }
  }

  return {
    identify,
    identifyDetailed,
    getLastError,
    collectAndSeal,
    rebindKey,
    clearSpoof,
    deleteSubject,
    resetSessionCache,
  }
}
