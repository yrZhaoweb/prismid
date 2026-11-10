/**
 * PrismID Web & WebView SDK (`prismid-js` v1.0.0)
 *
 * Provides 3-line integration for Browser Web apps and Tauri Desktop WebViews:
 *   1. Requests a 60s single-use challenge (`nonce` + `render_seed` [s0,s1,s2,s3])
 *   2. Executes WebGL shader spot-pixel sampling, non-extractable WebCrypto ECDSA P-256
 *      device key signing (`d_key_*`), inline Blob Worker + OffscreenCanvas cross-thread
 *      lie detection, 5-silo self-healing storage beacon, raw Canvas/Audio exactness
 *      measurements, sub-pixel TextMetrics font bounding boxes, and optional Rust NativeHardwareAnchor
 *   3. Seals the entire probe payload via AES-256-GCM (AEAD) and submits to `/api/v1/risk/identify`
 */

import {
  AEAD_KEY_DOMAIN_PREFIX,
  aes256GcmEncryptPureTS,
  deriveAEADKeyBytes,
  sealPayload,
  sha256Bytes,
  sha256Hex,
  toBase64RawURL,
} from './crypto/aead.js'
import {
  buildDeviceKeyTranscript,
  signChallengeWithDeviceKey,
  type DeviceKeyProof,
} from './crypto/deviceKey.js'
import { collectAudioProbe, collectAudioProbeWithTrap } from './probes/audio.js'
import { collectFontsAndCanvasProbe } from './probes/fontsCanvas.js'
import { collectLieDetectorProbe } from './probes/lieDetector.js'
import { collectAndHealStorageBeacon, type StorageBeaconResult } from './probes/storageBeacon.js'
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
  collectAndHealStorageBeacon,
  collectAudioProbe,
  collectFontsAndCanvasProbe,
  collectLieDetectorProbe,
  collectWebGLProbe,
  collectWorkerLieProbe,
  computeExpectedSpotPixelMath,
  DEFAULT_SAMPLE_POINTS,
  deriveAEADKeyBytes,
  sealPayload,
  sha256Bytes,
  sha256Hex,
  signChallengeWithDeviceKey,
  toBase64RawURL,
  type DeviceKeyProof,
  type StorageBeaconResult,
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
  category: string
  slice_id?: string
  rule_name: string
  log_odds_delta: number
  description: string
}

export interface IdentifyResponse {
  accepted: boolean
  code?: string
  message?: string
  confidence?: number
  exact_slice_id?: string
  device_key_slice_id?: string
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
  /** Returns the current user's bearer access token (if authenticated). */
  getAccessToken?: () => string | null | undefined | Promise<string | null | undefined>
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
}

export interface PrismClient {
  /** Runs the full shouldCollect -> challenge -> probe -> AEAD seal -> identify flow. */
  identify: (options?: { force?: boolean }) => Promise<IdentifyResponse | null>
  /** Collects all hardware probes for a given challenge and returns the sealed AEAD request. */
  collectAndSeal: (challenge: ChallengeResponse) => Promise<{
    request: IdentifyWireRequest
    payload: ProbePayload
  }>
  /** Clears the in-memory session cooldown cache. */
  resetSessionCache: () => void
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

  let lastIdentifiedToken: string | null = null
  let lastIdentifiedAt = 0
  let inFlightPromise: Promise<IdentifyResponse | null> | null = null

  function withDeadline<T>(promise: Promise<T>, timeoutMs: number, fallback: T): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<T>((resolve) => {
      timer = setTimeout(() => resolve(fallback), timeoutMs)
    })
    return Promise.race([promise, deadline]).finally(() => {
      if (timer !== undefined) clearTimeout(timer)
    })
  }

  // Covers both HTTP response headers AND full response body reading within a single deadline!
  async function fetchJsonWithDeadline<T>(
    url: string,
    init: RequestInit
  ): Promise<{ ok: boolean; status: number; data: T | null }> {
    if (!fetchFn) throw new Error('fetch unavailable')
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined
    let timer: ReturnType<typeof setTimeout> | undefined
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        if (controller) controller.abort()
        reject(new Error('request deadline exceeded'))
      }, requestTimeoutMs)
    })
    try {
      const work = (async () => {
        const res = await fetchFn(url, controller ? { ...init, signal: controller.signal } : init)
        const text = await res.text()
        if (!text) {
          return { ok: res.ok, status: res.status, data: null }
        }
        try {
          return { ok: res.ok, status: res.status, data: JSON.parse(text) as T }
        } catch {
          return { ok: res.ok, status: res.status, data: null }
        }
      })()
      return await Promise.race([work, timeoutPromise])
    } finally {
      if (timer !== undefined) clearTimeout(timer)
    }
  }

  async function buildAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (options.getAccessToken) {
      const token = await withDeadline(
        Promise.resolve(options.getAccessToken()).catch(() => null),
        Math.min(requestTimeoutMs, 1500),
        null
      )
      if (token) {
        headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`
      }
    }
    return headers
  }

  async function collectAndSeal(challenge: ChallengeResponse): Promise<{
    request: IdentifyWireRequest
    payload: ProbePayload
  }> {
    const samplePoints =
      Array.isArray(challenge.sample_points) && challenge.sample_points.length > 0
        ? challenge.sample_points
        : DEFAULT_SAMPLE_POINTS

    const sysMeta = collectSystemMetadata()
    const webgl = collectWebGLProbe(challenge.render_seed, samplePoints)
    const fontsCanvas = collectFontsAndCanvasProbe()
    const lieDetector = collectLieDetectorProbe()
    const providerTimeoutMs = Math.min(requestTimeoutMs, 1000)

    const [audioRes, workerLie, storageBeacon, nativeAnchor, turnstileToken] = await Promise.all([
      collectAudioProbeWithTrap(),
      collectWorkerLieProbe({
        gpuRenderer: webgl.gpu_renderer,
        staticWebGLFpHash: webgl.static_webgl_fp_hash,
        cpuCores: sysMeta.cpuCores,
        platform: sysMeta.platform,
        userAgent: sysMeta.userAgent,
        timezone: sysMeta.timezone,
      }),
      collectAndHealStorageBeacon(),
      options.nativeAnchorProvider
        ? withDeadline(
            Promise.resolve(options.nativeAnchorProvider()).catch(() => null),
            providerTimeoutMs,
            null
          )
        : Promise.resolve(null),
      options.getTurnstileToken
        ? withDeadline(
            Promise.resolve(options.getTurnstileToken()).catch(() => undefined),
            providerTimeoutMs,
            undefined
          )
        : Promise.resolve(undefined),
    ])

    const deviceKey = await withDeadline(
      signChallengeWithDeviceKey({
        nonce: challenge.nonce,
        beaconId: storageBeacon.beacon_id,
        staticWebGLFpHash: webgl.static_webgl_fp_hash,
        audioCompressorHash: audioRes.audio_compressor_hash,
      }),
      350,
      undefined
    )

    const payload: ProbePayload = {
      v: 1,
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
        storage_silos_mask: storageBeacon.surviving_silos.length,
        math_engine_signature: lieDetector.math_engine_signature,
        math_constants_hash: lieDetector.math_constants_hash,
        prototype_lies: lieDetector.prototype_lies,
        automation_flags: lieDetector.automation_flags,
      },
      ...(nativeAnchor ? { native_anchor: nativeAnchor } : {}),
    }

    const sealedBlob = await sealPayload(challenge.nonce, JSON.stringify(payload))
    const request: IdentifyWireRequest = {
      c: challenge.nonce,
      p: sealedBlob,
      ...(turnstileToken ? { ts: turnstileToken } : {}),
    }

    return { request, payload }
  }

  async function identify(callOpts?: { force?: boolean }): Promise<IdentifyResponse | null> {
    if (!fetchFn) return null
    const token = options.getAccessToken
      ? (await withDeadline(
          Promise.resolve(options.getAccessToken()).catch(() => null),
          Math.min(requestTimeoutMs, 1500),
          null
        )) || null
      : null
    const now = Date.now()
    if (
      !callOpts?.force &&
      lastIdentifiedAt > 0 &&
      lastIdentifiedToken === token &&
      now - lastIdentifiedAt < cooldownMs
    ) {
      return null
    }

    if (inFlightPromise) {
      return inFlightPromise
    }

    inFlightPromise = (async () => {
      try {
        const headers = await buildAuthHeaders()

        if (!callOpts?.force) {
          try {
            const scRes = await fetchJsonWithDeadline<{
              should_collect?: boolean
              data?: { should_collect?: boolean }
            }>(`${baseUrl}/api/v1/risk/should-collect`, {
              method: 'GET',
              headers,
            })
            if (scRes.ok && scRes.data) {
              const shouldCollect =
                scRes.data.should_collect ?? scRes.data.data?.should_collect ?? true
              if (shouldCollect === false) {
                lastIdentifiedToken = token
                lastIdentifiedAt = Date.now()
                return { accepted: true }
              }
            }
          } catch {
            // Proceed to challenge if should-collect endpoint is not used
          }
        }

        const chRes = await fetchJsonWithDeadline<
          ChallengeResponse & { data?: ChallengeResponse }
        >(`${baseUrl}/api/v1/risk/challenge`, {
          method: 'POST',
          headers,
          body: '{}',
        })
        if (!chRes.ok || !chRes.data) {
          return null
        }
        const chRaw = chRes.data
        const challenge: ChallengeResponse = chRaw.nonce ? chRaw : (chRaw.data as ChallengeResponse)
        if (!challenge || !challenge.nonce || !Array.isArray(challenge.render_seed)) {
          return null
        }

        const { request } = await collectAndSeal(challenge)

        const idRes = await fetchJsonWithDeadline<
          IdentifyResponse & { data?: IdentifyResponse }
        >(`${baseUrl}/api/v1/risk/identify`, {
          method: 'POST',
          headers,
          body: JSON.stringify(request),
        })
        const idRaw = idRes.data
        if (!idRaw || typeof idRaw !== 'object') {
          return null
        }
        const candidate: IdentifyResponse | undefined =
          typeof idRaw.accepted === 'boolean'
            ? idRaw
            : idRaw.data && typeof idRaw.data.accepted === 'boolean'
              ? idRaw.data
              : undefined
        // Strict schema check: never synthesize `{ accepted: true }` from an empty `{}` response!
        if (!candidate || typeof candidate.accepted !== 'boolean') {
          return null
        }
        if (!idRes.ok && candidate.accepted !== false) {
          return null
        }

        if (candidate.accepted && !candidate.risk_pending && !candidate.device_key_recovery_required) {
          lastIdentifiedToken = token
          lastIdentifiedAt = Date.now()
        }
        return candidate
      } catch {
        return null
      } finally {
        inFlightPromise = null
      }
    })()

    return inFlightPromise
  }

  function resetSessionCache(): void {
    lastIdentifiedToken = null
    lastIdentifiedAt = 0
  }

  return {
    identify,
    collectAndSeal,
    resetSessionCache,
  }
}
