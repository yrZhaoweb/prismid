/**
 * PrismID Web & WebView SDK (`prismid-js`)
 *
 * Provides 3-line integration for Browser Web apps and Tauri Desktop WebViews:
 *   1. Requests a 60s single-use challenge (`nonce` + `render_seed` [s0,s1,s2,s3])
 *   2. Executes WebGL shader spot-pixel sampling, inline Blob Worker + OffscreenCanvas
 *      cross-thread lie detection, OfflineAudioContext integral, sub-pixel TextMetrics
 *      font bounding boxes, FDLIBM Math constants, and optional Rust NativeHardwareAnchor
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
import { collectAudioProbe } from './probes/audio.js'
import { collectFontsAndCanvasProbe } from './probes/fontsCanvas.js'
import { collectLieDetectorProbe } from './probes/lieDetector.js'
import {
  collectWebGLProbe,
  computeExpectedSpotPixelMath,
  DEFAULT_SAMPLE_POINTS,
} from './probes/webgl.js'
import { collectWorkerLieProbe } from './probes/workerLie.js'

export {
  AEAD_KEY_DOMAIN_PREFIX,
  aes256GcmEncryptPureTS,
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
  toBase64RawURL,
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

export interface IdentifyResponse {
  accepted: boolean
  confidence?: number
  exact_slice_id?: string
  gpu_audio_slice_id?: string
  sys_net_slice_id?: string
  crowd_slice_id?: string
  is_native?: boolean
  is_virtual_gpu?: boolean
  spoof_trap_triggered?: boolean
  spoof_flags?: string[]
  risk_status?: string
  risk_pending?: boolean
}

export interface ProbePayload {
  v: number
  nonce: string
  collected_at: number
  webgl: {
    gpu_vendor: string
    gpu_renderer: string
    webgl_limits_vector: string
    static_webgl_fp_hash: string
    spot_pixels: [number, number, number, number][]
  }
  audio_compressor_hash: string
  system: {
    user_agent: string
    platform: string
    cpu_cores: number
    device_memory?: number
    timezone: string
    languages: string[]
    screen_spec: string
    canvas_2d_hash: string
    fonts_bitmap_hash: string
  }
  lies: {
    worker_unavailable: boolean
    worker_lie_detected: boolean
    worker_gpu_renderer?: string
    worker_static_webgl_fp_hash?: string
    worker_cpu_cores?: number
    worker_platform?: string
    worker_user_agent?: string
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
  }
}

export function createPrismClient(options: PrismClientOptions = {}): PrismClient {
  const baseUrl = (options.baseUrl || '').replace(/\/+$/, '')
  const fetchFn = options.fetchImpl || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : undefined)
  const cooldownMs = options.cooldownMs ?? 5 * 60 * 1000

  let lastIdentifiedToken: string | null = null
  let lastIdentifiedAt = 0
  let inFlightPromise: Promise<IdentifyResponse | null> | null = null

  async function buildAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (options.getAccessToken) {
      const token = await options.getAccessToken()
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

    const [audioHash, workerLie, nativeAnchor, turnstileToken] = await Promise.all([
      collectAudioProbe(),
      collectWorkerLieProbe({
        gpuRenderer: webgl.gpu_renderer,
        staticWebGLFpHash: webgl.static_webgl_fp_hash,
        cpuCores: sysMeta.cpuCores,
        platform: sysMeta.platform,
        userAgent: sysMeta.userAgent,
      }),
      options.nativeAnchorProvider
        ? options.nativeAnchorProvider().catch(() => null)
        : Promise.resolve(null),
      options.getTurnstileToken
        ? options.getTurnstileToken().catch(() => undefined)
        : Promise.resolve(undefined),
    ])

    const payload: ProbePayload = {
      v: 1,
      nonce: challenge.nonce,
      collected_at: Date.now(),
      webgl: {
        gpu_vendor: webgl.gpu_vendor,
        gpu_renderer: webgl.gpu_renderer,
        webgl_limits_vector: webgl.webgl_limits_vector,
        static_webgl_fp_hash: webgl.static_webgl_fp_hash,
        spot_pixels: webgl.spot_pixels,
      },
      audio_compressor_hash: audioHash,
      system: {
        user_agent: sysMeta.userAgent,
        platform: sysMeta.platform,
        cpu_cores: sysMeta.cpuCores,
        ...(sysMeta.deviceMemory !== undefined ? { device_memory: sysMeta.deviceMemory } : {}),
        timezone: sysMeta.timezone,
        languages: sysMeta.languages,
        screen_spec: sysMeta.screenSpec,
        canvas_2d_hash: fontsCanvas.canvas_2d_hash,
        fonts_bitmap_hash: fontsCanvas.fonts_bitmap_hash,
      },
      lies: {
        worker_unavailable: workerLie.worker_unavailable,
        worker_lie_detected: workerLie.worker_lie_detected,
        worker_gpu_renderer: workerLie.worker_gpu_renderer,
        worker_static_webgl_fp_hash: workerLie.worker_static_webgl_fp_hash,
        worker_cpu_cores: workerLie.worker_cpu_cores,
        worker_platform: workerLie.worker_platform,
        worker_user_agent: workerLie.worker_user_agent,
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
    const token = options.getAccessToken ? (await options.getAccessToken()) || null : null
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

        // Optional cooldown check via GET /api/v1/risk/should-collect
        if (!callOpts?.force) {
          try {
            const scRes = await fetchFn(`${baseUrl}/api/v1/risk/should-collect`, {
              method: 'GET',
              headers,
            })
            if (scRes.ok) {
              const scJson = (await scRes.json()) as {
                should_collect?: boolean
                data?: { should_collect?: boolean }
              }
              const shouldCollect =
                scJson.should_collect ?? scJson.data?.should_collect ?? true
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

        const chRes = await fetchFn(`${baseUrl}/api/v1/risk/challenge`, {
          method: 'POST',
          headers,
          body: '{}',
        })
        if (!chRes.ok) {
          return null
        }
        const chRaw = (await chRes.json()) as ChallengeResponse & { data?: ChallengeResponse }
        const challenge: ChallengeResponse = chRaw.nonce ? chRaw : (chRaw.data as ChallengeResponse)
        if (!challenge || !challenge.nonce || !Array.isArray(challenge.render_seed)) {
          return null
        }

        const { request } = await collectAndSeal(challenge)

        const idRes = await fetchFn(`${baseUrl}/api/v1/risk/identify`, {
          method: 'POST',
          headers,
          body: JSON.stringify(request),
        })
        if (!idRes.ok) {
          return null
        }
        const idRaw = (await idRes.json()) as IdentifyResponse & { data?: IdentifyResponse }
        const result: IdentifyResponse =
          typeof idRaw.accepted === 'boolean' ? idRaw : (idRaw.data || { accepted: true })

        lastIdentifiedToken = token
        lastIdentifiedAt = Date.now()
        return result
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
