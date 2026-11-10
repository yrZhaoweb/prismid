import { spawn, type ChildProcess } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  collectAndHealStorageBeacon,
  collectAudioProbe,
  collectFontsAndCanvasProbe,
  collectLieDetectorProbe,
  collectWebGLProbe,
  collectWorkerLieProbe,
  computeExpectedSpotPixelMath,
  createPrismClient,
  DEFAULT_SAMPLE_POINTS,
  sealPayload,
  sha256Hex,
} from '../src/index.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const GO_SERVER_DIR = path.resolve(__dirname, '../../../server/go')
const CHROME_MAC_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

async function allocateFreeLocalPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      srv.close((err) => (err ? reject(err) : resolve(port)))
    })
    srv.on('error', reject)
  })
}

describe('PrismID Web SDK (prismid-js) Unit & Cross-Language Suite', () => {
  it('1. sha256Hex matches Node native crypto SHA-256 across empty, ASCII, and UTF-8 inputs', () => {
    for (const input of ['', 'abc', 'prismid-v1-aead:nonce123', '棱镜 PrismID 🚀 2026']) {
      const expected = crypto.createHash('sha256').update(input, 'utf8').digest('hex')
      expect(sha256Hex(input)).toBe(expected)
    }
  })

  it('2. Pure-TS AES-256-GCM fallback produces identical wire envelope to WebCrypto subtle.encrypt', async () => {
    const nonce = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
    const iv = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    const plaintext = JSON.stringify({ v: 1, nonce, hello: 'prismid' })

    const webCryptoSealed = await sealPayload(nonce, plaintext, { iv, forceFallback: false })
    const pureTsSealed = await sealPayload(nonce, plaintext, { iv, forceFallback: true })

    expect(pureTsSealed).toBe(webCryptoSealed)
  })

  it('3. GLSL shader spot-pixel math calculation is deterministic and bounded in [0, 255]', () => {
    const seed: [number, number, number, number] = [3.141593, 2.718282, 1.618034, 4.669201]
    for (const [x, y] of DEFAULT_SAMPLE_POINTS) {
      const px = computeExpectedSpotPixelMath(x, y, seed)
      expect(px).toHaveLength(4)
      expect(px[0]).toBeGreaterThanOrEqual(0)
      expect(px[0]).toBeLessThanOrEqual(255)
      expect(px[1]).toBeGreaterThanOrEqual(0)
      expect(px[1]).toBeLessThanOrEqual(255)
      expect(px[2]).toBeGreaterThanOrEqual(0)
      expect(px[2]).toBeLessThanOrEqual(255)
      expect(px[3]).toBe(255)
    }
  })

  it('4. Probes gracefully execute and return structured signals even in headless Node test environment', async () => {
    const webgl = collectWebGLProbe([2.1, 3.2, 4.3, 5.4])
    expect(webgl.spot_pixels).toHaveLength(8)
    expect(webgl.webgl_limits_vector.split('|')).toHaveLength(11)

    const audioHash = await collectAudioProbe(100)
    expect(audioHash).toMatch(/^[0-9a-f]{64}$/)

    const fc = collectFontsAndCanvasProbe()
    expect(fc.canvas_2d_hash).toMatch(/^[0-9a-f]{64}$/)
    expect(fc.fonts_bitmap_hash).toMatch(/^[0-9a-f]{64}$/)

    const lies = collectLieDetectorProbe()
    expect(lies.math_engine_signature).toBe('v8')
    expect(lies.math_constants_hash).toMatch(/^[0-9a-f]{32}$/)

    const workerLie = await collectWorkerLieProbe({
      gpuRenderer: webgl.gpu_renderer,
      staticWebGLFpHash: webgl.static_webgl_fp_hash,
      cpuCores: 10,
      platform: 'MacIntel',
      userAgent: 'Mozilla/5.0',
    })
    expect(typeof workerLie.worker_unavailable).toBe('boolean')
  })

  it('5. Audit Regressions (F5 & F6): empty HTTP 200 returns null (never fake accepted=true) and hung IndexedDB open finishes within bounded deadline', async () => {
    // F6: HTTP 200 `{}` must return null instead of synthesizing `{ accepted: true }`
    const mockFetchEmpty200: typeof fetch = async (input) => {
      const url = String(input)
      if (url.endsWith('/should-collect')) {
        return new Response(JSON.stringify({ should_collect: true }), { status: 200 })
      }
      if (url.endsWith('/challenge')) {
        return new Response(
          JSON.stringify({
            nonce: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
            render_seed: [2.1, 3.2, 4.3, 5.4],
            sample_points: DEFAULT_SAMPLE_POINTS,
            expires_at: Math.floor(Date.now() / 1000) + 60,
          }),
          { status: 200 }
        )
      }
      // Malformed / empty 200 OK from gateway
      return new Response(JSON.stringify({}), { status: 200 })
    }
    const clientEmpty = createPrismClient({ baseUrl: 'http://127.0.0.1:19999', fetchImpl: mockFetchEmpty200 })
    const resEmpty = await clientEmpty.identify({ force: true })
    expect(resEmpty).toBeNull()

    // F6: HTTP 409 structured rejection is surfaced rather than swallowed
    const mockFetch409: typeof fetch = async (input) => {
      const url = String(input)
      if (url.endsWith('/challenge')) {
        return new Response(
          JSON.stringify({
            nonce: 'b1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
            render_seed: [2.1, 3.2, 4.3, 5.4],
            sample_points: DEFAULT_SAMPLE_POINTS,
            expires_at: Math.floor(Date.now() / 1000) + 60,
          }),
          { status: 200 }
        )
      }
      return new Response(
        JSON.stringify({ accepted: false, code: 'PRISMID_CHALLENGE_INVALID', message: 'nonce replayed' }),
        { status: 409 }
      )
    }
    const client409 = createPrismClient({ baseUrl: 'http://127.0.0.1:19999', fetchImpl: mockFetch409 })
    const res409 = await client409.identify({ force: true })
    expect(res409).not.toBeNull()
    expect(res409?.accepted).toBe(false)
    expect(res409?.code).toBe('PRISMID_CHALLENGE_INVALID')

    // F5: Hung indexedDB.open (never fires onsuccess/onerror/onupgradeneeded) must resolve within 450ms
    const g = globalThis as unknown as Record<string, unknown>
    const origIDB = g.indexedDB
    g.indexedDB = {
      open: () => ({
        onsuccess: null,
        onerror: null,
        onblocked: null,
        onupgradeneeded: null,
      }),
    }
    try {
      const t0 = Date.now()
      const bcn = await collectAndHealStorageBeacon()
      const elapsed = Date.now() - t0
      expect(bcn.beacon_id).toMatch(/^[0-9a-f]{32}$/)
      expect(elapsed).toBeLessThan(450)
    } finally {
      g.indexedDB = origIDB
    }

    // R5: Stalled HTTP response body (headers returned immediately, JSON stream never closes)
    // must time out within requestTimeoutMs and release inFlightPromise!
    const mockFetchStalledBody: typeof fetch = async (input) => {
      const url = String(input)
      if (url.endsWith('/challenge')) {
        return new Response(
          JSON.stringify({
            nonce: 'c1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
            render_seed: [2.1, 3.2, 4.3, 5.4],
            sample_points: DEFAULT_SAMPLE_POINTS,
            expires_at: Math.floor(Date.now() / 1000) + 60,
          }),
          { status: 200 }
        )
      }
      const stalledStream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"accepted":'))
          // Intentionally never call controller.close()
        },
      })
      return new Response(stalledStream, { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    const clientStalled = createPrismClient({
      baseUrl: 'http://127.0.0.1:19999',
      fetchImpl: mockFetchStalledBody,
      requestTimeoutMs: 50,
    })
    const tStall = Date.now()
    const resStalled = await clientStalled.identify({ force: true })
    const stallElapsed = Date.now() - tStall
    expect(resStalled).toBeNull()
    expect(stallElapsed).toBeLessThan(1500)
  })

  it('allows recovery to retry immediately instead of applying the success cooldown', async () => {
    let attempts = 0
    const client = createPrismClient({
      baseUrl: 'http://review.invalid',
      fetchImpl: async (input) => {
        const url = String(input)
        if (url.endsWith('/should-collect')) {
          return new Response(JSON.stringify({ should_collect: true }))
        }
        if (url.endsWith('/challenge')) {
          return new Response(JSON.stringify({ nonce: 'review', render_seed: [2, 3, 4, 5] }))
        }
        attempts++
        return new Response(JSON.stringify(attempts === 1
          ? { accepted: true, risk_pending: true, device_key_recovery_required: true }
          : { accepted: true, risk_pending: false }))
      },
    })
    expect((await client.identify())?.device_key_recovery_required).toBe(true)
    expect((await client.identify())?.risk_pending).toBe(false)
    expect(attempts).toBe(2)
  })

  describe('6. Live Cross-Language E2E Integration (prismid-js -> prismid-go standalone server)', () => {
    let serverProc: ChildProcess | null = null
    let baseUrl = ''

    beforeAll(async () => {
      const port = await allocateFreeLocalPort()
      baseUrl = `http://127.0.0.1:${port}`
      serverProc = spawn('go', ['run', './cmd/prismid-server', '-addr', `127.0.0.1:${port}`], {
        cwd: GO_SERVER_DIR,
        stdio: 'pipe',
        detached: true,
      })

      const deadline = Date.now() + 15000
      while (Date.now() < deadline) {
        try {
          const res = await fetch(`${baseUrl}/healthz`)
          if (res.ok) return
        } catch {
          // wait
        }
        await new Promise((r) => setTimeout(r, 150))
      }
      throw new Error('Timed out waiting for standalone prismid-go server to start')
    }, 20000)

    afterAll(() => {
      if (serverProc && serverProc.pid) {
        try {
          process.kill(-serverProc.pid, 'SIGTERM')
        } catch {
          serverProc.kill('SIGTERM')
        }
      }
    })

    it('completes full Challenge -> WebGL Math Spot-Pixels -> AEAD Seal -> Go VerifyAndDerive cycle (Web & Desktop Native modes)', async () => {
      const webClient = createPrismClient({
        baseUrl,
        getAccessToken: () => 'test-jwt-token-web',
      })
      const webRes = await webClient.identify({ force: true })
      expect(webRes).not.toBeNull()
      expect(webRes?.accepted).toBe(true)
      // Node has no persistent IndexedDB: do not establish TOFU with an ephemeral key.
      expect(webRes?.device_key_attested).not.toBe(true)
      expect(webRes?.device_key_slice_id).toBeFalsy()
      expect(webRes?.exact_slice_id).toMatch(/^d_web_[0-9a-f]{32}$/)
      expect(webRes?.beacon_slice_id).toMatch(/^d_bcn_[0-9a-f]{32}$/)
      expect(webRes?.gpu_audio_slice_id).toMatch(/^d_gpu_[0-9a-f]{32}$/)
      expect(webRes?.sys_net_slice_id).toMatch(/^d_sys_[0-9a-f]{32}$/)

      const desktopClient = createPrismClient({
        baseUrl,
        getAccessToken: () => 'test-jwt-token-desktop',
        nativeAnchorProvider: async () => ({
          platform: 'macos',
          hw_uuid: 'FD7FC36D-E2E0-4000-8000-112233445566',
          serial_number: 'T41KH4C9TF',
          keychain_anchor: 'aabbccddeeff00112233445566778899',
          cpu_brand: 'Apple M1 Pro',
          cpu_cores: 10,
          memory_bytes: 17179869184,
          is_vm: false,
        }),
      })
      const desktopRes = await desktopClient.identify({ force: true })
      expect(desktopRes).not.toBeNull()
      expect(desktopRes?.accepted).toBe(true)
      expect(desktopRes?.is_native).toBe(true)
      expect(desktopRes?.exact_slice_id).toMatch(/^d_nat_[0-9a-f]{32}$/)
      expect(desktopRes?.keychain_slice_id).toMatch(/^d_kch_[0-9a-f]{32}$/)
      expect(desktopRes?.gpu_audio_slice_id).toBe(webRes?.gpu_audio_slice_id)
    })

    it.skipIf(!fs.existsSync(CHROME_MAC_PATH))(
      'shares one committed key across pages and handles storage loss without poisoning history',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_MAC_PATH,
          headless: true,
          args: ['--enable-webgl', '--ignore-gpu-blocklist', '--use-gl=angle'],
        })
        try {
          const context = await browser.newContext()
          const pages = await Promise.all([context.newPage(), context.newPage()])
          await Promise.all(pages.map((p) => p.goto(baseUrl)))
          const proofs = await Promise.all(pages.map((p, i) => p.evaluate(async (i) => {
            // Load in the browser realm, without Vitest's server-side import transform.
            const { signChallengeWithDeviceKey } = await new Function('return import("/prismid.bundle.js")')()
            const params = { nonce: `concurrent-${i}`, beaconId: '1234567890abcdef1234567890abcdef', staticWebGLFpHash: 'gpu', audioCompressorHash: 'audio' }
            // Also exercise same-page single-flight initialization.
            return Promise.all([signChallengeWithDeviceKey(params), signChallengeWithDeviceKey({ ...params, nonce: `other-${i}` })])
          }, i)))
          const keys = proofs.flat().map((p) => p?.pub_key)
          expect(keys.every((k) => typeof k === 'string' && k.length === 130)).toBe(true)
          expect(new Set(keys).size).toBe(1)
          const page = pages[0]
          const identify = () => page.evaluate(async () => {
            const { createPrismClient } = await new Function('return import("/prismid.bundle.js")')()
            return createPrismClient({ getAccessToken: () => 'key-recovery-browser' }).identify({ force: true })
          })
          const first = await identify()
          expect(first?.device_key_attested).toBe(true)
          expect(first?.risk_status).toBe('green')
          await page.reload()
          await page.evaluate(() => Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true }))
          const unavailable = await identify()
          expect(unavailable?.device_key_recovery_required).toBe(true)
          expect(unavailable?.risk_pending).toBe(true)
          expect(unavailable?.risk_status).toBe('unknown')
          expect(unavailable?.spoof_trap_triggered).toBe(false)
          // Restoring access to the original key restores the ordinary result; no sticky spoof.
          await page.reload()
          const restored = await identify()
          expect(restored?.device_key_slice_id).toBe(first?.device_key_slice_id)
          expect(restored?.risk_status).toBe('green')
          expect(restored?.device_key_recovery_required).not.toBe(true)
        } finally {
          await browser.close()
        }
      },
      25000
    )

    it.skipIf(!fs.existsSync(CHROME_MAC_PATH))(
      'executes real Chrome GPU WebGL fragment shader, inline Blob Worker + OffscreenCanvas, OfflineAudioContext & TextMetrics against Go server',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_MAC_PATH,
          headless: true,
          args: ['--enable-webgl', '--ignore-gpu-blocklist', '--use-gl=angle'],
        })
        try {
          const page = await browser.newPage()
          await page.goto(baseUrl, { waitUntil: 'networkidle' })

          // 1. Trigger live browser identify button
          await page.click('#btn-identify')
          await page.waitForFunction(
            () => {
              const el = document.getElementById('server-out')
              return el && el.textContent && el.textContent.includes('"accepted": true')
            },
            undefined,
            { timeout: 10000 }
          )

          const serverOutText = await page.textContent('#server-out')
          const clientOutText = await page.textContent('#client-out')
          const serverRes = JSON.parse(serverOutText || '{}')
          const clientData = JSON.parse(clientOutText || '{}')

          expect(serverRes.accepted).toBe(true)
          expect(serverRes.exact_slice_id).toMatch(/^d_web_[0-9a-f]{32}$/)
          expect(serverRes.beacon_slice_id).toMatch(/^d_bcn_[0-9a-f]{32}$/)
          expect(serverRes.gpu_audio_slice_id).toMatch(/^d_gpu_[0-9a-f]{32}$/)
          expect(serverRes.sys_net_slice_id).toMatch(/^d_sys_[0-9a-f]{32}$/)
          expect(clientData.decrypted_payload.lies.worker_unavailable).toBe(false)
          expect(clientData.decrypted_payload.lies.worker_lie_detected).toBe(false)

          // 2. Test main-thread navigator tampering caught by inline Blob Worker + OffscreenCanvas in real Chrome!
          await page.evaluate(() => {
            Object.defineProperty(navigator, 'hardwareConcurrency', {
              get: () => 64,
              configurable: true,
            })
            const el = document.getElementById('server-out')
            if (el) el.textContent = 'pending...'
          })
          await page.click('#btn-identify')
          await page.waitForFunction(
            () => {
              const el = document.getElementById('server-out')
              return el && el.textContent && el.textContent.includes('"accepted": true')
            },
            undefined,
            { timeout: 10000 }
          )
          const hookedServerOut = JSON.parse((await page.textContent('#server-out')) || '{}')
          const hookedClientOut = JSON.parse((await page.textContent('#client-out')) || '{}')

          expect(hookedClientOut.decrypted_payload.lies.worker_lie_detected).toBe(true)
          expect(hookedServerOut.accepted).toBe(true)
          expect(hookedServerOut.spoof_trap_triggered).toBe(true)
          expect(hookedServerOut.spoof_flags).toContain('worker_lie_detected')
          // And d_gpu_* is STILL identical to the unhooked run!
          expect(hookedServerOut.gpu_audio_slice_id).toBe(serverRes.gpu_audio_slice_id)

          // 3. Test 5-Silo Self-Healing Storage Beacon + 16x16 Solid-Patch Canvas Noise Trap in real Chrome!
          await page.evaluate(() => {
            // Simulate attacker clearing localStorage, sessionStorage, and cookies in DevTools
            localStorage.clear()
            sessionStorage.clear()
            document.cookie = '_prismid_bcn_v1=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'

            // Simulate AdsPower / BitBrowser / CanvasBlocker injecting +1 pixel noise into getImageData
            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData
            CanvasRenderingContext2D.prototype.getImageData = function (sx, sy, sw, sh) {
              const img = origGetImageData.call(this, sx, sy, sw, sh)
              if (img.data.length >= 4) {
                img.data[2] = (img.data[2] + 1) & 0xff
              }
              return img
            }

            const el = document.getElementById('server-out')
            if (el) el.textContent = 'pending...'
          })
          await page.click('#btn-identify')
          await page.waitForFunction(
            () => {
              const el = document.getElementById('server-out')
              return el && el.textContent && el.textContent.includes('"accepted": true')
            },
            undefined,
            { timeout: 10000 }
          )
          const healedServerOut = JSON.parse((await page.textContent('#server-out')) || '{}')
          const healedClientOut = JSON.parse((await page.textContent('#client-out')) || '{}')

          // Beacon ID must be 100% resurrected from IndexedDB / CacheStorage!
          expect(healedClientOut.decrypted_payload.beacon_id).toBe(
            clientData.decrypted_payload.beacon_id
          )
          expect(healedClientOut.decrypted_payload.lies.storage_healed).toBe(true)
          expect(healedClientOut.decrypted_payload.lies.canvas_noise_injected).toBe(true)
          expect(healedServerOut.beacon_slice_id).toMatch(/^d_bcn_[0-9a-f]{32}$/)
          expect(healedServerOut.beacon_slice_id).toBe(serverRes.beacon_slice_id)
          expect(healedServerOut.privacy_signals).toContain('storage_healed')
          expect(healedServerOut.spoof_flags).toContain('storage_healed')
          expect(healedServerOut.spoof_flags).toContain('canvas_noise_injected')
        } finally {
          await browser.close()
        }
      },
      25000
    )

    it.skipIf(!fs.existsSync(CHROME_MAC_PATH))(
      'executes authoritative FP-Scanner / AmIUnique real-Chrome multi-profile FPR & FNR matrix',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_MAC_PATH,
          headless: true,
          args: ['--enable-webgl', '--ignore-gpu-blocklist', '--use-gl=angle'],
        })
        try {
          const runProfile = async (
            subjectId: string,
            clientIp: string,
            setupFn?: () => void | Promise<void>,
            mutatePayloadFn?: (payload: Record<string, unknown>, arg?: unknown) => void,
            mutateArg?: unknown
          ) => {
            const context = await browser.newContext()
            try {
              const page = await context.newPage()
              await page.goto(baseUrl, { waitUntil: 'networkidle' })
              if (setupFn) {
                await page.evaluate(setupFn)
              }
              return await page.evaluate(
                async ({ subjectId, clientIp, mutateStr, mutateArg }) => {
                  const { createPrismClient, sealPayload } = await new Function(
                    'return import("/prismid.bundle.js")'
                  )()
                  const prism = createPrismClient({ baseUrl: '' })
                  const chRes = await fetch('/api/v1/risk/challenge', {
                    method: 'POST',
                    headers: {
                      Authorization: `Bearer ${subjectId}`,
                      'X-Forwarded-For': clientIp,
                    },
                  })
                  const ch = await chRes.json()
                  const { request, payload } = await prism.collectAndSeal(ch)
                  let wireReq = request
                  if (mutateStr) {
                    const fn = new Function('payload', 'arg', mutateStr)
                    fn(payload, mutateArg)
                    const p = await sealPayload(ch.nonce, JSON.stringify(payload))
                    wireReq = { c: ch.nonce, p }
                  }
                  const idRes = await fetch('/api/v1/risk/identify', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      Authorization: `Bearer ${subjectId}`,
                      'X-Forwarded-For': clientIp,
                    },
                    body: JSON.stringify(wireReq),
                  })
                  const verifyResult = await idRes.json()
                  return { verifyResult, payload }
                },
                {
                  subjectId,
                  clientIp,
                  mutateStr: mutatePayloadFn
                    ? `(${mutatePayloadFn.toString()})(payload, arg)`
                    : '',
                  mutateArg: mutateArg ?? null,
                }
              )
            } finally {
              await context.close()
            }
          }

          // =========================================================================
          // PART 1: REAL-CHROME BENIGN PROFILES (FPR = 0% Verification)
          // =========================================================================

          // B1: Clean Chrome Profile #1
          const b1 = await runProfile('real_chrome_benign_1', '198.51.100.11')
          expect(b1.verifyResult.accepted).toBe(true)
          expect(b1.verifyResult.device_key_bound).toBe(true)
          expect(b1.verifyResult.spoof_trap_triggered).toBe(false)
          expect(b1.verifyResult.risk_status).toBe('green')
          expect(b1.verifyResult.component_snapshot.component_subjects).toEqual([
            'real_chrome_benign_1',
          ])

          // B2: Independent Chrome Profile #2 on the EXACT SAME physical MacBook GPU (different /24 IP)
          const b2 = await runProfile('real_chrome_benign_2', '203.0.113.22')
          expect(b2.verifyResult.gpu_audio_slice_id).toBe(b1.verifyResult.gpu_audio_slice_id)
          expect(b2.verifyResult.spoof_trap_triggered).toBe(false)
          expect(b2.verifyResult.risk_status).toBe('green')
          expect(b2.verifyResult.component_snapshot.component_subjects).toEqual([
            'real_chrome_benign_2',
          ])

          // B3: Independent Chrome Profile #3 on the SAME office /24 Wi-Fi & same physical GPU as B1
          const b3 = await runProfile('real_chrome_benign_3', '198.51.100.12')
          expect(b3.verifyResult.gpu_audio_slice_id).toBe(b1.verifyResult.gpu_audio_slice_id)
          expect(b3.verifyResult.sys_net_slice_id).toBe(b1.verifyResult.sys_net_slice_id)
          expect(b3.verifyResult.spoof_trap_triggered).toBe(false)
          expect(b3.verifyResult.risk_status).toBe('green')
          expect(b3.verifyResult.component_snapshot.component_subjects).toEqual([
            'real_chrome_benign_3',
          ])

          // B4: Browser that masks WEBGL_debug_renderer_info inside Web Worker ("WebKit WebGL")
          const b4 = await runProfile(
            'real_chrome_benign_4_masked_worker',
            '192.0.2.44',
            undefined,
            (payload: any) => {
              payload.lies.worker_gpu_renderer = 'WebKit WebGL'
            }
          )
          expect(b4.verifyResult.spoof_trap_triggered).toBe(false)
          expect(b4.verifyResult.risk_status).toBe('green')

          // =========================================================================
          // PART 2: REAL-CHROME ADVERSARIAL PROFILES (FP-Scanner / Stealth FNR Test)
          // =========================================================================

          // A1: Object.defineProperty(Navigator.prototype, 'userAgent', { value: ... }) data-descriptor override
          const a1 = await runProfile('real_chrome_atk_1_data_desc', '198.18.0.10', () => {
            Object.defineProperty(Navigator.prototype, 'userAgent', {
              value:
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36',
              configurable: true,
            })
          })
          expect(a1.verifyResult.spoof_trap_triggered).toBe(true)
          expect(a1.verifyResult.risk_status).toBe('red')
          expect(a1.verifyResult.spoof_flags).toContain(
            'prototype_lie:Navigator.userAgent:data_descriptor_override'
          )

          // A2: Stealth ES6 Proxy wrapping WebGLRenderingContext.prototype.getParameter
          const a2 = await runProfile('real_chrome_atk_2_es6_proxy', '198.18.0.20', () => {
            const origGetParam = WebGLRenderingContext.prototype.getParameter
            const proxyGetParam = new Proxy(origGetParam, {
              apply(target, thisArg, args) {
                return Reflect.apply(target, thisArg, args)
              },
            })
            WebGLRenderingContext.prototype.getParameter = proxyGetParam
          })
          expect(a2.verifyResult.spoof_trap_triggered).toBe(true)
          expect(a2.verifyResult.risk_status).toBe('red')
          expect(
            a2.verifyResult.spoof_flags.some((f: string) =>
              f.includes('WebGLRenderingContext.getParameter:es6_proxy_detected')
            )
          ).toBe(true)

          // A3: ChromeDriver / Selenium CDP injection ($cdc_asdjflasutopfhvcZLmcfl_ on document)
          const a3 = await runProfile('real_chrome_atk_3_cdp_bot', '198.18.0.30', () => {
            ;(document as unknown as Record<string, unknown>).$cdc_asdjflasutopfhvcZLmcfl_ = true
          })
          expect(a3.verifyResult.spoof_trap_triggered).toBe(true)
          expect(a3.verifyResult.risk_status).toBe('red')
          expect(a3.verifyResult.spoof_flags).toContain(
            'automation:document:$cdc_asdjflasutopfhvcZLmcfl_'
          )

          // A4: Cross-OS User-Agent vs Platform contradiction (claiming Windows NT on MacIntel)
          const a4 = await runProfile(
            'real_chrome_atk_4_ua_os_mismatch',
            '198.18.0.40',
            undefined,
            (payload: any) => {
              payload.system.user_agent =
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'
              payload.lies.worker_user_agent = payload.system.user_agent
            }
          )
          expect(a4.verifyResult.spoof_trap_triggered).toBe(true)
          expect(a4.verifyResult.risk_status).toBe('red')
          expect(a4.verifyResult.spoof_flags).toContain(
            'gpu_register_law_violation:platform_ua_os_mismatch'
          )

          // A5: Stolen beacon_id from B1 replayed without B1's non-extractable private key
          const a5 = await runProfile(
            'real_chrome_atk_5_stolen_beacon',
            '198.18.0.50',
            undefined,
            (payload: any, stolenBeaconId: any) => {
              payload.beacon_id = stolenBeaconId
              delete payload.device_key
            },
            b1.payload.beacon_id
          )
          expect(a5.verifyResult.device_key_recovery_required).toBe(true)
          expect(a5.verifyResult.risk_pending).toBe(true)
          expect(a5.verifyResult.confidence).toBe(0.3)

          // And verify B1..B4 are STILL green after all 5 real-Chrome attacks on the same physical GPU!
          for (const id of [
            'real_chrome_benign_1',
            'real_chrome_benign_2',
            'real_chrome_benign_3',
            'real_chrome_benign_4_masked_worker',
          ]) {
            const expRes = await fetch(
              `${baseUrl}/api/v1/risk/explain?subject_id=${encodeURIComponent(id)}`
            )
            const snap = await expRes.json()
            expect(snap.risk_status).toBe('green')
            expect(snap.component_subjects).toEqual([id])
          }
        } finally {
          await browser.close()
        }
      },
      35000
    )
  })
})
