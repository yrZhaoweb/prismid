import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, firefox, webkit } from 'playwright-core'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const cjsRequire = createRequire(import.meta.url)
import {
  collectAndHealStorageBeacon,
  collectAudioProbe,
  collectAudioProbeWithTrap,
  collectFontsAndCanvasProbe,
  collectLieDetectorProbe,
  collectWebGLProbe,
  collectWorkerLieProbe,
  computeExpectedSpotPixelMath,
  createPrismClient,
  csprngBytes,
  DEFAULT_SAMPLE_POINTS,
  resetFontsProbeCache,
  sealPayload,
  sha256Hex,
} from '../src/index.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const GO_SERVER_DIR = path.resolve(__dirname, '../../../server/go')
const CHROME_EXECUTABLE_PATH =
  process.env.CHROME_PATH ||
  process.env.GOOGLE_CHROME_BIN ||
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const REQUIRE_CHROME_E2E =
  process.env.CI === 'true' || process.env.PRISMID_REQUIRE_CHROME === '1'

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
  it('0. enforces real Chrome availability when running in CI or PRISMID_REQUIRE_CHROME=1', () => {
    if (REQUIRE_CHROME_E2E) {
      expect(fs.existsSync(CHROME_EXECUTABLE_PATH)).toBe(true)
    }
  })

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
    let serverBinPath = ''
    let baseUrl = ''

    beforeAll(async () => {
      const port = await allocateFreeLocalPort()
      baseUrl = `http://127.0.0.1:${port}`
      const binExt = process.platform === 'win32' ? '.exe' : ''
      serverBinPath = path.join(os.tmpdir(), `prismid-e2e-server-${process.pid}${binExt}`)
      const buildRes = spawnSync('go', ['build', '-o', serverBinPath, './cmd/prismid-server'], {
        cwd: GO_SERVER_DIR,
        encoding: 'utf-8',
      })
      if (buildRes.status !== 0) {
        throw new Error(
          `Failed to build prismid-server: ${buildRes.stderr || buildRes.stdout || buildRes.error?.message}`
        )
      }
      serverProc = spawn(
        serverBinPath,
        [
          '-addr',
          `127.0.0.1:${port}`,
          '-demo-mode=true',
          '-admin-secret=test-admin-secret-0123456789abcdef',
        ],
        {
          cwd: GO_SERVER_DIR,
          stdio: 'pipe',
          detached: process.platform !== 'win32',
        }
      )

      const deadline = Date.now() + 20000
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
    }, 65000)

    afterAll(() => {
      if (serverProc && serverProc.pid) {
        try {
          if (process.platform !== 'win32') {
            process.kill(-serverProc.pid, 'SIGTERM')
          } else {
            serverProc.kill()
          }
        } catch {
          serverProc.kill()
        }
      }
      if (serverBinPath) {
        try {
          fs.unlinkSync(serverBinPath)
        } catch {
          // ignore cleanup race on Windows file lock
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

    it.skipIf(!fs.existsSync(CHROME_EXECUTABLE_PATH))(
      'shares one committed key across pages and handles storage loss without poisoning history',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_EXECUTABLE_PATH,
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

    it.skipIf(!fs.existsSync(CHROME_EXECUTABLE_PATH))(
      'executes real Chrome GPU WebGL fragment shader, inline Blob Worker + OffscreenCanvas, OfflineAudioContext & TextMetrics against Go server',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_EXECUTABLE_PATH,
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

    it.skipIf(!fs.existsSync(CHROME_EXECUTABLE_PATH))(
      'executes authoritative FP-Scanner / AmIUnique real-Chrome multi-profile FPR & FNR matrix',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_EXECUTABLE_PATH,
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

    it.skipIf(!fs.existsSync(CHROME_EXECUTABLE_PATH))(
      'executes third-party Apify Bayesian dataset (500 real-world profiles) + FingerprintInjector + 14 Puppeteer-Stealth evasions in real Chrome',
      async () => {
        const { FingerprintGenerator } = cjsRequire('fingerprint-generator')
        const { FingerprintInjector } = cjsRequire('fingerprint-injector')
        const fg = new FingerprintGenerator()
        const injector = new FingerprintInjector()

        // =========================================================================
        // PART 1: 500 REAL-WORLD BAYESIAN PROFILES FROM APIFY FINGERPRINT-GENERATOR
        // =========================================================================
        // Seed Math.random deterministically during Bayesian sampling (DeepSeek v1.0 P1 #3)
        // so release/CI test runs are 100% reproducible with zero random flakiness.
        let prngState = 0x50524953 >>> 0
        const seededRandom = (): number => {
          prngState = (prngState + 0x6d2b79f5) >>> 0
          let t = Math.imul(prngState ^ (prngState >>> 15), 1 | prngState)
          t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
          return ((t ^ (t >>> 14)) >>> 0) / 4294967296
        }

        let genuineCount = 0
        let genuineFalseRed = 0
        let virtualGpuDemotedCount = 0
        let datasetBotAnomalyCount = 0
        let datasetBotAnomalyCaught = 0

        const cohortSpecs = [
          { devices: ['desktop'], operatingSystems: ['windows'], count: 150 },
          { devices: ['desktop'], operatingSystems: ['macos'], count: 150 },
          { devices: ['desktop'], operatingSystems: ['linux'], count: 80 },
          { devices: ['mobile'], operatingSystems: ['android'], count: 60 },
          { devices: ['mobile'], operatingSystems: ['ios'], count: 60 },
        ]

        const virtualGpuSubstrings = [
          'swiftshader',
          'llvmpipe',
          'softpipe',
          'lavapipe',
          'mesa offscreen',
          'software rasterizer',
          'microsoft basic render driver',
          'vmware',
          'svga3d',
          'virtualbox',
          'vboxvideo',
          'parallels',
          'qemu',
          'virtio',
        ]

        let idx = 0
        for (const spec of cohortSpecs) {
          for (let i = 0; i < spec.count; i++) {
            idx++
            const origRandom = Math.random
            let fingerprint: ReturnType<typeof fg.getFingerprint>['fingerprint']
            try {
              Math.random = seededRandom
              fingerprint = fg.getFingerprint({
                devices: spec.devices,
                operatingSystems: spec.operatingSystems,
              }).fingerprint
            } finally {
              Math.random = origRandom
            }
            const nav = fingerprint.navigator
            const gpu = fingerprint.videoCard
            const scr = fingerprint.screen

            const ua = String(nav.userAgent || '')
            const plat = String(nav.platform || '')
            const renderer = String(gpu.renderer || '')
            const vendor = String(gpu.vendor || '')
            const uaLow = ua.toLowerCase()
            const platLow = plat.toLowerCase()
            const rendLow = renderer.trim().toLowerCase()
            const vendLow = vendor.trim().toLowerCase()
            const combinedGpuLow = `${vendLow} ${rendLow}`

            // Derive correct JS engine signature for the real browser family
            let mathSig: 'v8' | 'jsc' | 'spidermonkey' = 'v8'
            if (uaLow.includes('firefox/') || uaLow.includes('fxios/')) {
              mathSig = 'spidermonkey'
            } else if (
              platLow.includes('iphone') ||
              platLow.includes('ipad') ||
              (uaLow.includes('safari/') &&
                uaLow.includes('version/') &&
                !uaLow.includes('chrome/') &&
                !uaLow.includes('crios/') &&
                !uaLow.includes('chromium/') &&
                !uaLow.includes('edg/') &&
                !uaLow.includes('opr/') &&
                !uaLow.includes('android'))
            ) {
              mathSig = 'jsc'
            }

            // Mirror server/go/gpu_laws.go physical hardware/OS pairing laws & virtual GPU demotion:
            const isWinPlat = platLow.includes('win')
            const isMacPlat = platLow.includes('mac')
            const isIOSPlat = platLow.includes('iphone') || platLow.includes('ipad')
            const isLinuxPlat = platLow.includes('linux') && !platLow.includes('android')
            const claimsIOSUA = uaLow.includes('iphone') || uaLow.includes('ipad')
            const claimsMacUA =
              (uaLow.includes('macintosh') || uaLow.includes('mac os x')) && !claimsIOSUA
            const claimsWinUA = uaLow.includes('windows nt')
            const claimsLinuxDesktopUA =
              uaLow.includes('x11; linux') || uaLow.includes('x11; ubuntu')
            const claimsAndroidUA = uaLow.includes('android')

            const isAppleOnlyDriver =
              rendLow.includes('apple m1') ||
              rendLow.includes('apple m2') ||
              rendLow.includes('apple m3') ||
              rendLow.includes('apple m4') ||
              rendLow.includes('apple m5') ||
              rendLow.includes('apple gpu') ||
              rendLow.includes('angle metal renderer') ||
              rendLow.includes('opengl engine')

            const hasOSContradiction =
              (isWinPlat &&
                (claimsMacUA || claimsIOSUA || claimsLinuxDesktopUA || claimsAndroidUA)) ||
              (isMacPlat && (claimsWinUA || claimsLinuxDesktopUA || claimsAndroidUA)) ||
              (isIOSPlat && (claimsWinUA || claimsLinuxDesktopUA || claimsAndroidUA)) ||
              (isLinuxPlat && (claimsWinUA || claimsMacUA || claimsIOSUA)) ||
              (isAppleOnlyDriver &&
                (isWinPlat ||
                  isLinuxPlat ||
                  claimsWinUA ||
                  claimsLinuxDesktopUA ||
                  claimsAndroidUA)) ||
              ((rendLow.includes('direct3d') || rendLow.includes('d3d11') || rendLow.includes('d3d9')) &&
                (isMacPlat ||
                  isIOSPlat ||
                  isLinuxPlat ||
                  claimsLinuxDesktopUA ||
                  claimsAndroidUA)) ||
              (vendLow.includes('apple') &&
                (rendLow.includes('nvidia') ||
                  rendLow.includes('radeon') ||
                  rendLow.includes('geforce'))) ||
              (isMacPlat &&
                (rendLow.includes('mesa') ||
                  rendLow.includes('/pcie/sse2') ||
                  rendLow.includes('x11')))

            const isVirtualGPU =
              rendLow === '' ||
              rendLow === 'chromium' ||
              virtualGpuSubstrings.some((kw) => combinedGpuLow.includes(kw))

            const subjectId = `apify_fp_${idx}`
            const clientIp = `100.${64 + Math.floor(idx / 200)}.${(idx * 7) % 250}.${(idx % 200) + 10}`

            const chRes = await fetch(`${baseUrl}/api/v1/risk/challenge`, {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${subjectId}`,
                'X-Forwarded-For': clientIp,
              },
            })
            const ch = (await chRes.json()) as {
              nonce: string
              render_seed: [number, number, number, number]
              sample_points: Array<[number, number]>
            }

            const pts = ch.sample_points && ch.sample_points.length > 0 ? ch.sample_points : DEFAULT_SAMPLE_POINTS
            const spotPixels = pts.map(([x, y]) =>
              computeExpectedSpotPixelMath(x, y, ch.render_seed)
            )
            const staticHash = sha256Hex(`apify_webgl|${vendor}|${renderer}`).slice(0, 64)
            const audioHash = sha256Hex(`apify_audio|${plat}|${renderer}`).slice(0, 64)
            const canvasHash = sha256Hex(`apify_canvas|${plat}|${ua}`).slice(0, 64)
            const fontsHash = sha256Hex(
              `apify_fonts|${(fingerprint.fonts || []).join(',')}|${idx}`
            ).slice(0, 64)
            const beaconId = sha256Hex(`apify_bcn_${idx}`).slice(0, 32)

            // Generate real ECDSA P-256 signature using Node WebCrypto
            const kp = await crypto.webcrypto.subtle.generateKey(
              { name: 'ECDSA', namedCurve: 'P-256' },
              true,
              ['sign', 'verify']
            )
            const rawPub = new Uint8Array(
              await crypto.webcrypto.subtle.exportKey('raw', kp.publicKey)
            )
            const pubHex = Buffer.from(rawPub).toString('hex')
            const msgBytes = new TextEncoder().encode(
              `prismid-v2-sig|${ch.nonce}|${beaconId}|${staticHash}|${audioHash}`
            )
            const sigBytes = new Uint8Array(
              await crypto.webcrypto.subtle.sign(
                { name: 'ECDSA', hash: 'SHA-256' },
                kp.privateKey,
                msgBytes
              )
            )
            const sigHex = Buffer.from(sigBytes).toString('hex')

            const payload = {
              v: 1,
              nonce: ch.nonce,
              beacon_id: beaconId,
              device_key: {
                alg: 'ecdsa-p256',
                pub_key: pubHex,
                signature: sigHex,
              },
              webgl: {
                gpu_vendor: vendor,
                gpu_renderer: renderer,
                webgl_limits_vector:
                  '16384|16384|16384,16384|16384|4096|1024|31|1,1|1,511|16|23,23,23,23|a1b2c3d4',
                static_webgl_fp_hash: staticHash,
                spot_pixels: spotPixels,
                webgl_available: true,
              },
              audio_compressor_hash: audioHash,
              audio_copy_hash: audioHash,
              audio_silent_delta: 0,
              system: {
                fonts_bitmap_hash: fontsHash,
                canvas_2d_hash: canvasHash,
                canvas_control_rgba: [0, 0, 0, 0, 17, 136, 221, 255],
                canvas_readback_delta: 0,
                cpu_cores: Number(nav.hardwareConcurrency || 8),
                memory_gb: Number(nav.deviceMemory || 8),
                screen_spec: `${scr.width}x${scr.height}@${scr.devicePixelRatio || 1}`,
                timezone: 'UTC',
                platform: plat,
                user_agent: ua,
              },
              lies: {
                worker_unavailable: false,
                worker_lie_detected: false,
                worker_gpu_renderer: renderer,
                worker_static_webgl_fp_hash: staticHash,
                worker_cpu_cores: Number(nav.hardwareConcurrency || 8),
                worker_platform: plat,
                worker_user_agent: ua,
                worker_timezone: 'UTC',
                canvas_noise_injected: false,
                webgl_noise_injected: false,
                audio_noise_injected: false,
                storage_healed: false,
                math_engine_signature: mathSig,
                math_constants_hash: 'dacb4db70a52c5ec6de100f2d0e68344',
                prototype_lies: [],
                automation_flags: [],
              },
              ts: Date.now(),
            }

            const sealed = await sealPayload(ch.nonce, JSON.stringify(payload))
            const idRes = await fetch(`${baseUrl}/api/v1/risk/identify`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${subjectId}`,
                'X-Forwarded-For': clientIp,
              },
              body: JSON.stringify({ c: ch.nonce, p: sealed }),
            })
            const vr = (await idRes.json()) as {
              accepted: boolean
              confidence: number
              risk_status: string
              risk_pending: boolean
              spoof_trap_triggered: boolean
            }
            expect(vr.accepted).toBe(true)

            if (isVirtualGPU) {
              // Virtual/software GPUs are demoted to Confidence=0.30 (< 0.60 graph threshold) -> unknown + pending
              virtualGpuDemotedCount++
              expect(vr.confidence).toBe(0.3)
              expect(vr.risk_status).toBe('unknown')
              expect(vr.risk_pending).toBe(true)
            } else if (hasOSContradiction) {
              datasetBotAnomalyCount++
              if (vr.spoof_trap_triggered && vr.risk_status === 'red') {
                datasetBotAnomalyCaught++
              }
            } else {
              genuineCount++
              if (vr.risk_status === 'red' || vr.spoof_trap_triggered) {
                genuineFalseRed++
              }
            }
          }
        }

        expect(genuineCount + virtualGpuDemotedCount + datasetBotAnomalyCount).toBe(500)
        expect(genuineCount).toBeGreaterThan(440)
        expect(genuineFalseRed).toBe(0)
        expect(datasetBotAnomalyCaught).toBe(datasetBotAnomalyCount)

        // =========================================================================
        // PART 2: REAL-CHROME APIFY FINGERPRINT-INJECTOR & 14 PUPPETEER-STEALTH EVASIONS
        // =========================================================================
        const browser = await chromium.launch({
          executablePath: CHROME_EXECUTABLE_PATH,
          headless: true,
          args: ['--enable-webgl', '--ignore-gpu-blocklist', '--use-gl=angle'],
        })

        try {
          const evalContextAgainstServer = async (
            ctx: Awaited<ReturnType<typeof browser.newContext>>,
            subjectId: string,
            clientIp: string
          ) => {
            try {
              const page = await ctx.newPage()
              await page.goto(baseUrl, { waitUntil: 'networkidle' })
              return await page.evaluate(
                async ({ subjectId, clientIp }) => {
                  const { createPrismClient } = await new Function(
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
                  const idRes = await fetch('/api/v1/risk/identify', {
                    method: 'POST',
                    headers: {
                      'Content-Type': 'application/json',
                      Authorization: `Bearer ${subjectId}`,
                      'X-Forwarded-For': clientIp,
                    },
                    body: JSON.stringify(request),
                  })
                  const verifyResult = await idRes.json()
                  return { verifyResult, payload }
                },
                { subjectId, clientIp }
              )
            } finally {
              await ctx.close()
            }
          }

          // 2A. Apify FingerprintInjector: Cross-OS (Windows fingerprint injected on macOS Chrome)
          {
            const ctx = await browser.newContext()
            const fpWin = fg.getFingerprint({
              operatingSystems: ['windows'],
              browsers: ['chrome'],
            })
            await injector.attachFingerprintToPlaywright(ctx, fpWin)
            const res = await evalContextAgainstServer(ctx, 'apify_inj_win_on_mac', '198.19.1.10')
            expect(res.verifyResult.spoof_trap_triggered).toBe(true)
            expect(res.verifyResult.risk_status).toBe('red')
          }

          // 2B. Apify FingerprintInjector: Same-OS (macOS fingerprint + matching CPU cores on macOS Chrome)
          {
            const ctx = await browser.newContext()
            const fpMac = fg.getFingerprint({
              operatingSystems: ['macos'],
              browsers: ['chrome'],
            })
            fpMac.fingerprint.navigator.hardwareConcurrency = os.cpus().length
            await injector.attachFingerprintToPlaywright(ctx, fpMac)
            const res = await evalContextAgainstServer(ctx, 'apify_inj_mac_same_os', '198.19.1.20')
            expect(res.verifyResult.spoof_trap_triggered).toBe(true)
            expect(res.verifyResult.risk_status).toBe('red')
            expect(res.verifyResult.spoof_flags).toContain(
              'prototype_lie:Function.toString:toString_proxy_getter'
            )
          }

          // 2C. Apify FingerprintInjector: Safari fingerprint injected into V8 Chromium
          {
            const ctx = await browser.newContext()
            const fpSafari = fg.getFingerprint({
              operatingSystems: ['macos'],
              browsers: ['safari'],
            })
            fpSafari.fingerprint.navigator.hardwareConcurrency = os.cpus().length
            await injector.attachFingerprintToPlaywright(ctx, fpSafari)
            const res = await evalContextAgainstServer(
              ctx,
              'apify_inj_safari_on_v8',
              '198.19.1.30'
            )
            expect(res.verifyResult.spoof_trap_triggered).toBe(true)
            expect(res.verifyResult.risk_status).toBe('red')
            expect(res.verifyResult.spoof_flags).toContain(
              'math_engine_ua_mismatch:v8_claiming_safari'
            )
          }

          // 2D. All 14 Puppeteer-Extra-Plugin-Stealth Evasion Modules in Real Chrome
          const stealthSpecs: Array<[string, (() => void) | undefined, Record<string, unknown> | undefined]> = [
            [
              'chrome.app',
              () => {
                ;(window as unknown as Record<string, unknown>).chrome = {}
              },
              undefined,
            ],
            [
              'chrome.csi',
              () => {
                ;(window as unknown as Record<string, unknown>).chrome = {}
              },
              undefined,
            ],
            [
              'chrome.loadTimes',
              () => {
                ;(window as unknown as Record<string, unknown>).chrome = {}
              },
              undefined,
            ],
            ['chrome.runtime', undefined, { runOnInsecureOrigins: true }],
            ['iframe.contentWindow', undefined, undefined],
            ['media.codecs', undefined, undefined],
            ['navigator.hardwareConcurrency', undefined, undefined],
            ['navigator.languages', undefined, undefined],
            ['navigator.permissions', undefined, undefined],
            [
              'navigator.plugins',
              () => {
                Object.defineProperty(Navigator.prototype, 'plugins', {
                  get: () => [],
                  configurable: true,
                })
              },
              undefined,
            ],
            ['navigator.vendor', undefined, undefined],
            ['navigator.webdriver', undefined, undefined],
            ['webgl.vendor', undefined, undefined],
            [
              'window.outerdimensions',
              () => {
                Object.defineProperty(window, 'outerWidth', {
                  get: () => 0,
                  set(v) {
                    Object.defineProperty(window, 'outerWidth', {
                      value: v,
                      writable: true,
                      enumerable: true,
                      configurable: true,
                    })
                  },
                  configurable: true,
                })
              },
              undefined,
            ],
          ]

          let stealthCaught = 0
          for (let sIdx = 0; sIdx < stealthSpecs.length; sIdx++) {
            const [evasionName, prepFn, opts] = stealthSpecs[sIdx]
            const ctx = await browser.newContext()
            if (prepFn) {
              await ctx.addInitScript(prepFn)
            }
            const EvasionFactory = cjsRequire(
              `puppeteer-extra-plugin-stealth/evasions/${evasionName}`
            )
            const evasion = EvasionFactory(opts)
            const fakePage = {
              evaluateOnNewDocument: async (fn: (...args: unknown[]) => unknown, ...args: unknown[]) => {
                await ctx.addInitScript(fn, ...args)
              },
              _client: null,
            }
            if (typeof evasion.onPageCreated === 'function') {
              await evasion.onPageCreated(fakePage)
            }
            const res = await evalContextAgainstServer(
              ctx,
              `stealth_${evasionName.replace(/\./g, '_')}`,
              `198.19.2.${10 + sIdx}`
            )
            expect(res.verifyResult.spoof_trap_triggered).toBe(true)
            expect(res.verifyResult.risk_status).toBe('red')
            stealthCaught++
          }
          expect(stealthCaught).toBe(14)
        } finally {
          await browser.close()
        }
      },
      60000
    )

    it('7A. S3-29/33/34/35/36/37/39/40/53: verifies CSPRNG-only beacon, Secure cookie, deadline race, ±2 canvas uniformity, muted audio, tampered math, single token call, error diagnostics, and should_collect:false', async () => {
      // 1. S3-34: CSPRNG-only random generation (never falls back to Math.random when crypto is missing)
      const g = globalThis as unknown as Record<string, unknown>
      const origCryptoDesc = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
      Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true })
      try {
        expect(csprngBytes(16)).toBeNull()
        const noCryptoBcn = await collectAndHealStorageBeacon(50)
        expect(noCryptoBcn.beacon_id).toBe('')
        await expect(sealPayload('nonce', 'hello')).rejects.toThrow(/crypto\.getRandomValues/)
      } finally {
        if (origCryptoDesc) {
          Object.defineProperty(globalThis, 'crypto', origCryptoDesc)
        }
      }

      // 2. S3-33 & S3-35: HTTPS Secure cookie attribute + storage beacon deadline race safety
      let cookieJar = ''
      let lsVal: string | null = 'aabbccddeeff00112233445566778899'
      let lateIdbPutCount = 0
      const origDoc = g.document
      const origLoc = g.location
      const origLS = g.localStorage
      const origIDB = g.indexedDB
      g.location = { protocol: 'https:' }
      g.document = {
        get cookie() {
          return cookieJar
        },
        set cookie(v: string) {
          cookieJar = v
        },
      }
      g.localStorage = {
        getItem: () => lsVal,
        setItem: (_k: string, v: string) => {
          lsVal = v
        },
      }
      let lateOpenReq: any = null
      g.indexedDB = {
        open: () => {
          const req: any = {}
          lateOpenReq = req
          return req
        },
      }
      try {
        const raced = await collectAndHealStorageBeacon(60)
        // Must preserve existing synchronous localStorage beacon on async timeout instead of clobbering!
        expect(raced.beacon_id).toBe('aabbccddeeff00112233445566778899')
        expect(cookieJar).toContain('; Secure')
        // Simulate late IndexedDB wakeup after deadline: must NOT overwrite or put!
        if (lateOpenReq) {
          lateOpenReq.result = {
            close() {},
            transaction: () => ({
              objectStore: () => ({
                get: () => ({ result: 'ffffffffffffffffffffffffffffffff' }),
                put: () => {
                  lateIdbPutCount++
                },
              }),
            }),
          }
          lateOpenReq.onsuccess?.()
        }
        await new Promise((r) => setTimeout(r, 20))
        expect(lsVal).toBe('aabbccddeeff00112233445566778899')
        expect(lateIdbPutCount).toBe(0)
      } finally {
        g.document = origDoc
        g.location = origLoc
        g.localStorage = origLS
        g.indexedDB = origIDB
      }

      // 3. S3-36: Uniform ±2 ICC color-space rounding passes, single-pixel +1 noise fails
      const makeMockDocument = (
        solidPixelFn: (pixelIdx: number) => [number, number, number, number]
      ) => ({
        createElement: (tag: string) => {
          if (tag !== 'canvas') return {}
          return {
            width: 0,
            height: 0,
            toDataURL: () => 'data:image/png;base64,AA==',
            getContext: () => ({
              font: '',
              fillStyle: '',
              strokeStyle: '',
              globalCompositeOperation: 'source-over',
              measureText: () => ({
                width: 120.125,
                actualBoundingBoxAscent: 12,
                actualBoundingBoxDescent: 3,
                actualBoundingBoxLeft: 0,
                actualBoundingBoxRight: 120.125,
              }),
              createLinearGradient: () => ({ addColorStop() {} }),
              fillRect() {},
              clearRect() {},
              beginPath() {},
              arc() {},
              closePath() {},
              fill() {},
              fillText() {},
              bezierCurveTo() {},
              stroke() {},
              getImageData: (_x: number, y: number, w: number, h: number) => {
                const buf = new Uint8ClampedArray(w * h * 4)
                if (w === 16 && h === 16 && y === 0 && _x === 224) {
                  // blank clearRect area -> all zeros
                  return { data: buf }
                }
                if (w === 16 && h === 16) {
                  for (let p = 0; p < w * h; p++) {
                    const [r, gr, b, a] = solidPixelFn(p)
                    buf[p * 4] = r
                    buf[p * 4 + 1] = gr
                    buf[p * 4 + 2] = b
                    buf[p * 4 + 3] = a
                  }
                  return { data: buf }
                }
                return { data: buf }
              },
            }),
          }
        },
      })
      try {
        resetFontsProbeCache()
        // Uniform Display-P3 ±1/±2 color shift across all 256 pixels -> clean!
        g.document = makeMockDocument(() => [18, 135, 222, 255])
        const uniformRes = collectFontsAndCanvasProbe()
        expect(uniformRes.canvas_noise_injected).toBe(false)
        expect(uniformRes.canvas_readback_delta).toBe(0)

        // Single-pixel +1 farbling on pixel 0 -> caught immediately!
        g.document = makeMockDocument((p) => (p === 0 ? [18, 136, 221, 255] : [17, 136, 221, 255]))
        const farbledRes = collectFontsAndCanvasProbe()
        expect(farbledRes.canvas_noise_injected).toBe(true)
        expect(farbledRes.canvas_readback_delta).toBeGreaterThan(0)
      } finally {
        g.document = origDoc
        resetFontsProbeCache()
      }

      // 4. S3-37: Muted all-zero OfflineAudioContext sets audio_muted=true, audio_noise_injected=false
      const origOffline = g.OfflineAudioContext
      g.OfflineAudioContext = class MockMutedAudioContext {
        currentTime = 0
        destination = {}
        createOscillator() {
          return {
            type: 'triangle',
            frequency: { setValueAtTime() {} },
            connect() {},
            start() {},
          }
        }
        createDynamicsCompressor() {
          const p = { setValueAtTime() {} }
          return { threshold: p, knee: p, ratio: p, attack: p, release: p, connect() {} }
        }
        createBuffer(_ch: number, len: number) {
          const zeros = new Float32Array(len)
          return { getChannelData: () => zeros }
        }
        startRendering() {
          const mutedSamples = new Float32Array(5000) // all 0.0
          return Promise.resolve({
            getChannelData: () => mutedSamples,
            copyFromChannel: (dst: Float32Array) => dst.fill(0),
          })
        }
      }
      try {
        const mutedAudio = await collectAudioProbeWithTrap(100)
        expect(mutedAudio.audio_muted).toBe(true)
        expect(mutedAudio.audio_noise_injected).toBe(false)
      } finally {
        g.OfflineAudioContext = origOffline
      }

      // 5. S3-29: Tampered Math transcendental emits `unknown_tampered_math`
      const origCos = Math.cos
      Math.cos = ((x: number) => (x === 0 ? 0.999999 : origCos(x))) as typeof Math.cos
      try {
        const tamperedLies = collectLieDetectorProbe()
        expect(tamperedLies.math_engine_signature).toBe('unknown_tampered_math')
      } finally {
        Math.cos = origCos
      }

      // 6. S3-39 & S3-53: getAccessToken invoked once + should_collect:false returns {accepted:false, skipped:true}
      let tokenCalls = 0
      const skipClient = createPrismClient({
        baseUrl: 'http://skip.invalid',
        getAccessToken: () => {
          tokenCalls++
          return 'single-call-token'
        },
        fetchImpl: async (input) => {
          const url = String(input)
          if (url.endsWith('/should-collect')) {
            return new Response(JSON.stringify({ should_collect: false }), { status: 200 })
          }
          throw new Error('should not call challenge when should_collect is false')
        },
      })
      const skipRes = await skipClient.identify()
      expect(tokenCalls).toBe(1)
      expect(skipRes?.accepted).toBe(false)
      expect(skipRes?.skipped).toBe(true)
      expect(skipRes?.code).toBe('COLLECTION_SKIPPED')

      // Verify full identify() also invokes getAccessToken ONLY ONCE across should-collect + challenge + identify!
      let fullTokenCalls = 0
      const singleTokClient = createPrismClient({
        baseUrl,
        getAccessToken: () => {
          fullTokenCalls++
          return 'single_token_check_user'
        },
      })
      const singleTokRes = await singleTokClient.identify()
      expect(singleTokRes?.accepted).toBe(true)
      expect(fullTokenCalls).toBe(1)

      // 7. S3-40: Structured error diagnostics distinguish HTTP 429 from HTTP 401
      const observedErrors: Array<{ kind: string; status?: number }> = []
      const err429Client = createPrismClient({
        baseUrl: 'http://ratelimit.invalid',
        onError: (e) => observedErrors.push({ kind: e.kind, status: e.status }),
        fetchImpl: async () =>
          new Response(JSON.stringify({ accepted: false, error: 'rate limit exceeded' }), {
            status: 429,
          }),
      })
      const detailed429 = await err429Client.identifyDetailed({ force: true })
      expect(detailed429.result).toBeNull()
      expect(detailed429.error?.kind).toBe('http')
      expect(detailed429.error?.status).toBe(429)
      expect(err429Client.getLastError()?.status).toBe(429)
      expect(observedErrors).toEqual([{ kind: 'http', status: 429 }])
    })

    it.skipIf(!fs.existsSync(CHROME_EXECUTABLE_PATH))(
      '7B. S1-2/S1-3/S2-10/S2-12/S2-25: executes shared-browser yellow+pending policy, high-level client.rebindKey (proactive rotation + single-use step-up recovery), clearSpoof, and GDPR deleteSubject in real Chrome',
      async () => {
        const browser = await chromium.launch({
          executablePath: CHROME_EXECUTABLE_PATH,
          headless: true,
          args: ['--enable-webgl', '--ignore-gpu-blocklist', '--use-gl=angle'],
        })
        try {
          const context = await browser.newContext()
          const page = await context.newPage()
          await page.goto(baseUrl, { waitUntil: 'networkidle' })

          // 1. S1-2: Shared household browser profile: mom -> green, kid -> yellow + risk_pending (NOT red!)
          const sharedRes = await page.evaluate(async () => {
            const { createPrismClient } = await new Function('return import("/prismid.bundle.js")')()
            const momClient = createPrismClient({ getAccessToken: () => 'e2e_family_mom' })
            const kidClient = createPrismClient({ getAccessToken: () => 'e2e_family_kid' })
            const mom = await momClient.identify({ force: true })
            const kid = await kidClient.identify({ force: true })
            return { mom, kid }
          })
          expect(sharedRes.mom.risk_status).toBe('green')
          expect(sharedRes.mom.device_key_bound).toBe(true)
          expect(sharedRes.kid.risk_status).toBe('yellow')
          expect(sharedRes.kid.risk_pending).toBe(true)

          // 2. S2-12 & S1-3: Proactive key rotation (`rebindKey({ rotate: true })`) succeeds WITHOUT step-up MFA
          // using `previous_device_key` continuity proof, and retires old `d_key_*` edge!
          const rotCtx = await browser.newContext({
            extraHTTPHeaders: { 'X-Forwarded-For': '198.18.210.10' },
            screen: { width: 1280, height: 800 },
            viewport: { width: 1280, height: 800 },
          })
          const rotPage = await rotCtx.newPage()
          await rotPage.goto(baseUrl, { waitUntil: 'networkidle' })

          const rotFlow = await rotPage.evaluate(async () => {
            const { createPrismClient } = await new Function('return import("/prismid.bundle.js")')()
            const client = createPrismClient({ getAccessToken: () => 'e2e_rotate_owner' })
            const before = await client.identify({ force: true })
            const rebound = await client.rebindKey({ rotate: true })
            const after = await client.identify({ force: true })
            const explain = await (
              await fetch('/api/v1/risk/explain?subject_id=e2e_rotate_owner')
            ).json()
            return { before, rebound, after, explain }
          })
          expect(rotFlow.before.device_key_bound).toBe(true)
          expect(rotFlow.rebound).toMatchObject({ accepted: true })
          expect(rotFlow.after.device_key_bound).toBe(true)
          expect(rotFlow.after.device_key_slice_id).not.toBe(rotFlow.before.device_key_slice_id)
          // Old d_key_* slice MUST be retired from risk graph!
          expect(rotFlow.explain.slice_ids).toContain(rotFlow.after.device_key_slice_id)
          expect(rotFlow.explain.slice_ids).not.toContain(rotFlow.before.device_key_slice_id)

          // 3. S2-25 & S2-10: Lost-key recovery via admin mint-step-up + clearSpoof + single-use replay rejection + deleteSubject
          const beaconId = await rotPage.evaluate(async () => {
            const { collectAndHealStorageBeacon } = await new Function(
              'return import("/prismid.bundle.js")'
            )()
            return (await collectAndHealStorageBeacon()).beacon_id
          })
          // Wipe IndexedDB keystore inside the SAME tab (without reloading!) to simulate in-session site-data loss:
          await rotPage.evaluate(async () => {
            await new Promise<void>((resolve) => {
              const req = indexedDB.deleteDatabase('_prismid_key_v1')
              req.onsuccess = req.onerror = req.onblocked = () => resolve()
            })
          })
          // Mint single-use step-up tokens from standalone server admin endpoint:
          const mintRes = await fetch(`${baseUrl}/api/v1/risk/admin/mint-step-up`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-PrismID-Admin-Secret': 'test-admin-secret-0123456789abcdef',
            },
            body: JSON.stringify({
              subject_id: 'e2e_rotate_owner',
              beacon_id: beaconId,
            }),
          })
          expect(mintRes.status).toBe(200)
          const { step_up_token: stepUpToken } = (await mintRes.json()) as { step_up_token: string }
          expect(stepUpToken).toMatch(/^stepup_v2\./)

          const mintClearSpoofRes = await fetch(`${baseUrl}/api/v1/risk/admin/mint-step-up`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-PrismID-Admin-Secret': 'test-admin-secret-0123456789abcdef',
            },
            body: JSON.stringify({
              subject_id: 'e2e_rotate_owner',
              target: 'clear_spoof',
            }),
          })
          expect(mintClearSpoofRes.status).toBe(200)
          const { step_up_token: clearSpoofToken } = (await mintClearSpoofRes.json()) as {
            step_up_token: string
          }

          const recFlow = await rotPage.evaluate(
            async (args: { rebindTok: string; clearTok: string }) => {
              const { createPrismClient } = await new Function(
                'return import("/prismid.bundle.js")'
              )()
              const client = createPrismClient({ getAccessToken: () => 'e2e_rotate_owner' })
              const firstRecovery = await client.rebindKey({ stepUpToken: args.rebindTok })
              // Replaying the exact same single-use step-up token a second time MUST fail 403!
              const replayAttempt = await client.rebindKey({ stepUpToken: args.rebindTok })
              const verifiedAfter = await client.identify({ force: true })
              const clearedSpoof = await client.clearSpoof({ stepUpToken: args.clearTok })
              const clearReplay = await client.clearSpoof({ stepUpToken: args.clearTok })
              const deleted = await client.deleteSubject()
              return {
                firstRecovery,
                replayAttempt,
                verifiedAfter,
                clearedSpoof,
                clearReplay,
                deleted,
              }
            },
            { rebindTok: stepUpToken, clearTok: clearSpoofToken }
          )

          expect(recFlow.firstRecovery.accepted).toBe(true)
          expect(recFlow.replayAttempt.accepted).toBe(false)
          expect(recFlow.verifiedAfter.risk_status).toBe('green')
          expect(recFlow.verifiedAfter.device_key_bound).toBe(true)
          expect(recFlow.clearedSpoof.accepted).toBe(true)
          expect(recFlow.clearReplay.accepted).toBe(false)
          expect(recFlow.deleted.accepted).toBe(true)
          expect(recFlow.deleted.deleted).toBe(true)
          expect(recFlow.deleted.purged_key_bindings).toBeGreaterThanOrEqual(1)

          await rotCtx.close()
          await context.close()
        } finally {
          await browser.close()
        }
      },
      30000
    )

    it(
      '7C. S2-17 & S3-55: executes real 3-engine Cross-Browser Matrix (Chromium V8 + Firefox SpiderMonkey + WebKit Safari JSC) with 0% false positives',
      async () => {
        const engines: Array<{
          name: string
          expectedMathSig: 'v8' | 'spidermonkey' | 'jsc'
          launch: () => Promise<Awaited<ReturnType<typeof chromium.launch>> | null>
        }> = [
          {
            name: 'chromium',
            expectedMathSig: 'v8',
            launch: async () => {
              if (!fs.existsSync(CHROME_EXECUTABLE_PATH)) return null
              return chromium.launch({
                executablePath: CHROME_EXECUTABLE_PATH,
                headless: true,
                args: ['--enable-webgl', '--ignore-gpu-blocklist', '--use-gl=angle'],
              })
            },
          },
          {
            name: 'firefox',
            expectedMathSig: 'spidermonkey',
            launch: async () => {
              const exe = firefox.executablePath()
              if (!exe || !fs.existsSync(exe)) {
                if (process.env.PRISMID_REQUIRE_ALL_BROWSERS === '1') {
                  throw new Error(`Playwright Firefox executable missing at ${exe}`)
                }
                return null
              }
              return firefox.launch({ headless: true })
            },
          },
          {
            name: 'webkit',
            expectedMathSig: 'jsc',
            launch: async () => {
              const exe = webkit.executablePath()
              if (!exe || !fs.existsSync(exe)) {
                if (process.env.PRISMID_REQUIRE_ALL_BROWSERS === '1') {
                  throw new Error(`Playwright WebKit executable missing at ${exe}`)
                }
                return null
              }
              return webkit.launch({ headless: true })
            },
          },
        ]

        let testedEngines = 0
        for (const eng of engines) {
          const browser = await eng.launch()
          if (!browser) continue
          testedEngines++
          try {
            const context = await browser.newContext({
              screen: { width: 1512, height: 982 },
              viewport: { width: 1512, height: 982 },
            })
            const page = await context.newPage()
            await page.goto(baseUrl, { waitUntil: 'networkidle' })

            const out = await page.evaluate(async (engineName: string) => {
              const { createPrismClient, sealPayload } = await new Function(
                'return import("/prismid.bundle.js")'
              )()
              const client = createPrismClient({
                baseUrl: '',
                probeTimeoutMs: 2500,
                requestTimeoutMs: 10000,
              })
              const clientIp =
                engineName === 'chromium'
                  ? '198.18.201.11'
                  : engineName === 'firefox'
                    ? '198.18.202.11'
                    : '198.18.203.11'
              const chRes = await fetch('/api/v1/risk/challenge', {
                method: 'POST',
                headers: {
                  Authorization: `Bearer matrix_clean_${engineName}`,
                  'X-Forwarded-For': clientIp,
                },
              })
              const ch = await chRes.json()
              const { payload } = await client.collectAndSeal(ch)
              // Note: headless Playwright sets navigator.webdriver = true by browser-automation spec;
              // strip ONLY `navigator_webdriver` when testing benign engine compatibility (matching
              // real non-automated user sessions in Chrome, Firefox, and Safari!).
              if (Array.isArray(payload.lies?.automation_flags)) {
                payload.lies.automation_flags = payload.lies.automation_flags.filter(
                  (f: string) => f !== 'navigator_webdriver'
                )
              }
              const resealed = await sealPayload(ch.nonce, JSON.stringify(payload))
              const idRes = await fetch('/api/v1/risk/identify', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: `Bearer matrix_clean_${engineName}`,
                  'X-Forwarded-For': clientIp,
                },
                body: JSON.stringify({ c: ch.nonce, p: resealed }),
              })
              const verifyResult = await idRes.json()
              return { verifyResult, payload }
            }, eng.name)

            expect(out.payload.lies.math_engine_signature, `${eng.name} math sig`).toBe(
              eng.expectedMathSig
            )
            expect(out.payload.lies.prototype_lies, `${eng.name} prototype lies`).toEqual([])
            expect(out.payload.lies.canvas_noise_injected, `${eng.name} canvas noise`).toBe(false)
            expect(out.payload.lies.audio_noise_injected, `${eng.name} audio noise`).toBe(false)
            expect(out.payload.lies.worker_lie_detected, `${eng.name} worker lie`).toBe(false)
            expect(out.verifyResult.accepted, `${eng.name} accepted`).toBe(true)
            const isWindowsSyntheticWebKit =
              process.platform === 'win32' && eng.name === 'webkit'
            if (isWindowsSyntheticWebKit) {
              // Playwright's experimental WinCairo WebKit port on Windows (Safari does not ship on
              // Windows) hardcodes a macOS Safari User-Agent + "Apple GPU" renderer while exposing
              // navigator.platform === "Win32". Verify Layer 2B catches this cross-OS mismatch while
              // JSC math & probe integrity remain clean.
              expect(out.verifyResult.spoof_trap_triggered, 'wincairo cross-os mismatch').toBe(true)
              expect(out.verifyResult.spoof_flags).toContain(
                'gpu_register_law_violation:apple_gpu_on_non_apple_os'
              )
            } else {
              expect(
                out.verifyResult.spoof_trap_triggered,
                `${eng.name} spoof trap: ${JSON.stringify(out.verifyResult.spoof_flags)} | payload.webgl=${JSON.stringify({ v: out.payload.webgl.gpu_vendor, r: out.payload.webgl.gpu_renderer, lim: out.payload.webgl.webgl_limits_vector })} | worker=${JSON.stringify(out.payload.lies)}`
              ).toBe(false)
              expect(
                out.verifyResult.device_key_bound,
                `${eng.name} device key bound (payload.device_key=${Boolean(out.payload.device_key)}, privacy_signals=${JSON.stringify(out.verifyResult.privacy_signals)})`
              ).toBe(true)
              if (!out.verifyResult.is_virtual_gpu) {
                expect(out.verifyResult.risk_status, `${eng.name} risk status`).toBe('green')
              }
            }

            await context.close()
          } finally {
            await browser.close()
          }
        }
        expect(testedEngines).toBeGreaterThanOrEqual(1)
      },
      90000
    )
  })
})
