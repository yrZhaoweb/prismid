import { spawn, type ChildProcess } from 'node:child_process'
import crypto from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
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

  it('3. GLSL shader mathspot-pixel calculation is deterministic and bounded in [0, 255]', () => {
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
    expect(webgl.webgl_limits_vector.split('|').length).toBeGreaterThanOrEqual(10)

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

  describe('5. Live Cross-Language E2E Integration (prismid-js -> prismid-go standalone server)', () => {
    let serverProc: ChildProcess | null = null
    const port = 18095
    const baseUrl = `http://127.0.0.1:${port}`

    beforeAll(async () => {
      serverProc = spawn('go', ['run', './cmd/prismid-server', '-addr', `127.0.0.1:${port}`], {
        cwd: GO_SERVER_DIR,
        stdio: 'pipe',
      })

      // Poll /healthz until server is listening
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
      if (serverProc) {
        serverProc.kill('SIGTERM')
      }
    })

    it('completes full Challenge -> WebGL Math Spot-Pixels -> AEAD Seal -> Go VerifyAndDerive cycle (Web & Desktop Native modes)', async () => {
      // Test 1: Pure Browser Web mode
      const webClient = createPrismClient({
        baseUrl,
        getAccessToken: () => 'test-jwt-token-web',
      })
      const webRes = await webClient.identify({ force: true })
      expect(webRes).not.toBeNull()
      expect(webRes?.accepted).toBe(true)
      expect(webRes?.exact_slice_id).toMatch(/^d_web_[0-9a-f]{32}$/)
      expect(webRes?.gpu_audio_slice_id).toMatch(/^d_gpu_[0-9a-f]{32}$/)
      expect(webRes?.sys_net_slice_id).toMatch(/^d_sys_[0-9a-f]{32}$/)

      // Test 2: Desktop Tauri Native mode with NativeHardwareAnchor
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
      expect(desktopRes?.gpu_audio_slice_id).toBe(webRes?.gpu_audio_slice_id)
    })
  })
})
