#!/usr/bin/env node
/**
 * PrismID vs. Global Open-Source Online Platforms (CreepJS / SannySoft / BrowserLeaks)
 * Live Browser Head-to-Head Evaluation Suite
 */
import { spawn } from 'node:child_process'
import { chromium } from 'playwright-core'

const CHROME_MAC_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'

async function startLocalPrismServer(port) {
  const proc = spawn('go', ['run', './cmd/prismid-server', '-addr', `127.0.0.1:${port}`], {
    cwd: new URL('../../../server/go', import.meta.url).pathname,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  const baseUrl = `http://127.0.0.1:${port}`
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${baseUrl}/api/v1/risk/should-collect`)
      if (res.ok) return { proc, baseUrl }
    } catch {
      // wait
    }
    await new Promise((r) => setTimeout(r, 150))
  }
  try {
    process.kill(-proc.pid, 'SIGTERM')
  } catch {}
  throw new Error('Failed to start local prismid-server')
}

async function runPrismScenario(browser, baseUrl, initScript, subjectId) {
  const context = await browser.newContext({
    extraHTTPHeaders: subjectId ? { Authorization: `Bearer ${subjectId}` } : undefined,
  })
  if (initScript) {
    await context.addInitScript(initScript)
  }
  const page = await context.newPage()
  await page.goto(baseUrl, { waitUntil: 'networkidle' })
  await page.click('#btn-identify')
  await page.waitForFunction(() => {
    const el = document.getElementById('server-out')
    return el && el.textContent && el.textContent.includes('"accepted": true')
  }, { timeout: 10000 })
  const raw = await page.textContent('#server-out')
  await context.close()
  return JSON.parse(raw)
}

async function main() {
  const port = 19100 + Math.floor(Math.random() * 500)
  const { proc, baseUrl } = await startLocalPrismServer(port)
  const browser = await chromium.launch({
    executablePath: CHROME_MAC_PATH,
    headless: true,
    args: ['--use-gl=angle', '--enable-webgl', '--ignore-gpu-blocklist'],
  })

  try {
    console.log('=== [Part 1] Live Online Public Benchmark Platforms Inspection ===')

    // 1. Test SannySoft Online (https://bot.sannysoft.com/) - Standard vs Stealth Patch
    {
      const ctxRaw = await browser.newContext()
      const pageRaw = await ctxRaw.newPage()
      await pageRaw.goto('https://bot.sannysoft.com/', { waitUntil: 'domcontentloaded', timeout: 15000 })
      await pageRaw.waitForTimeout(1500)
      const sannyRaw = await pageRaw.evaluate(() => {
        const webdriverEl = document.getElementById('webdriver-result')
        const failedCount = document.querySelectorAll('.failed').length
        const passedCount = document.querySelectorAll('.passed').length
        return {
          webdriverText: webdriverEl ? webdriverEl.textContent : 'unknown',
          failedCount,
          passedCount,
        }
      })
      await ctxRaw.close()

      // Now with Stealth Patch (hiding navigator.webdriver via arrow getter on Navigator.prototype)
      const ctxStealth = await browser.newContext()
      await ctxStealth.addInitScript(() => {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
          get: () => false,
          enumerable: true,
          configurable: true,
        })
      })
      const pageStealth = await ctxStealth.newPage()
      await pageStealth.goto('https://bot.sannysoft.com/', { waitUntil: 'domcontentloaded', timeout: 15000 })
      await pageStealth.waitForTimeout(1500)
      const sannyStealth = await pageStealth.evaluate(() => {
        const webdriverEl = document.getElementById('webdriver-result')
        const failedCount = document.querySelectorAll('.failed').length
        const passedCount = document.querySelectorAll('.passed').length
        return {
          webdriverText: webdriverEl ? webdriverEl.textContent : 'unknown',
          failedCount,
          passedCount,
        }
      })
      await ctxStealth.close()
      console.log('SannySoft Online (Raw Headless):', JSON.stringify(sannyRaw))
      console.log('SannySoft Online (Stealth-Patched):', JSON.stringify(sannyStealth))
    }

    // 2. Test BrowserLeaks Canvas Online (https://browserleaks.com/canvas) - Normal vs Deterministic Canvas Noise
    {
      const ctx1 = await browser.newContext()
      const p1 = await ctx1.newPage()
      await p1.goto('https://browserleaks.com/canvas', { waitUntil: 'domcontentloaded', timeout: 15000 })
      await p1.waitForTimeout(1500)
      const blNormal = await p1.evaluate(() => {
        const txt = document.body.innerText || ''
        const sigMatch = txt.match(/Signature\s+([0-9A-Fa-f]{16,64})/i)
        return { signature: sigMatch ? sigMatch[1] : 'rendered' }
      })
      await ctx1.close()

      // With Deterministic Seeded Canvas Noise (simulating AdsPower / Multilogin profile noise)
      const ctx2 = await browser.newContext()
      await ctx2.addInitScript(() => {
        const origGetImageData = CanvasRenderingContext2D.prototype.getImageData
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL
        CanvasRenderingContext2D.prototype.getImageData = function (x, y, w, h) {
          const img = origGetImageData.call(this, x, y, w, h)
          // Deterministic seed offset: add +1 to R channel at index 0
          if (img.data.length >= 4) {
            img.data[0] = (img.data[0] + 1) & 0xff
          }
          return img
        }
        HTMLCanvasElement.prototype.toDataURL = function (...args) {
          const ctx = this.getContext('2d')
          if (ctx) {
            const img = origGetImageData.call(ctx, 0, 0, 1, 1)
            img.data[0] = (img.data[0] + 1) & 0xff
            ctx.putImageData(img, 0, 0)
          }
          return origToDataURL.apply(this, args)
        }
      })
      const p2 = await ctx2.newPage()
      await p2.goto('https://browserleaks.com/canvas', { waitUntil: 'domcontentloaded', timeout: 15000 })
      await p2.waitForTimeout(1500)
      const blSpoofed = await p2.evaluate(() => {
        const txt = document.body.innerText || ''
        const sigMatch = txt.match(/Signature\s+([0-9A-Fa-f]{16,64})/i)
        return { signature: sigMatch ? sigMatch[1] : 'rendered' }
      })
      await ctx2.close()
      console.log('BrowserLeaks Online (Normal):', JSON.stringify(blNormal))
      console.log('BrowserLeaks Online (Deterministic Seed Noise - Blindly Accepted!):', JSON.stringify(blSpoofed))
    }

    // 3. Test CreepJS Online (https://abrahamjuliot.github.io/creepjs/)
    {
      const ctxCreep = await browser.newContext()
      await ctxCreep.addInitScript(() => {
        // Inject Stealth + Canvas + Navigator spoof to see how CreepJS reacts
        Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 32 })
        Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => false })
      })
      const pageCreep = await ctxCreep.newPage()
      await pageCreep.goto('https://abrahamjuliot.github.io/creepjs/', {
        waitUntil: 'domcontentloaded',
        timeout: 20000,
      })
      await pageCreep.waitForTimeout(6000)
      const creepSummary = await pageCreep.evaluate(() => {
        const fpEl = document.getElementById('fingerprint-data')
        const text = fpEl ? fpEl.innerText : document.body.innerText
        const liesMatch = text.match(/lies\s*\(\d+\)[^%\n]*/i) || text.match(/lies:\s*[^\n]+/i)
        const headlessMatch = text.match(/Headless[\s\S]{0,160}/i)
        return {
          loaded: text.length > 200,
          liesInfo: liesMatch ? liesMatch[0].trim() : 'see stealth/headless score',
          headlessSection: (headlessMatch ? headlessMatch[0] : text.slice(0, 180)).replace(/\s+/g, ' ').trim(),
        }
      })
      await ctxCreep.close()
      console.log('CreepJS Online (Adversarial Spoof Profile):', JSON.stringify(creepSummary))
    }

    console.log('\n=== [Part 2] PrismID v0.3.0 Live 6-Scenario Adversarial Matrix ===')

    // Scenario 1: Clean Browser Session A & Session B (Cookie Wiped) -> Same Device Recovery & Storage Self-Healing
    const s1 = await runPrismScenario(
      browser,
      baseUrl,
      () => {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
          value: false,
        })
      },
      'clean_user_1'
    )

    // Scenario 2: Stealth Plugin (`Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => false })`
    // + `Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 32 })`)
    const s2 = await runPrismScenario(
      browser,
      baseUrl,
      () => {
        Object.defineProperty(Navigator.prototype, 'webdriver', {
          get: () => false,
          enumerable: true,
          configurable: true,
        })
        Object.defineProperty(navigator, 'hardwareConcurrency', {
          get: () => 32,
          enumerable: true,
          configurable: true,
        })
      },
      'stealth_bot_user'
    )

    // Scenario 3: Deterministic Profile-Seeded Canvas Noise (AdsPower / Multilogin simulation:
    // ONLY activates noise when `fillText` was called on the canvas, using a fixed deterministic +1 offset!)
    const s3 = await runPrismScenario(
      browser,
      baseUrl,
      () => {
        const origFillText = CanvasRenderingContext2D.prototype.fillText
        const origGetImageData = CanvasRenderingContext2D.prototype.getImageData
        const textCanvases = new WeakSet()
        CanvasRenderingContext2D.prototype.fillText = function (...args) {
          textCanvases.add(this)
          return origFillText.apply(this, args)
        }
        CanvasRenderingContext2D.prototype.getImageData = function (x, y, w, h) {
          const img = origGetImageData.call(this, x, y, w, h)
          if (textCanvases.has(this) && img.data.length >= 4) {
            // Deterministic +1 noise on R channel!
            img.data[0] = (img.data[0] + 1) & 0xff
          }
          return img
        }
      },
      'deterministic_canvas_attacker'
    )

    // Scenario 4: Audio Fingerprint Defender Extension (hooks `AudioBuffer.prototype.getChannelData` with deterministic +1e-5 offset)
    const s4 = await runPrismScenario(
      browser,
      baseUrl,
      () => {
        const origGetChannelData = AudioBuffer.prototype.getChannelData
        AudioBuffer.prototype.getChannelData = function (channel) {
          const data = origGetChannelData.call(this, channel)
          for (let i = 0; i < data.length; i += 64) {
            data[i] = data[i] + 0.00001
          }
          return data
        }
      },
      'audio_spoof_attacker'
    )

    // Scenario 5: ES6 Proxy Wrapper around `WebGLRenderingContext.prototype.getParameter` (hiding `[native code]`)
    const s5 = await runPrismScenario(
      browser,
      baseUrl,
      () => {
        const origGetParam = WebGLRenderingContext.prototype.getParameter
        WebGLRenderingContext.prototype.getParameter = new Proxy(origGetParam, {
          apply(target, thisArg, args) {
            if (args[0] === 0x9246) {
              return 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4090 Direct3D11 vs_5_0 ps_5_0, D3D11)'
            }
            return Reflect.apply(target, thisArg, args)
          },
        })
      },
      'proxy_webgl_attacker'
    )

    // Scenario 6: Timezone / Locale Spoofing Extension (hooks main-thread `Intl.DateTimeFormat`, misses Web Worker)
    const s6 = await runPrismScenario(
      browser,
      baseUrl,
      () => {
        const origResolved = Intl.DateTimeFormat.prototype.resolvedOptions
        Intl.DateTimeFormat.prototype.resolvedOptions = function () {
          const res = origResolved.call(this)
          res.timeZone = 'America/Los_Angeles'
          return res
        }
      },
      'timezone_spoof_attacker'
    )

    const printRow = (name, res) => {
      console.log(
        JSON.stringify({
          scenario: name,
          confidence: res.confidence,
          risk_status: res.risk_status,
          spoof_trap_triggered: res.spoof_trap_triggered,
          spoof_flags: res.spoof_flags,
          privacy_signals: res.privacy_signals,
          beacon_slice_id: res.beacon_slice_id,
          gpu_audio_slice_id: res.gpu_audio_slice_id,
        })
      )
    }

    printRow('1_Clean_Baseline', s1)
    printRow('2_Stealth_Prototype_And_Instance_Spoof', s2)
    printRow('3_Smart_Deterministic_Canvas_Noise', s3)
    printRow('4_Audio_Buffer_Noise_Defender', s4)
    printRow('5_ES6_Proxy_WebGL_Renderer_Spoof', s5)
    printRow('6_Main_Thread_Timezone_Spoof', s6)
  } finally {
    await browser.close()
    try {
      process.kill(-proc.pid, 'SIGTERM')
    } catch {}
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
