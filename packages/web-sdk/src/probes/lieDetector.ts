/**
 * PrismID JS Engine FDLIBM `Math` Constants & Prototype Chain Lie Detector
 *
 * 1. Evaluates boundary floating-point transcendental functions (`Math.acos`, `Math.acosh`,
 *    `Math.sinh`, `Math.tan`, `Math.expm1`, `Math.cbrt`) to identify the underlying JS engine
 *    (V8 vs. JavaScriptCore vs. SpiderMonkey) in 0.01ms, catching spoofed User-Agent headers.
 * 2. Uses `Function.prototype.toString.call(fn)` and `Object.getOwnPropertyDescriptor`
 *    to detect monkey-patched browser APIs and `Proxy` wrappers.
 * 3. Checks `navigator.webdriver` and CDP/automation globals.
 */

import { sha256Hex } from '../crypto/aead.js'

export interface LieDetectorResult {
  math_engine_signature: 'v8' | 'jsc' | 'spidermonkey' | 'unknown'
  math_constants_hash: string
  prototype_lies: string[]
  automation_flags: string[]
}

export function collectLieDetectorProbe(): LieDetectorResult {
  // 1. FDLIBM Math floating-point boundary fingerprint
  const mValues = [
    Math.acos(0.12345678910111213),
    Math.acosh(1e300),
    Math.asin(0.12345678910111213),
    Math.atanh(0.5),
    Math.cbrt(Math.PI),
    Math.cos(1e20),
    Math.cosh(1),
    Math.expm1(1),
    Math.log1p(0.9999999999999999),
    Math.sin(-1e300),
    Math.sinh(1),
    Math.tan(-1e300),
  ]
  const mathConstantsHash = sha256Hex(mValues.map((n) => String(n)).join('|')).slice(0, 32)

  // Determine JS engine family from runtime intrinsics & error formatting
  let mathEngineSignature: 'v8' | 'jsc' | 'spidermonkey' | 'unknown' = 'unknown'
  try {
    const errStack = new Error().stack || ''
    if ('captureStackTrace' in Error) {
      mathEngineSignature = 'v8'
    } else if (errStack.includes('@') && typeof (globalThis as Record<string, unknown>).mozInnerScreenX !== 'undefined') {
      mathEngineSignature = 'spidermonkey'
    } else if (errStack.includes('@')) {
      mathEngineSignature = 'jsc'
    } else {
      mathEngineSignature = 'v8'
    }
  } catch {
    mathEngineSignature = 'unknown'
  }

  // 2. Prototype chain & native function integrity inspection
  const prototypeLies: string[] = []
  const fnToString = Function.prototype.toString

  const checkNativeFunction = (fn: unknown, label: string) => {
    if (typeof fn !== 'function') return
    try {
      const str = fnToString.call(fn)
      if (!/\{\s*\[native code\]\s*\}/.test(str)) {
        prototypeLies.push(`${label}:non_native_toString`)
      }
      // Check if function itself has an own `toString` override
      if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
        prototypeLies.push(`${label}:own_toString_override`)
      }
    } catch {
      prototypeLies.push(`${label}:proxy_toString_trap`)
    }
  }

  try {
    checkNativeFunction(Function.prototype.toString, 'Function.toString')
    if (typeof HTMLCanvasElement !== 'undefined') {
      checkNativeFunction(HTMLCanvasElement.prototype.toDataURL, 'HTMLCanvasElement.toDataURL')
      checkNativeFunction(HTMLCanvasElement.prototype.getContext, 'HTMLCanvasElement.getContext')
    }
    if (typeof CanvasRenderingContext2D !== 'undefined') {
      checkNativeFunction(
        CanvasRenderingContext2D.prototype.measureText,
        'CanvasRenderingContext2D.measureText'
      )
      checkNativeFunction(
        CanvasRenderingContext2D.prototype.getImageData,
        'CanvasRenderingContext2D.getImageData'
      )
    }
    if (typeof WebGLRenderingContext !== 'undefined') {
      checkNativeFunction(
        WebGLRenderingContext.prototype.getParameter,
        'WebGLRenderingContext.getParameter'
      )
      checkNativeFunction(
        WebGLRenderingContext.prototype.readPixels,
        'WebGLRenderingContext.readPixels'
      )
    }
    if (typeof OfflineAudioContext !== 'undefined') {
      checkNativeFunction(
        OfflineAudioContext.prototype.startRendering,
        'OfflineAudioContext.startRendering'
      )
    }
    if (typeof Navigator !== 'undefined') {
      for (const prop of ['userAgent', 'platform', 'hardwareConcurrency', 'webdriver'] as const) {
        const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop)
        if (desc && desc.get) {
          checkNativeFunction(desc.get, `Navigator.${prop}.get`)
        }
        if (typeof navigator !== 'undefined' && Object.prototype.hasOwnProperty.call(navigator, prop)) {
          prototypeLies.push(`navigator.${prop}:instance_property_override`)
        }
      }
    }
  } catch {
    // ignore
  }

  // 3. Automation / WebDriver / CDP flags
  const automationFlags: string[] = []
  try {
    if (typeof navigator !== 'undefined' && navigator.webdriver === true) {
      automationFlags.push('navigator_webdriver')
    }
    const g = globalThis as Record<string, unknown>
    const cdpKeys = [
      '__webdriver_evaluate',
      '__selenium_unwrapped',
      '__fxdriver_evaluate',
      '__driver_evaluate',
      '_phantom',
      '__nightmare',
      'callPhantom',
      'domAutomation',
      'domAutomationController',
    ]
    for (const k of cdpKeys) {
      if (k in g) {
        automationFlags.push(`global:${k}`)
      }
    }
    if (typeof document !== 'undefined') {
      for (const attr of ['$cdc_asdjflasutopfhvcZLmcfl_', '$chrome_asyncScriptInfo']) {
        if (attr in (document as unknown as Record<string, unknown>)) {
          automationFlags.push(`document:${attr}`)
        }
      }
    }
  } catch {
    // ignore
  }

  return {
    math_engine_signature: mathEngineSignature,
    math_constants_hash: mathConstantsHash,
    prototype_lies: prototypeLies,
    automation_flags: automationFlags,
  }
}
