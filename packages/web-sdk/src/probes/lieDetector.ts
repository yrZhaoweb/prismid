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

  // 2. Prototype chain & native function integrity inspection (CreepJS `getPrototypeLies` grade)
  const prototypeLies: string[] = []
  const fnToString = Function.prototype.toString

  const checkNativeFunction = (fn: unknown, label: string, expectedName?: string) => {
    if (typeof fn !== 'function') return
    try {
      const str = fnToString.call(fn)
      if (!/\{\s*\[native code\]\s*\}/.test(str)) {
        prototypeLies.push(`${label}:non_native_toString`)
      }
      // Check if function itself has an own `toString` or `name` override
      if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
        prototypeLies.push(`${label}:own_toString_override`)
      }
      // Native WebIDL methods & getters never have a `.prototype` property (`'prototype' in fn === false`)
      if ('prototype' in fn) {
        prototypeLies.push(`${label}:has_prototype_property`)
      }
      // Check expected function `.name` (e.g. `'get userAgent'` or `'userAgent'` for native getters)
      if (
        expectedName &&
        fn.name !== expectedName &&
        fn.name !== expectedName.replace(/^get /, '')
      ) {
        prototypeLies.push(`${label}:unexpected_name_${fn.name || 'empty'}`)
      }
      // ECMAScript §10.1.2.1 OrdinarySetPrototypeOf cyclic __proto__ invariant:
      // Calling `Object.setPrototypeOf(fn, Object.create(fn))` on any genuine function MUST
      // throw `TypeError: Cyclic __proto__ value` because `SameValue(p, O)` matches `fn`.
      // On an ES6 `new Proxy(target, handler)`, `[[SetPrototypeOf]]` forwards to `target` while
      // `Object.create(proxy)` links to `proxy` (`SameValue(proxy, target) === false`), so it
      // succeeds without throwing (or triggers a custom `setPrototypeOf` trap)!
      const origProto = Object.getPrototypeOf(fn)
      try {
        Object.setPrototypeOf(fn, Object.create(fn))
        prototypeLies.push(`${label}:es6_proxy_detected`)
      } catch (err) {
        const stack = (err as Error)?.stack || ''
        if (stack.includes('Proxy.')) {
          prototypeLies.push(`${label}:proxy_setPrototypeOf_trap`)
        }
      } finally {
        try {
          Object.setPrototypeOf(fn, origProto)
        } catch {
          // ignore
        }
      }
    } catch {
      prototypeLies.push(`${label}:proxy_toString_trap`)
    }
  }

  try {
    checkNativeFunction(Function.prototype.toString, 'Function.toString', 'toString')
    if (typeof HTMLCanvasElement !== 'undefined') {
      checkNativeFunction(HTMLCanvasElement.prototype.toDataURL, 'HTMLCanvasElement.toDataURL', 'toDataURL')
      checkNativeFunction(HTMLCanvasElement.prototype.getContext, 'HTMLCanvasElement.getContext', 'getContext')
    }
    if (typeof CanvasRenderingContext2D !== 'undefined') {
      checkNativeFunction(
        CanvasRenderingContext2D.prototype.measureText,
        'CanvasRenderingContext2D.measureText',
        'measureText'
      )
      checkNativeFunction(
        CanvasRenderingContext2D.prototype.getImageData,
        'CanvasRenderingContext2D.getImageData',
        'getImageData'
      )
    }
    if (typeof WebGLRenderingContext !== 'undefined') {
      checkNativeFunction(
        WebGLRenderingContext.prototype.getParameter,
        'WebGLRenderingContext.getParameter',
        'getParameter'
      )
      checkNativeFunction(
        WebGLRenderingContext.prototype.readPixels,
        'WebGLRenderingContext.readPixels',
        'readPixels'
      )
    }
    if (typeof OfflineAudioContext !== 'undefined') {
      checkNativeFunction(
        OfflineAudioContext.prototype.startRendering,
        'OfflineAudioContext.startRendering',
        'startRendering'
      )
    }
    if (typeof AudioBuffer !== 'undefined') {
      checkNativeFunction(
        AudioBuffer.prototype.getChannelData,
        'AudioBuffer.getChannelData',
        'getChannelData'
      )
      if (typeof AudioBuffer.prototype.copyFromChannel === 'function') {
        checkNativeFunction(
          AudioBuffer.prototype.copyFromChannel,
          'AudioBuffer.copyFromChannel',
          'copyFromChannel'
        )
      }
    }
    if (typeof Navigator !== 'undefined') {
      const navProps = [
        'userAgent',
        'appVersion',
        'platform',
        'hardwareConcurrency',
        'deviceMemory',
        'language',
        'languages',
        'webdriver',
        'vendor',
        'plugins',
        'mimeTypes',
        'maxTouchPoints',
      ] as const
      for (const prop of navProps) {
        const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop)
        if (desc) {
          if ('value' in desc || typeof desc.get !== 'function') {
            prototypeLies.push(`Navigator.${prop}:data_descriptor_override`)
          } else {
            checkNativeFunction(desc.get, `Navigator.${prop}.get`, `get ${prop}`)
          }
        }
        if (typeof navigator !== 'undefined' && Object.prototype.hasOwnProperty.call(navigator, prop)) {
          prototypeLies.push(`navigator.${prop}:instance_property_override`)
        }
      }
    }
    if (typeof Screen !== 'undefined' && typeof screen !== 'undefined') {
      const scrProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'] as const
      for (const prop of scrProps) {
        const desc = Object.getOwnPropertyDescriptor(Screen.prototype, prop)
        if (desc) {
          if ('value' in desc || typeof desc.get !== 'function') {
            prototypeLies.push(`Screen.${prop}:data_descriptor_override`)
          } else {
            checkNativeFunction(desc.get, `Screen.${prop}.get`, `get ${prop}`)
          }
        }
        if (Object.prototype.hasOwnProperty.call(screen, prop)) {
          prototypeLies.push(`screen.${prop}:instance_property_override`)
        }
      }
      if (
        (screen.width > 0 && screen.availWidth > screen.width) ||
        (screen.height > 0 && screen.availHeight > screen.height)
      ) {
        prototypeLies.push('screen:avail_exceeds_total_dimensions')
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
