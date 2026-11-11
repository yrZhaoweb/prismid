/**
 * PrismID JS Engine FDLIBM `Math` Constants & Prototype Chain Lie Detector
 *
 * 1. Evaluates boundary floating-point transcendental functions (`Math.acos`, `Math.acosh`,
 *    `Math.sinh`, `Math.tan`, `Math.expm1`, `Math.cbrt`), verifies IEEE-754 exactness and
 *    repeat-call determinism (`unknown_tampered_math`), and identifies the underlying JS engine
 *    (V8 vs. JavaScriptCore vs. SpiderMonkey), catching spoofed User-Agent headers.
 * 2. Uses `Function.prototype.toString.call(fn)` and `Object.getOwnPropertyDescriptor`
 *    to detect monkey-patched browser APIs and `Proxy` wrappers while staying compatible with
 *    frozen-intrinsic (SES/Lockdown) environments.
 * 3. Checks `navigator.webdriver` and CDP/automation globals.
 */

import { sha256Hex } from '../crypto/aead.js'

export interface LieDetectorResult {
  math_engine_signature: 'v8' | 'jsc' | 'spidermonkey' | 'unknown_tampered_math' | 'unknown'
  math_constants_hash: string
  prototype_lies: string[]
  automation_flags: string[]
}

function sampleMathConstants(): number[] {
  return [
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
}

export function collectLieDetectorProbe(): LieDetectorResult {
  // 1. FDLIBM Math floating-point boundary fingerprint + active tamper check (S3-29)
  const mValues = sampleMathConstants()
  const mValuesRepeat = sampleMathConstants()
  const mathConstantsHash = sha256Hex(mValues.map((n) => String(n)).join('|')).slice(0, 32)

  let mathTampered =
    Math.cos(0) !== 1 ||
    Math.sin(0) !== 0 ||
    Math.atan2(0, 1) !== 0 ||
    Math.expm1(0) !== 0 ||
    Math.log1p(0) !== 0 ||
    mValues.some((v) => !Number.isFinite(v))

  if (!mathTampered) {
    for (let i = 0; i < mValues.length; i++) {
      if (mValues[i] !== mValuesRepeat[i]) {
        mathTampered = true
        break
      }
    }
  }

  // Determine JS engine family from stack-frame grammar & engine-exclusive intrinsics.
  // Note: Safari 18.2+ (JSC) and Firefox 135+ (SpiderMonkey) also expose `Error.captureStackTrace`,
  // so we NEVER rely on `'captureStackTrace' in Error` alone (S2-17)!
  let mathEngineSignature: LieDetectorResult['math_engine_signature'] = 'unknown'
  try {
    const errStack = new Error().stack || ''
    const hasV8AtFrames = /^\s*(?:Error|TypeError)\b[\s\S]*\n\s+at\s+/m.test(errStack)
    const g = globalThis as Record<string, unknown>
    if (hasV8AtFrames) {
      mathEngineSignature = 'v8'
    } else if (
      typeof g.InternalError === 'function' ||
      typeof g.mozInnerScreenX !== 'undefined'
    ) {
      mathEngineSignature = 'spidermonkey'
    } else if (errStack.includes('@')) {
      mathEngineSignature = 'jsc'
    } else if ('captureStackTrace' in Error) {
      mathEngineSignature = 'v8'
    }
  } catch {
    mathEngineSignature = 'unknown'
  }

  // 2. Prototype chain & native function integrity inspection
  const prototypeLies: string[] = []
  const fnToString = Function.prototype.toString

  const checkNativeFunction = (fn: unknown, label: string, expectedName?: string): boolean => {
    if (typeof fn !== 'function') return false
    const beforeLen = prototypeLies.length
    try {
      const str = fnToString.call(fn)
      if (!/\{\s*\[native code\]\s*\}/.test(str)) {
        prototypeLies.push(`${label}:non_native_toString`)
      }
      if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
        prototypeLies.push(`${label}:own_toString_override`)
      }
      // Native WebIDL methods, getters & Math functions do not have a `.prototype` property
      if ('prototype' in fn) {
        prototypeLies.push(`${label}:has_prototype_property`)
      }
      if (
        expectedName &&
        fn.name !== expectedName &&
        fn.name !== expectedName.replace(/^get /, '')
      ) {
        prototypeLies.push(`${label}:unexpected_name_${fn.name || 'empty'}`)
      }
      if (fn.toString !== fnToString || fn.toString !== fn.toString) {
        prototypeLies.push(`${label}:toString_proxy_getter`)
      }
      // Guard setPrototypeOf probes with `Object.isExtensible(fn)` so SES / Lockdown
      // frozen-intrinsics environments never suffer false positives (S2-17).
      if (Object.isExtensible(fn)) {
        const origProto = Object.getPrototypeOf(fn)
        try {
          if (Reflect.setPrototypeOf(fn, origProto) !== true) {
            prototypeLies.push(`${label}:non_cyclic_setPrototypeOf_rejected`)
          }
          Object.setPrototypeOf(fn, origProto)
        } catch {
          prototypeLies.push(`${label}:fake_cyclic_proto_trap`)
        }
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
      }
    } catch {
      prototypeLies.push(`${label}:proxy_toString_trap`)
    }
    return prototypeLies.length > beforeLen
  }

  try {
    checkNativeFunction(Function.prototype.toString, 'Function.toString', 'toString')

    // Verify Math transcendental functions have not been monkey-patched or proxied (S3-29)
    if (
      checkNativeFunction(Math.acos, 'Math.acos', 'acos') ||
      checkNativeFunction(Math.sin, 'Math.sin', 'sin') ||
      checkNativeFunction(Math.cos, 'Math.cos', 'cos') ||
      checkNativeFunction(Math.tan, 'Math.tan', 'tan') ||
      checkNativeFunction(Math.expm1, 'Math.expm1', 'expm1')
    ) {
      mathTampered = true
    }

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
    if (typeof WebGL2RenderingContext !== 'undefined') {
      checkNativeFunction(
        WebGL2RenderingContext.prototype.getParameter,
        'WebGL2RenderingContext.getParameter',
        'getParameter'
      )
    }
    if (typeof HTMLMediaElement !== 'undefined') {
      checkNativeFunction(
        HTMLMediaElement.prototype.canPlayType,
        'HTMLMediaElement.canPlayType',
        'canPlayType'
      )
    }
    if (typeof Document !== 'undefined' && typeof document !== 'undefined') {
      checkNativeFunction(
        Document.prototype.createElement,
        'Document.createElement',
        'createElement'
      )
      if (Object.prototype.hasOwnProperty.call(document, 'createElement')) {
        prototypeLies.push('document.createElement:instance_property_override')
      }
    }
    if (typeof window !== 'undefined') {
      for (const dimProp of ['outerWidth', 'outerHeight', 'innerWidth', 'innerHeight'] as const) {
        const wDesc = Object.getOwnPropertyDescriptor(window, dimProp)
        if (wDesc && ('value' in wDesc || typeof wDesc.get !== 'function')) {
          prototypeLies.push(`window.${dimProp}:replaceable_data_override`)
        }
      }
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
        'AudioBuffer.prototype.getChannelData',
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
        if (!desc) {
          if (prop !== 'deviceMemory') {
            prototypeLies.push(`Navigator.${prop}:descriptor_deleted`)
          }
        } else if ('value' in desc || typeof desc.get !== 'function') {
          prototypeLies.push(`Navigator.${prop}:data_descriptor_override`)
        } else {
          checkNativeFunction(desc.get, `Navigator.${prop}.get`, `get ${prop}`)
          if (
            typeof navigator !== 'undefined' &&
            prop !== 'plugins' &&
            prop !== 'mimeTypes'
          ) {
            try {
              const v0 = desc.get.call(navigator)
              const v1 = (desc.get as unknown as (arg: number) => unknown).call(navigator, 1)
              if (JSON.stringify(v0) !== JSON.stringify(v1)) {
                prototypeLies.push(`Navigator.${prop}:getter_arity_lie`)
              }
            } catch {
              // ignore
            }
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
        if (!desc) {
          prototypeLies.push(`Screen.${prop}:descriptor_deleted`)
        } else if ('value' in desc || typeof desc.get !== 'function') {
          prototypeLies.push(`Screen.${prop}:data_descriptor_override`)
        } else {
          checkNativeFunction(desc.get, `Screen.${prop}.get`, `get ${prop}`)
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

  if (mathTampered) {
    mathEngineSignature = 'unknown_tampered_math'
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
