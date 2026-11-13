import { describe, expect, it } from 'vitest'
import { PRISM_PROBE_VERSION } from '../src/index.js'
import { collectLieDetectorProbe, isTopFrameProxySetPrototypeTrap } from '../src/probes/lieDetector.js'

describe('isTopFrameProxySetPrototypeTrap', () => {
  it('ignores Proxy frames appearing below checkNativeFunction in caller stack', () => {
    const stack = [
      'TypeError: Cannot redefine property',
      '    at Proxy.setPrototypeOf (<anonymous>)',
    ].join('\n')
    expect(isTopFrameProxySetPrototypeTrap(stack)).toBe(true)

    const vueCallerStack = [
      'TypeError: Cyclic __proto__ value',
      '    at Object.setPrototypeOf (<anonymous>)',
      '    at checkNativeFunction (https://app.example/assets/index.js:10:20)',
      '    at collectLieDetectorProbe (https://app.example/assets/index.js:20:5)',
      '    at Proxy.mounted (https://app.example/assets/vue.js:100:12)',
    ].join('\n')
    expect(isTopFrameProxySetPrototypeTrap(vueCallerStack)).toBe(false)
  })

  it('ignores Proxy frames beyond the top two frames when minified', () => {
    const minifiedCallerStack = [
      'TypeError: Cyclic __proto__ value',
      '    at Object.setPrototypeOf (<anonymous>)',
      '    at a (https://app.example/assets/index.js:1:20)',
      '    at Proxy.b (https://app.example/assets/vue.js:2:30)',
    ].join('\n')
    expect(isTopFrameProxySetPrototypeTrap(minifiedCallerStack)).toBe(false)
  })

  it('ignores script URLs containing Proxy. and inlined Vue component Proxy hooks', () => {
    const proxyUrlStack = [
      'TypeError: Cyclic __proto__ value',
      '    at Object.setPrototypeOf (<anonymous>)',
      '    at a (https://cdn.example/assets/Proxy.vendor.js:1:20)',
    ].join('\n')
    expect(isTopFrameProxySetPrototypeTrap(proxyUrlStack)).toBe(false)

    const inlinedVueHookStack = [
      'TypeError: Cyclic __proto__ value',
      '    at Object.setPrototypeOf (<anonymous>)',
      '    at Proxy.mounted (https://cdn.example/assets/app.js:1:20)',
    ].join('\n')
    expect(isTopFrameProxySetPrototypeTrap(inlinedVueHookStack)).toBe(false)
  })
})

describe('collectLieDetectorProbe', () => {
  it('bumps PRISM_PROBE_VERSION to 2 and does not emit false positives for canPlayType, screen avail, or window replaceable dims', () => {
    expect(PRISM_PROBE_VERSION).toBe(2)

    const origCanPlayType =
      typeof HTMLMediaElement !== 'undefined' ? HTMLMediaElement.prototype.canPlayType : undefined
    const origAvailWidthDesc =
      typeof screen !== 'undefined' ? Object.getOwnPropertyDescriptor(screen, 'availWidth') : undefined
    const origInnerWidthDesc =
      typeof window !== 'undefined' ? Object.getOwnPropertyDescriptor(window, 'innerWidth') : undefined

    try {
      if (typeof HTMLMediaElement !== 'undefined') {
        HTMLMediaElement.prototype.canPlayType = (() => 'probably') as typeof HTMLMediaElement.prototype.canPlayType
      }
      if (typeof screen !== 'undefined') {
        Object.defineProperty(screen, 'availWidth', {
          value: 99999,
          configurable: true,
        })
      }
      if (typeof window !== 'undefined') {
        Object.defineProperty(window, 'innerWidth', {
          value: 1440,
          writable: true,
          configurable: true,
        })
      }

      const res = collectLieDetectorProbe()
      expect(res.prototype_lies.some((f) => f.includes('HTMLMediaElement.canPlayType'))).toBe(false)
      expect(res.prototype_lies).not.toContain('screen:avail_exceeds_total_dimensions')
      expect(res.prototype_lies).not.toContain('window.innerWidth:replaceable_data_override')
    } finally {
      if (typeof HTMLMediaElement !== 'undefined' && origCanPlayType) {
        HTMLMediaElement.prototype.canPlayType = origCanPlayType
      }
      if (typeof screen !== 'undefined') {
        if (origAvailWidthDesc) {
          Object.defineProperty(screen, 'availWidth', origAvailWidthDesc)
        } else {
          Reflect.deleteProperty(screen, 'availWidth')
        }
      }
      if (typeof window !== 'undefined' && origInnerWidthDesc) {
        Object.defineProperty(window, 'innerWidth', origInnerWidthDesc)
      }
    }
  })
})
