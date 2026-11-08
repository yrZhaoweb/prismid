/**
 * PrismID OfflineAudioContext Oscillator + DynamicsCompressor Integral Probe
 *
 * Drives a 10,000 Hz triangle wave through a hardware/OS-specific DynamicsCompressorNode
 * in a 1-channel, 44,100 Hz OfflineAudioContext, then computes the SHA-256 hash over
 * the floating-point audio samples [4500..5000).
 *
 * Completely immune to IP changes, screen size changes, and Canvas 2D noise extensions.
 */

import { sha256Hex } from '../crypto/aead.js'

export async function collectAudioProbe(timeoutMs = 400): Promise<string> {
  const OfflineCtx =
    typeof globalThis !== 'undefined'
      ? (globalThis as unknown as {
          OfflineAudioContext?: typeof OfflineAudioContext
          webkitOfflineAudioContext?: typeof OfflineAudioContext
        }).OfflineAudioContext ||
        (globalThis as unknown as {
          webkitOfflineAudioContext?: typeof OfflineAudioContext
        }).webkitOfflineAudioContext
      : undefined

  if (!OfflineCtx) {
    return sha256Hex('prismid-audio-context-unavailable')
  }

  return new Promise<string>((resolve) => {
    let done = false
    const finish = (hash: string) => {
      if (done) return
      done = true
      resolve(hash)
    }

    const timer = setTimeout(() => {
      finish(sha256Hex('prismid-audio-context-timeout'))
    }, timeoutMs)

    try {
      const ctx = new OfflineCtx(1, 5000, 44100)
      const osc = ctx.createOscillator()
      osc.type = 'triangle'
      osc.frequency.setValueAtTime(10000, ctx.currentTime)

      const comp = ctx.createDynamicsCompressor()
      comp.threshold.setValueAtTime(-50, ctx.currentTime)
      comp.knee.setValueAtTime(40, ctx.currentTime)
      comp.ratio.setValueAtTime(12, ctx.currentTime)
      comp.attack.setValueAtTime(0, ctx.currentTime)
      comp.release.setValueAtTime(0.25, ctx.currentTime)

      osc.connect(comp)
      comp.connect(ctx.destination)
      osc.start(0)

      const renderPromise = ctx.startRendering()
      if (renderPromise && typeof renderPromise.then === 'function') {
        renderPromise
          .then((buffer: AudioBuffer) => {
            clearTimeout(timer)
            const channelData = buffer.getChannelData(0)
            const slice = channelData.subarray(4500, 5000)
            let acc = ''
            for (let i = 0; i < slice.length; i++) {
              acc += slice[i].toFixed(7) + ','
            }
            finish(sha256Hex(acc))
          })
          .catch(() => {
            clearTimeout(timer)
            finish(sha256Hex('prismid-audio-render-rejected'))
          })
      } else {
        ctx.oncomplete = (ev: OfflineAudioCompletionEvent) => {
          clearTimeout(timer)
          const channelData = ev.renderedBuffer.getChannelData(0)
          const slice = channelData.subarray(4500, 5000)
          let acc = ''
          for (let i = 0; i < slice.length; i++) {
            acc += slice[i].toFixed(7) + ','
          }
          finish(sha256Hex(acc))
        }
      }
    } catch {
      clearTimeout(timer)
      finish(sha256Hex('prismid-audio-exception'))
    }
  })
}
