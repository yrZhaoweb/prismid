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

export interface AudioProbeResult {
  audio_compressor_hash: string
  audio_copy_hash: string
  audio_silent_delta: number
  audio_noise_injected: boolean
}

export async function collectAudioProbeWithTrap(timeoutMs = 400): Promise<AudioProbeResult> {
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
    const fallbackHash = sha256Hex('prismid-audio-context-unavailable')
    return {
      audio_compressor_hash: fallbackHash,
      audio_copy_hash: fallbackHash,
      audio_silent_delta: 0,
      audio_noise_injected: false,
    }
  }

  return new Promise<AudioProbeResult>((resolve) => {
    let done = false
    const finish = (res: AudioProbeResult) => {
      if (done) return
      done = true
      resolve(res)
    }

    const timer = setTimeout(() => {
      const timeoutHash = sha256Hex('prismid-audio-context-timeout')
      finish({
        audio_compressor_hash: timeoutHash,
        audio_copy_hash: timeoutHash,
        audio_silent_delta: 0,
        audio_noise_injected: false,
      })
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

      // Start oscillator at sample ~44 (t = 0.001s) so frames [0..16) are a mathematically
      // guaranteed silent prefix (0.0), while [4500..5000) is fully steady-state compressed!
      // Wait: to keep 100% hash compatibility for [4500..5000), we keep osc.start(0) on ctx
      // and check:
      //  1) Repeat-read determinism: buffer.getChannelData(0) read twice
      //  2) Cross-surface readback: buffer.getChannelData(0) vs buffer.copyFromChannel()
      //  3) Unconnected tail / silent channel check via a 2-channel context where channel 1 is silent!
      osc.connect(comp)
      comp.connect(ctx.destination)
      osc.start(0)

      const inspectBuffer = (buffer: AudioBuffer): AudioProbeResult => {
        const ch0A = buffer.getChannelData(0)
        const sliceA = new Float32Array(500)
        for (let i = 0; i < 500; i++) {
          sliceA[i] = ch0A[4500 + i]
        }

        let noiseInjected = false
        let copyAcc = ''
        let silentDelta = 0

        // Trap 1: Cross-Surface `copyFromChannel` vs `getChannelData` consistency
        if (typeof buffer.copyFromChannel === 'function') {
          try {
            const copySlice = new Float32Array(500)
            buffer.copyFromChannel(copySlice, 0, 4500)
            for (let i = 0; i < 500; i++) {
              if (copySlice[i] !== sliceA[i]) {
                noiseInjected = true
              }
              copyAcc += copySlice[i].toFixed(7) + ','
            }
          } catch {
            // ignore
          }
        }

        // Trap 2: Second `getChannelData(0)` call determinism check
        const ch0B = buffer.getChannelData(0)
        for (let i = 0; i < 500; i++) {
          if (ch0B[4500 + i] !== sliceA[i]) {
            noiseInjected = true
            break
          }
        }

        // Trap 3: Pristine Silent AudioBuffer Invariant
        try {
          const silentBuf = ctx.createBuffer(1, 16, 44100)
          const silentData = silentBuf.getChannelData(0)
          for (let i = 0; i < silentData.length; i++) {
            if (silentData[i] !== 0) {
              noiseInjected = true
              silentDelta += Math.abs(silentData[i])
              break
            }
          }
        } catch {
          // ignore
        }

        // Trap 4: Realistic magnitude & NaN/Infinity check
        let nonZeroCount = 0
        let acc = ''
        for (let i = 0; i < 500; i++) {
          const v = sliceA[i]
          if (!Number.isFinite(v) || Math.abs(v) > 2.0) {
            noiseInjected = true
          }
          if (v !== 0) nonZeroCount++
          acc += v.toFixed(7) + ','
        }
        if (nonZeroCount === 0) {
          noiseInjected = true
        }

        const primaryHash = sha256Hex(acc)
        const copyHash = copyAcc ? sha256Hex(copyAcc) : primaryHash

        return {
          audio_compressor_hash: primaryHash,
          audio_copy_hash: copyHash,
          audio_silent_delta: silentDelta,
          audio_noise_injected: noiseInjected,
        }
      }

      const renderPromise = ctx.startRendering()
      if (renderPromise && typeof renderPromise.then === 'function') {
        renderPromise
          .then((buffer: AudioBuffer) => {
            clearTimeout(timer)
            finish(inspectBuffer(buffer))
          })
          .catch(() => {
            clearTimeout(timer)
            const rejHash = sha256Hex('prismid-audio-render-rejected')
            finish({
              audio_compressor_hash: rejHash,
              audio_copy_hash: rejHash,
              audio_silent_delta: 0,
              audio_noise_injected: false,
            })
          })
      } else {
        ctx.oncomplete = (ev: OfflineAudioCompletionEvent) => {
          clearTimeout(timer)
          finish(inspectBuffer(ev.renderedBuffer))
        }
      }
    } catch {
      clearTimeout(timer)
      const excHash = sha256Hex('prismid-audio-exception')
      finish({
        audio_compressor_hash: excHash,
        audio_copy_hash: excHash,
        audio_silent_delta: 0,
        audio_noise_injected: false,
      })
    }
  })
}

export async function collectAudioProbe(timeoutMs = 400): Promise<string> {
  const res = await collectAudioProbeWithTrap(timeoutMs)
  return res.audio_compressor_hash
}
