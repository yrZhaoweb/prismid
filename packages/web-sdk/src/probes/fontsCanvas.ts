/**
 * PrismID Sub-Pixel Font Bounding Box (`TextMetrics`), Canvas 2D Composite Probe,
 * and Solid-Patch Anti-Detect Noise Trap (`canvas_noise_injected`).
 *
 * 1. Uses `CanvasRenderingContext2D.measureText()` across 45 baseline fonts to capture
 *    64-bit sub-pixel floating-point metrics (`width`, `actualBoundingBoxAscent/Descent/Left/Right`).
 * 2. Renders a composite 2D scene for `canvas_2d_hash`.
 * 3. **Solid-Patch Spatial Uniformity + ±2 ICC Tolerance + Dual-Canvas Consistency Check**:
 *    Verifies that a 16x16 pure solid `rgb(17, 136, 221)` patch has 100% spatial uniformity across
 *    all 256 pixels while allowing up to ±2 channel delta for legitimate Display-P3 / OS ICC color
 *    management profiles (matching `server/go/engine.go`), and verifies repeat-read determinism.
 */

import { sha256Hex } from '../crypto/aead.js'

const BASELINE_FONTS: readonly string[] = [
  'Arial',
  'Arial Black',
  'Helvetica',
  'Helvetica Neue',
  'Times New Roman',
  'Courier New',
  'Verdana',
  'Georgia',
  'Palatino',
  'Garamond',
  'Bookman',
  'Trebuchet MS',
  'Impact',
  'Comic Sans MS',
  'Tahoma',
  'Geneva',
  'Lucida Console',
  'Lucida Sans Unicode',
  'Monaco',
  'Menlo',
  'Consolas',
  'SF Pro Text',
  'SF Pro Display',
  'PingFang SC',
  'Hiragino Sans GB',
  'Heiti SC',
  'Songti SC',
  'Kaiti SC',
  'Microsoft YaHei',
  'SimSun',
  'SimHei',
  'Malgun Gothic',
  'Meiryo',
  'Yu Gothic',
  'Segoe UI',
  'Segoe UI Emoji',
  'Apple Color Emoji',
  'Noto Color Emoji',
  'Noto Sans CJK SC',
  'Ubuntu',
  'DejaVu Sans',
  'Liberation Sans',
  'Cantarell',
  'Roboto',
  'Fira Code',
]

const PROBE_GLYPHS = 'mmmmmmmmmmlliW@#0123456789棱镜PrismID🔥'

export interface FontsCanvasProbeResult {
  canvas_2d_hash: string
  fonts_bitmap_hash: string
  canvas_noise_injected: boolean
  canvas_control_rgba: number[]
  canvas_readback_delta: number
}

let cachedFontsBitmapHash: string | null = null

export function resetFontsProbeCache(): void {
  cachedFontsBitmapHash = null
}

function renderCompositeScene(canvas: HTMLCanvasElement): string {
  canvas.width = 240
  canvas.height = 60
  const ctx = canvas.getContext('2d')
  if (!ctx) return ''

  const grad = ctx.createLinearGradient(0, 0, 240, 60)
  grad.addColorStop(0, '#0ea5e9')
  grad.addColorStop(0.5, '#6366f1')
  grad.addColorStop(1, '#ec4899')
  ctx.fillStyle = grad
  ctx.fillRect(0, 0, 240, 60)

  ctx.globalCompositeOperation = 'multiply'
  ctx.fillStyle = 'rgba(255, 180, 0, 0.75)'
  ctx.beginPath()
  ctx.arc(75, 30, 24, 0, Math.PI * 2, true)
  ctx.closePath()
  ctx.fill()

  ctx.globalCompositeOperation = 'source-over'
  ctx.fillStyle = '#0f172a'
  ctx.font = '15px "Arial", sans-serif'
  ctx.fillText('PrismID 棱镜 0123456789 🚀', 10, 36)

  ctx.strokeStyle = '#22d3ee'
  ctx.beginPath()
  ctx.bezierCurveTo(10, 10, 120, 55, 230, 15)
  ctx.stroke()

  return canvas.toDataURL()
}

function inspectSolidPatch(data: Uint8ClampedArray): {
  tampered: boolean
  sampleRgba: [number, number, number, number]
  nonUniformDelta: number
} {
  if (data.length < 4) {
    return { tampered: false, sampleRgba: [17, 136, 221, 255], nonUniformDelta: 0 }
  }
  const r0 = data[0]
  const g0 = data[1]
  const b0 = data[2]
  const a0 = data[3]

  // Allow ±2 uniform ICC / wide-gamut color management rounding (matching server/go/engine.go S3-36).
  if (
    Math.abs(r0 - 17) > 2 ||
    Math.abs(g0 - 136) > 2 ||
    Math.abs(b0 - 221) > 2 ||
    Math.abs(a0 - 255) > 2
  ) {
    return { tampered: true, sampleRgba: [r0, g0, b0, a0], nonUniformDelta: 0 }
  }

  // Every pixel in a pure solid fillRect MUST be identical across all 256 pixels;
  // catches per-pixel farbling or single-pixel +1 noise hooks.
  for (let i = 4; i < data.length; i += 4) {
    const diff =
      Math.abs(data[i] - r0) +
      Math.abs(data[i + 1] - g0) +
      Math.abs(data[i + 2] - b0) +
      Math.abs(data[i + 3] - a0)
    if (diff !== 0) {
      return {
        tampered: true,
        sampleRgba: [data[i], data[i + 1], data[i + 2], data[i + 3]],
        nonUniformDelta: diff,
      }
    }
  }

  return { tampered: false, sampleRgba: [r0, g0, b0, a0], nonUniformDelta: 0 }
}

function detectCanvasNoiseWithRawMeasurements(): {
  noiseInjected: boolean
  controlRgba: number[]
  readbackDelta: number
} {
  let noiseInjected = false
  let controlRgba: number[] = [0, 0, 0, 0, 17, 136, 221, 255]
  let readbackDelta = 0

  try {
    // Trap 1: 16x16 Pure Solid-Color Uniformity + ±2 ICC Tolerance Trap
    const trapCanvas = document.createElement('canvas')
    trapCanvas.width = 16
    trapCanvas.height = 16
    const trapCtx = trapCanvas.getContext('2d')
    if (!trapCtx) {
      return { noiseInjected, controlRgba, readbackDelta }
    }

    trapCtx.globalCompositeOperation = 'copy'
    trapCtx.fillStyle = 'rgb(17, 136, 221)'
    trapCtx.fillRect(0, 0, 16, 16)
    const imgData = trapCtx.getImageData(0, 0, 16, 16).data
    const patch1 = inspectSolidPatch(imgData)
    if (patch1.tampered) {
      noiseInjected = true
      controlRgba = [0, 0, 0, 0, ...patch1.sampleRgba]
      readbackDelta += patch1.nonUniformDelta
    }

    // Trap 2: In-Scene Complex Text+Arc Deterministic Seed Trap
    const c1 = document.createElement('canvas')
    const c2 = document.createElement('canvas')
    const url1 = renderCompositeScene(c1)
    const url2 = renderCompositeScene(c2)
    if (url1 !== url2) {
      noiseInjected = true
      readbackDelta += 1
    }

    const ctx1 = c1.getContext('2d')
    if (ctx1) {
      ctx1.globalCompositeOperation = 'source-over'
      ctx1.clearRect(224, 0, 16, 32)
      ctx1.fillStyle = 'rgb(17, 136, 221)'
      ctx1.fillRect(224, 16, 16, 16)

      const blankData = ctx1.getImageData(224, 0, 16, 16).data
      const solidInScene = ctx1.getImageData(224, 16, 16, 16).data
      const patch2 = inspectSolidPatch(solidInScene)

      controlRgba = [
        blankData[0] ?? 0,
        blankData[1] ?? 0,
        blankData[2] ?? 0,
        blankData[3] ?? 0,
        ...patch2.sampleRgba,
      ]

      for (let i = 0; i < blankData.length; i++) {
        if (blankData[i] !== 0) {
          noiseInjected = true
          controlRgba[i % 4] = blankData[i]
          break
        }
      }

      if (patch2.tampered) {
        noiseInjected = true
        readbackDelta += patch2.nonUniformDelta
      }

      // Trap 3: Stateful PRNG Seed Advance Trap
      const readA = ctx1.getImageData(0, 0, 220, 60).data
      const readB = ctx1.getImageData(0, 0, 220, 60).data
      for (let i = 0; i < readA.length; i += 16) {
        const diff =
          Math.abs(readA[i] - readB[i]) +
          Math.abs(readA[i + 1] - readB[i + 1]) +
          Math.abs(readA[i + 2] - readB[i + 2])
        if (diff !== 0) {
          noiseInjected = true
          readbackDelta += diff
          break
        }
      }
    }
  } catch {
    // ignore
  }
  return { noiseInjected, controlRgba, readbackDelta }
}

export function collectFontsAndCanvasProbe(): FontsCanvasProbeResult {
  if (typeof document === 'undefined' || typeof document.createElement !== 'function') {
    return {
      canvas_2d_hash: sha256Hex('headless-canvas2d-fallback'),
      fonts_bitmap_hash: sha256Hex('headless-fonts-fallback'),
      canvas_noise_injected: false,
      canvas_control_rgba: [0, 0, 0, 0, 17, 136, 221, 255],
      canvas_readback_delta: 0,
    }
  }

  let canvas2dHash = ''
  let fontsBitmapHash = cachedFontsBitmapHash || ''
  let canvasNoiseInjected = false
  let canvasControlRgba: number[] = [0, 0, 0, 0, 17, 136, 221, 255]
  let canvasReadbackDelta = 0

  try {
    const canvas = document.createElement('canvas')
    canvas.width = 240
    canvas.height = 60
    const ctx = canvas.getContext('2d')
    if (ctx) {
      // 1. Sub-pixel TextMetrics bounding box probe across 45 fonts (memoized per session, S3-41)
      if (!fontsBitmapHash) {
        const fontMetricsParts: string[] = []
        for (const fontName of BASELINE_FONTS) {
          ctx.font = `16px "${fontName}", monospace`
          const m = ctx.measureText(PROBE_GLYPHS)
          fontMetricsParts.push(
            [
              fontName,
              Number(m.width || 0).toFixed(4),
              Number(m.actualBoundingBoxAscent || 0).toFixed(4),
              Number(m.actualBoundingBoxDescent || 0).toFixed(4),
              Number(m.actualBoundingBoxLeft || 0).toFixed(4),
              Number(m.actualBoundingBoxRight || 0).toFixed(4),
            ].join(':')
          )
        }
        fontsBitmapHash = sha256Hex(fontMetricsParts.join('|'))
        cachedFontsBitmapHash = fontsBitmapHash
      }

      // 2. Composite Canvas 2D rendering
      const dataUrl = renderCompositeScene(canvas)
      if (dataUrl) {
        canvas2dHash = sha256Hex(dataUrl)
      }
    }

    // 3. Anti-detect Canvas Noise Injection Trap + Raw Measurements
    const rawCheck = detectCanvasNoiseWithRawMeasurements()
    canvasNoiseInjected = rawCheck.noiseInjected
    canvasControlRgba = rawCheck.controlRgba
    canvasReadbackDelta = rawCheck.readbackDelta
  } catch {
    // Fallback if canvas is blocked
  }

  return {
    canvas_2d_hash: canvas2dHash || sha256Hex('canvas2d-fallback'),
    fonts_bitmap_hash: fontsBitmapHash || sha256Hex('fonts-fallback'),
    canvas_noise_injected: canvasNoiseInjected,
    canvas_control_rgba: canvasControlRgba,
    canvas_readback_delta: canvasReadbackDelta,
  }
}
