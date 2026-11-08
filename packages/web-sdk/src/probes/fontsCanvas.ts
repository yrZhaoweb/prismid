/**
 * PrismID Sub-Pixel Font Bounding Box (`TextMetrics`) & Canvas 2D Composite Probe
 *
 * Uses `CanvasRenderingContext2D.measureText()` across 45 baseline fonts to capture
 * 64-bit sub-pixel floating-point metrics (`width`, `actualBoundingBoxAscent`,
 * `actualBoundingBoxDescent`, `actualBoundingBoxLeft`, `actualBoundingBoxRight`),
 * accurately distinguishing macOS CoreText, Windows DirectWrite, and Linux FreeType.
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
}

export function collectFontsAndCanvasProbe(): FontsCanvasProbeResult {
  if (typeof document === 'undefined' || typeof document.createElement !== 'function') {
    return {
      canvas_2d_hash: sha256Hex('headless-canvas2d-fallback'),
      fonts_bitmap_hash: sha256Hex('headless-fonts-fallback'),
    }
  }

  let canvas2dHash = ''
  let fontsBitmapHash = ''

  try {
    const canvas = document.createElement('canvas')
    canvas.width = 240
    canvas.height = 60
    const ctx = canvas.getContext('2d')
    if (ctx) {
      // 1. Sub-pixel TextMetrics bounding box probe across 45 fonts
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

      // 2. Composite Canvas 2D rendering (gradients, blending, arcs, bezier, CJK + emoji)
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

      canvas2dHash = sha256Hex(canvas.toDataURL())
    }
  } catch {
    // Fallback if canvas is blocked
  }

  return {
    canvas_2d_hash: canvas2dHash || sha256Hex('canvas2d-fallback'),
    fonts_bitmap_hash: fontsBitmapHash || sha256Hex('fonts-fallback'),
  }
}
