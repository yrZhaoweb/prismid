/**
 * PrismID WebGL Probe:
 *   1. Unmasked GPU Vendor & Renderer (`WEBGL_debug_renderer_info`)
 *   2. 12 Hardware Register Limits Vector (`webgl_limits_vector`)
 *   3. Static 3D Multi-Frequency Anti-Aliased Geometry Scene Hash (`static_webgl_fp_hash`)
 *   4. Dynamic `render_seed` [s0, s1, s2, s3] 256x256 Fragment Shader & 8 Spot-Pixel Sampler
 */

import { sha256Hex } from '../crypto/aead.js'

export interface WebGLProbeResult {
  gpu_vendor: string
  gpu_renderer: string
  webgl_limits_vector: string
  webgl_extensions_hash: string
  static_webgl_fp_hash: string
  spot_pixels: [number, number, number, number][]
  webgl_available: boolean
  webgl_noise_injected: boolean
}

export const DEFAULT_SAMPLE_POINTS: [number, number][] = [
  [32, 48],
  [96, 64],
  [160, 80],
  [224, 96],
  [48, 144],
  [112, 160],
  [176, 192],
  [208, 224],
]

const VERTEX_SHADER_SRC = `
attribute vec2 a_pos;
void main() {
  gl_Position = vec4(a_pos, 0.0, 1.0);
}
`

// Dynamic Challenge Fragment Shader: MUST match server/go/shader_math.go character-for-character!
// In WebGL, gl_FragCoord.xy is at the half-pixel center (x + 0.5, y + 0.5).
const DYNAMIC_CHALLENGE_FRAGMENT_SHADER_SRC = `
precision highp float;
uniform vec4 u_seed;
void main() {
  vec2 uv = gl_FragCoord.xy / 256.0;
  float r = 0.5 + 0.5 * sin(uv.x * u_seed.x + uv.y * u_seed.y + u_seed.z);
  float g = 0.5 + 0.5 * cos(uv.x * u_seed.y - uv.y * u_seed.z + u_seed.w);
  float b = 0.5 + 0.5 * sin((uv.x + uv.y) * u_seed.w + u_seed.x);
  gl_FragColor = vec4(r, g, b, 1.0);
}
`

// Static Hardware Fingerprint Shader: exercises hardware SFU trigonometric & exponential
// units across high-frequency normal lighting gradients to expose chip-level rounding traits.
export const STATIC_FINGERPRINT_FRAGMENT_SHADER_SRC = `
precision highp float;
void main() {
  vec2 uv = (gl_FragCoord.xy - vec2(32.0, 32.0)) / 32.0;
  float dist = length(uv);
  float angle = atan(uv.y, uv.x);
  float wave1 = sin(dist * 19.7392088 + angle * 7.0);
  float wave2 = cos(uv.x * 13.4164078 - uv.y * 17.8885438);
  float spec = pow(max(0.0, sin(dist * 11.0 + wave2)), 3.0);
  float r = 0.5 + 0.5 * sin(wave1 * 3.14159265 + spec);
  float g = 0.5 + 0.5 * cos(wave2 * 2.71828182 - wave1);
  float b = 0.5 + 0.5 * sin((wave1 + wave2) * 1.61803398 + dist);
  gl_FragColor = vec4(r, g, b, 1.0);
}
`

/**
 * Exact mathematical mirror of `DYNAMIC_CHALLENGE_FRAGMENT_SHADER_SRC` at integer pixel (x, y).
 */
export function computeExpectedSpotPixelMath(
  x: number,
  y: number,
  seed: [number, number, number, number]
): [number, number, number, number] {
  const u = (x + 0.5) / 256.0
  const v = (y + 0.5) / 256.0
  const [s0, s1, s2, s3] = seed

  const r = 0.5 + 0.5 * Math.sin(u * s0 + v * s1 + s2)
  const g = 0.5 + 0.5 * Math.cos(u * s1 - v * s2 + s3)
  const b = 0.5 + 0.5 * Math.sin((u + v) * s3 + s0)

  const q = (val: number): number => {
    const clamped = Math.max(0, Math.min(1, val))
    return Math.round(clamped * 255)
  }
  return [q(r), q(g), q(b), 255]
}

function createWebGLContext(width: number, height: number): WebGLRenderingContext | null {
  try {
    if (typeof OffscreenCanvas !== 'undefined') {
      const oc = new OffscreenCanvas(width, height)
      const gl = oc.getContext('webgl', {
        antialias: true,
        preserveDrawingBuffer: true,
      }) as WebGLRenderingContext | null
      if (gl) return gl
    }
  } catch {
    // Fallback to HTMLCanvasElement
  }
  try {
    if (typeof document !== 'undefined' && typeof document.createElement === 'function') {
      const canvas = document.createElement('canvas')
      canvas.width = width
      canvas.height = height
      const gl = (canvas.getContext('webgl', {
        antialias: true,
        preserveDrawingBuffer: true,
      }) ||
        canvas.getContext('experimental-webgl', {
          antialias: true,
          preserveDrawingBuffer: true,
        })) as WebGLRenderingContext | null
      return gl
    }
  } catch {
    // WebGL unavailable
  }
  return null
}

function compileProgram(
  gl: WebGLRenderingContext,
  vsSource: string,
  fsSource: string
): WebGLProgram | null {
  const compile = (type: number, src: string): WebGLShader | null => {
    const shader = gl.createShader(type)
    if (!shader) return null
    gl.shaderSource(shader, src)
    gl.compileShader(shader)
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      gl.deleteShader(shader)
      return null
    }
    return shader
  }
  const vs = compile(gl.VERTEX_SHADER, vsSource)
  const fs = compile(gl.FRAGMENT_SHADER, fsSource)
  if (!vs || !fs) return null

  const prog = gl.createProgram()
  if (!prog) return null
  gl.attachShader(prog, vs)
  gl.attachShader(prog, fs)
  gl.linkProgram(prog)
  gl.deleteShader(vs)
  gl.deleteShader(fs)
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
    gl.deleteProgram(prog)
    return null
  }
  return prog
}

function drawFullScreenQuad(gl: WebGLRenderingContext, prog: WebGLProgram): WebGLBuffer | null {
  const buf = gl.createBuffer()
  if (!buf) return null
  gl.bindBuffer(gl.ARRAY_BUFFER, buf)
  const vertices = new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1])
  gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW)
  const posLoc = gl.getAttribLocation(prog, 'a_pos')
  gl.enableVertexAttribArray(posLoc)
  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0)
  gl.drawArrays(gl.TRIANGLES, 0, 6)
  return buf
}

function extractWebGLLimitsVector(gl: WebGLRenderingContext): string {
  const p = (pname: number): string => {
    try {
      const val = gl.getParameter(pname)
      if (val == null) return '0'
      if (ArrayBuffer.isView(val) || Array.isArray(val)) {
        return Array.from(val as ArrayLike<number>).join(',')
      }
      return String(val)
    } catch {
      return '0'
    }
  }

  let maxAnisotropy = '0'
  try {
    const ext =
      gl.getExtension('EXT_texture_filter_anisotropic') ||
      gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic') ||
      gl.getExtension('MOZ_EXT_texture_filter_anisotropic')
    if (ext) {
      maxAnisotropy = String(gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT) ?? 0)
    }
  } catch {
    maxAnisotropy = '0'
  }

  const precisions: number[] = []
  try {
    for (const st of [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER]) {
      for (const pt of [gl.HIGH_FLOAT, gl.MEDIUM_FLOAT]) {
        const fmt = gl.getShaderPrecisionFormat(st, pt)
        precisions.push(fmt ? fmt.precision : 0)
      }
    }
  } catch {
    precisions.push(23, 23, 23, 23)
  }

  return [
    p(gl.MAX_TEXTURE_SIZE),
    p(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
    p(gl.MAX_VIEWPORT_DIMS),
    p(gl.MAX_RENDERBUFFER_SIZE),
    p(gl.MAX_VERTEX_UNIFORM_VECTORS),
    p(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
    p(gl.MAX_VARYING_VECTORS),
    p(gl.ALIASED_LINE_WIDTH_RANGE),
    p(gl.ALIASED_POINT_SIZE_RANGE),
    maxAnisotropy,
    precisions.join(','),
  ].join('|')
}

function extractWebGLExtensionsHash(gl: WebGLRenderingContext): string {
  try {
    const exts = (gl.getSupportedExtensions() || []).slice().sort().join(',')
    return sha256Hex(exts).slice(0, 16)
  } catch {
    return '0000000000000000'
  }
}

export function collectWebGLProbe(
  renderSeed: [number, number, number, number],
  samplePoints: [number, number][] = DEFAULT_SAMPLE_POINTS
): WebGLProbeResult {
  const gl = createWebGLContext(256, 256)
  if (!gl) {
    // Headless / non-WebGL environment fallback (strictly marked webgl_available: false and SwiftShader,
    // which server/go demotes to VirtualGPUConfidence = 0.30 / RiskPending = true)
    return {
      gpu_vendor: 'SwiftShader',
      gpu_renderer: 'Google SwiftShader (Headless Fallback)',
      webgl_limits_vector: '8192|8192|8192,8192|8192|1024|1024|30|1,1|1,1024|0|23,23,23,23',
      webgl_extensions_hash: '0000000000000000',
      static_webgl_fp_hash: sha256Hex('headless-no-webgl-static-fallback'),
      spot_pixels: samplePoints.map(([x, y]) => computeExpectedSpotPixelMath(x, y, renderSeed)),
      webgl_available: false,
      webgl_noise_injected: false,
    }
  }

  let gpuVendor = 'Unknown'
  let gpuRenderer = 'Unknown'
  try {
    const dbg = gl.getExtension('WEBGL_debug_renderer_info')
    if (dbg) {
      gpuVendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || gl.getParameter(gl.VENDOR) || 'Unknown')
      gpuRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || gl.getParameter(gl.RENDERER) || 'Unknown')
    } else {
      gpuVendor = String(gl.getParameter(gl.VENDOR) || 'Unknown')
      gpuRenderer = String(gl.getParameter(gl.RENDERER) || 'Unknown')
    }
  } catch {
    // ignore
  }

  const limitsVector = extractWebGLLimitsVector(gl)
  const extensionsHash = extractWebGLExtensionsHash(gl)

  // Step 1: Render 64x64 static fingerprint scene and hash raw pixel buffer
  // Also perform dual readPixels determinism check to detect WebGL noise-injection extensions.
  let staticFpHash = ''
  let webglNoiseInjected = false
  try {
    gl.viewport(0, 0, 64, 64)
    const staticProg = compileProgram(gl, VERTEX_SHADER_SRC, STATIC_FINGERPRINT_FRAGMENT_SHADER_SRC)
    if (staticProg) {
      gl.useProgram(staticProg)
      const buf = drawFullScreenQuad(gl, staticProg)
      const pixels1 = new Uint8Array(64 * 64 * 4)
      const pixels2 = new Uint8Array(64 * 64 * 4)
      gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, pixels1)
      gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, pixels2)
      const hash1 = sha256Hex(pixels1)
      const hash2 = sha256Hex(pixels2)
      staticFpHash = hash1
      if (hash1 !== hash2) {
        webglNoiseInjected = true
      }
      if (buf) gl.deleteBuffer(buf)
      gl.deleteProgram(staticProg)
    }
  } catch {
    // ignore
  }
  if (!staticFpHash) {
    staticFpHash = sha256Hex(`${gpuVendor}|${gpuRenderer}|${limitsVector}`)
  }

  // Step 2: Render 256x256 dynamic challenge shader with u_seed = renderSeed
  const spotPixels: [number, number, number, number][] = []
  try {
    gl.viewport(0, 0, 256, 256)
    const dynProg = compileProgram(gl, VERTEX_SHADER_SRC, DYNAMIC_CHALLENGE_FRAGMENT_SHADER_SRC)
    if (dynProg) {
      gl.useProgram(dynProg)
      const seedLoc = gl.getUniformLocation(dynProg, 'u_seed')
      gl.uniform4f(seedLoc, renderSeed[0], renderSeed[1], renderSeed[2], renderSeed[3])
      const buf = drawFullScreenQuad(gl, dynProg)
      const pixel = new Uint8Array(4)
      for (const [x, y] of samplePoints) {
        gl.readPixels(x, y, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel)
        spotPixels.push([pixel[0], pixel[1], pixel[2], pixel[3]])
      }
      if (buf) gl.deleteBuffer(buf)
      gl.deleteProgram(dynProg)
    }
  } catch {
    // Fallback if shader compilation was blocked
  }

  // Do NOT fall back to CPU math when a WebGL context exists but failed/blocked shader rendering:
  // fill with [0,0,0,0] so broken/stubbed WebGL mocks fail spot-pixel verification honestly.
  while (spotPixels.length < samplePoints.length) {
    spotPixels.push([0, 0, 0, 0])
  }

  return {
    gpu_vendor: gpuVendor,
    gpu_renderer: gpuRenderer,
    webgl_limits_vector: limitsVector,
    webgl_extensions_hash: extensionsHash,
    static_webgl_fp_hash: staticFpHash,
    spot_pixels: spotPixels,
    webgl_available: true,
    webgl_noise_injected: webglNoiseInjected,
  }
}
