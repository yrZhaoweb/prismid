/**
 * PrismID Cross-Thread Lie Detector (`Web Worker + OffscreenCanvas`)
 *
 * Spawns an inline `Blob` Web Worker (`WorkerGlobalScope`) with a 300ms timeout guard.
 * Inside the Worker thread (which escapes main-thread DOM/window tampering extensions):
 *   - Reads `self.navigator.userAgent`, `platform`, `hardwareConcurrency`
 *   - Reads `Intl.DateTimeFormat().resolvedOptions().timeZone` (catches timezone-spoofing proxy plugins!)
 *   - Creates `new OffscreenCanvas(64, 64).getContext('webgl', { antialias: false, ... })` to read
 *     `UNMASKED_RENDERER_WEBGL` and render the exact same static 3D hardware fingerprint scene.
 *
 * Handles GPU context loss / all-zero `readPixels` buffers without false positives (S3-38), and
 * gracefully falls back (`worker_unavailable = true`) when CSP blocks `Blob` Workers.
 */

import { sha256Hex } from '../crypto/aead.js'
import { STATIC_FINGERPRINT_FRAGMENT_SHADER_SRC } from './webgl.js'

export interface WorkerComparisonInput {
  gpuRenderer: string
  staticWebGLFpHash: string
  webglAvailable?: boolean
  cpuCores: number
  platform: string
  userAgent: string
  timezone?: string
}

export interface WorkerLieProbeResult {
  worker_unavailable: boolean
  worker_webgl_available: boolean
  worker_lie_detected: boolean
  worker_gpu_renderer: string
  worker_static_webgl_fp_hash: string
  worker_cpu_cores: number
  worker_platform: string
  worker_user_agent: string
  worker_timezone: string
}

export async function collectWorkerLieProbe(
  mainThread: WorkerComparisonInput,
  timeoutMs = 300
): Promise<WorkerLieProbeResult> {
  const emptyUnavailable: WorkerLieProbeResult = {
    worker_unavailable: true,
    worker_webgl_available: false,
    worker_lie_detected: false,
    worker_gpu_renderer: '',
    worker_static_webgl_fp_hash: '',
    worker_cpu_cores: 0,
    worker_platform: '',
    worker_user_agent: '',
    worker_timezone: '',
  }

  if (
    typeof Worker === 'undefined' ||
    typeof Blob === 'undefined' ||
    typeof URL === 'undefined' ||
    typeof URL.createObjectURL !== 'function'
  ) {
    return emptyUnavailable
  }

  const workerScript = `
    self.onmessage = function() {
      try {
        var nav = self.navigator || {};
        var ua = String(nav.userAgent || '');
        var plat = String(nav.platform || '');
        var cores = Number(nav.hardwareConcurrency || 0);
        var tz = '';
        try {
          tz = String(Intl.DateTimeFormat().resolvedOptions().timeZone || '');
        } catch (_) {}
        var renderer = '';
        var pixelsArray = null;
        var webglOk = false;

        if (typeof OffscreenCanvas !== 'undefined') {
          var oc = new OffscreenCanvas(64, 64);
          var gl = oc.getContext('webgl', {
            antialias: false,
            depth: false,
            stencil: false,
            preserveDrawingBuffer: true
          });
          if (gl && (typeof gl.isContextLost !== 'function' || !gl.isContextLost())) {
            try {
              var dbg = gl.getExtension('WEBGL_debug_renderer_info');
              renderer = String(
                (dbg && gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)) ||
                gl.getParameter(gl.RENDERER) ||
                ''
              );
              var vs = gl.createShader(gl.VERTEX_SHADER);
              gl.shaderSource(vs, 'attribute vec2 a_pos; void main() { gl_Position = vec4(a_pos, 0.0, 1.0); }');
              gl.compileShader(vs);
              var fs = gl.createShader(gl.FRAGMENT_SHADER);
              gl.shaderSource(fs, ${JSON.stringify(STATIC_FINGERPRINT_FRAGMENT_SHADER_SRC)});
              gl.compileShader(fs);
              var prog = gl.createProgram();
              gl.attachShader(prog, vs);
              gl.attachShader(prog, fs);
              gl.linkProgram(prog);
              if (gl.getProgramParameter(prog, gl.LINK_STATUS)) {
                gl.viewport(0, 0, 64, 64);
                gl.useProgram(prog);
                var buf = gl.createBuffer();
                gl.bindBuffer(gl.ARRAY_BUFFER, buf);
                gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
                var loc = gl.getAttribLocation(prog, 'a_pos');
                gl.enableVertexAttribArray(loc);
                gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
                gl.drawArrays(gl.TRIANGLES, 0, 3);
                var px = new Uint8Array(64 * 64 * 4);
                gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
                var glErr = typeof gl.getError === 'function' ? gl.getError() : 0;
                var lost = typeof gl.isContextLost === 'function' && gl.isContextLost();
                var nonZero = false;
                for (var i = 0; i < px.length; i++) {
                  if (px[i] !== 0) { nonZero = true; break; }
                }
                if (!lost && glErr === 0 && nonZero) {
                  pixelsArray = px.buffer;
                  webglOk = true;
                }
              }
            } finally {
              try {
                var loseExt = gl.getExtension('WEBGL_lose_context');
                if (loseExt && typeof loseExt.loseContext === 'function') loseExt.loseContext();
              } catch (_) {}
            }
          }
        }
        self.postMessage(
          { ok: true, webglOk: webglOk, ua: ua, plat: plat, cores: cores, tz: tz, renderer: renderer, pixelsBuffer: pixelsArray },
          pixelsArray ? [pixelsArray] : []
        );
      } catch (e) {
        self.postMessage({ ok: false });
      }
    };
  `

  return new Promise<WorkerLieProbeResult>((resolve) => {
    let settled = false
    let blobUrl = ''
    let worker: Worker | null = null

    const finish = (res: WorkerLieProbeResult) => {
      if (settled) return
      settled = true
      try {
        if (worker) worker.terminate()
      } catch {
        // ignore
      }
      try {
        if (blobUrl) URL.revokeObjectURL(blobUrl)
      } catch {
        // ignore
      }
      resolve(res)
    }

    const timer = setTimeout(() => {
      finish(emptyUnavailable)
    }, timeoutMs)

    try {
      const blob = new Blob([workerScript], { type: 'application/javascript' })
      blobUrl = URL.createObjectURL(blob)
      worker = new Worker(blobUrl)

      worker.onerror = () => {
        clearTimeout(timer)
        finish(emptyUnavailable)
      }

      worker.onmessage = (ev: MessageEvent) => {
        clearTimeout(timer)
        const data = ev.data
        if (!data || !data.ok) {
          finish(emptyUnavailable)
          return
        }

        const workerCores = Number(data.cores || 0)
        const workerPlat = String(data.plat || '')
        const workerUA = String(data.ua || '')
        const workerTZ = String(data.tz || '')
        const rawWorkerWebglOk = Boolean(data.webglOk) && data.pixelsBuffer instanceof ArrayBuffer
        const workerFpHash = rawWorkerWebglOk
          ? sha256Hex(new Uint8Array(data.pixelsBuffer))
          : ''
        // Only expose worker_gpu_renderer / worker_static_webgl_fp_hash when Worker WebGL actually
        // completed cleanly AND main-thread WebGL was also enabled (avoids false positives on GPU reset, S3-38).
        const mainWebglAvailable = mainThread.webglAvailable !== false
        const workerRenderer = rawWorkerWebglOk ? String(data.renderer || '') : ''

        const isGenericMaskedRenderer = (r: string): boolean => {
          const low = r.trim().toLowerCase()
          return (
            low === '' ||
            low === 'webkit webgl' ||
            low === 'mozilla' ||
            low === 'webgl' ||
            low === 'unknown' ||
            low === 'unavailable' ||
            low === 'webgl disabled'
          )
        }

        let lieDetected = false
        if (
          mainWebglAvailable &&
          rawWorkerWebglOk &&
          workerRenderer &&
          mainThread.gpuRenderer &&
          !isGenericMaskedRenderer(workerRenderer) &&
          !isGenericMaskedRenderer(mainThread.gpuRenderer) &&
          workerRenderer.toLowerCase() !== mainThread.gpuRenderer.toLowerCase()
        ) {
          lieDetected = true
        }
        if (
          mainWebglAvailable &&
          rawWorkerWebglOk &&
          workerFpHash &&
          mainThread.staticWebGLFpHash &&
          workerFpHash.toLowerCase() !== mainThread.staticWebGLFpHash.toLowerCase()
        ) {
          lieDetected = true
        }
        if (workerCores > 0 && mainThread.cpuCores > 0 && workerCores !== mainThread.cpuCores) {
          lieDetected = true
        }
        if (
          workerPlat &&
          mainThread.platform &&
          workerPlat.toLowerCase() !== mainThread.platform.toLowerCase()
        ) {
          lieDetected = true
        }
        if (workerUA && mainThread.userAgent && workerUA !== mainThread.userAgent) {
          lieDetected = true
        }
        if (workerTZ && mainThread.timezone && workerTZ !== mainThread.timezone) {
          lieDetected = true
        }

        finish({
          worker_unavailable: false,
          worker_webgl_available: rawWorkerWebglOk,
          worker_lie_detected: lieDetected,
          worker_gpu_renderer: mainWebglAvailable ? workerRenderer : '',
          worker_static_webgl_fp_hash: mainWebglAvailable ? workerFpHash : '',
          worker_cpu_cores: workerCores,
          worker_platform: workerPlat,
          worker_user_agent: workerUA,
          worker_timezone: workerTZ,
        })
      }

      worker.postMessage('probe')
    } catch {
      clearTimeout(timer)
      finish(emptyUnavailable)
    }
  })
}
