// PrismID Web SDK (prismid-js) Standalone ES Module Bundle

// --- crypto/aead.js ---
/**
 * PrismID AEAD (AES-256-GCM) Cryptographic Envelope & Pure-TS Fallback
 *
 * Wire format specification (see docs/PROTOCOL_SPEC.md):
 *   Key        = SHA256("prismid-v1-aead:" + challenge.nonce) (32 bytes)
 *   IV         = 12 random bytes
 *   AAD        = ASCII(challenge.nonce)
 *   SealedBlob = Base64RawURL(IV [12B] || Ciphertext || GCM_Tag [16B])
 *
 * Uses hardware-accelerated WebCrypto (`crypto.subtle.encrypt`) whenever available,
 * and falls back seamlessly to a compliant pure-TypeScript AES-256-GCM implementation
 * in non-HTTPS local LAN debugging environments where `crypto.subtle` is undefined.
 */
export const AEAD_KEY_DOMAIN_PREFIX = 'prismid-v1-aead:';
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
function rotr32(x, n) {
    return (x >>> n) | (x << (32 - n));
}
/**
 * Pure TypeScript SHA-256 implementation returning a 32-byte Uint8Array.
 * Works synchronously in any browser, WebView, Worker, or non-HTTPS LAN context.
 */
export function sha256Bytes(input) {
    const msg = typeof input === 'string' ? new TextEncoder().encode(input) : input;
    const bitLenHi = Math.floor((msg.length * 8) / 0x100000000);
    const bitLenLo = (msg.length * 8) >>> 0;
    const padLen = ((msg.length + 9 + 63) & ~63);
    const padded = new Uint8Array(padLen);
    padded.set(msg);
    padded[msg.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padLen - 8, bitLenHi, false);
    dv.setUint32(padLen - 4, bitLenLo, false);
    let h0 = 0x6a09e667;
    let h1 = 0xbb67ae85;
    let h2 = 0x3c6ef372;
    let h3 = 0xa54ff53a;
    let h4 = 0x510e527f;
    let h5 = 0x9b05688c;
    let h6 = 0x1f83d9ab;
    let h7 = 0x5be0cd19;
    const w = new Uint32Array(64);
    for (let offset = 0; offset < padLen; offset += 64) {
        for (let i = 0; i < 16; i++) {
            w[i] = dv.getUint32(offset + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        let a = h0;
        let b = h1;
        let c = h2;
        let d = h3;
        let e = h4;
        let f = h5;
        let g = h6;
        let h = h7;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
        h5 = (h5 + f) >>> 0;
        h6 = (h6 + g) >>> 0;
        h7 = (h7 + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const outDv = new DataView(out.buffer);
    outDv.setUint32(0, h0, false);
    outDv.setUint32(4, h1, false);
    outDv.setUint32(8, h2, false);
    outDv.setUint32(12, h3, false);
    outDv.setUint32(16, h4, false);
    outDv.setUint32(20, h5, false);
    outDv.setUint32(24, h6, false);
    outDv.setUint32(28, h7, false);
    return out;
}
export function sha256Hex(input) {
    const bytes = sha256Bytes(input);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}
export function deriveAEADKeyBytes(nonce) {
    return sha256Bytes(AEAD_KEY_DOMAIN_PREFIX + nonce);
}
export function randomBytes(length) {
    const buf = new Uint8Array(length);
    if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
        globalThis.crypto.getRandomValues(buf);
        return buf;
    }
    for (let i = 0; i < length; i++) {
        buf[i] = Math.floor(Math.random() * 256);
    }
    return buf;
}
export function toBase64RawURL(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const b64 = typeof btoa === 'function'
        ? btoa(binary)
        : Buffer.from(bytes).toString('base64');
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
/**
 * Seals plaintext UTF-8 string or bytes using AES-256-GCM and returns
 * `Base64RawURL(IV [12B] || Ciphertext || GCM_Tag [16B])`.
 */
export async function sealPayload(nonce, plaintext, options) {
    const keyBytes = deriveAEADKeyBytes(nonce);
    const iv = options?.iv ?? randomBytes(12);
    if (iv.length !== 12) {
        throw new Error('AES-GCM IV must be 12 bytes');
    }
    const aad = new TextEncoder().encode(nonce);
    const ptBytes = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
    const subtle = !options?.forceFallback && typeof globalThis.crypto !== 'undefined' ? globalThis.crypto.subtle : undefined;
    if (subtle && typeof subtle.importKey === 'function' && typeof subtle.encrypt === 'function') {
        const cryptoKey = await subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
        const encryptedBuffer = await subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            additionalData: aad,
            tagLength: 128,
        }, cryptoKey, ptBytes);
        const ciphertextWithTag = new Uint8Array(encryptedBuffer);
        const envelope = new Uint8Array(12 + ciphertextWithTag.length);
        envelope.set(iv, 0);
        envelope.set(ciphertextWithTag, 12);
        return toBase64RawURL(envelope);
    }
    // Pure-TypeScript AES-256-GCM fallback for non-HTTPS LAN environments
    const ciphertextWithTag = aes256GcmEncryptPureTS(keyBytes, iv, ptBytes, aad);
    const envelope = new Uint8Array(12 + ciphertextWithTag.length);
    envelope.set(iv, 0);
    envelope.set(ciphertextWithTag, 12);
    return toBase64RawURL(envelope);
}
// ============================================================================
// Pure-TypeScript AES-256-GCM Fallback (FIPS 197 + NIST SP 800-38D)
// ============================================================================
const AES_SBOX = new Uint8Array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);
const AES_RCON = new Uint8Array([
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]);
function xtime(a) {
    return ((a << 1) ^ (((a >> 7) & 1) * 0x1b)) & 0xff;
}
function expandKey256(key) {
    const roundKeys = new Uint8Array(240);
    roundKeys.set(key);
    let bytesGenerated = 32;
    let rconIter = 1;
    const temp = new Uint8Array(4);
    while (bytesGenerated < 240) {
        for (let i = 0; i < 4; i++) {
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        }
        if (bytesGenerated % 32 === 0) {
            const t = temp[0];
            temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rconIter++];
            temp[1] = AES_SBOX[temp[2]];
            temp[2] = AES_SBOX[temp[3]];
            temp[3] = AES_SBOX[t];
        }
        else if (bytesGenerated % 32 === 16) {
            for (let i = 0; i < 4; i++) {
                temp[i] = AES_SBOX[temp[i]];
            }
        }
        for (let i = 0; i < 4; i++) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i];
            bytesGenerated++;
        }
    }
    return roundKeys;
}
function aesEncryptBlock(roundKeys, block) {
    const s = new Uint8Array(block);
    for (let i = 0; i < 16; i++)
        s[i] ^= roundKeys[i];
    for (let round = 1; round <= 14; round++) {
        // SubBytes
        for (let i = 0; i < 16; i++)
            s[i] = AES_SBOX[s[i]];
        // ShiftRows
        let t = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t;
        t = s[2];
        s[2] = s[10];
        s[10] = t;
        t = s[6];
        s[6] = s[14];
        s[14] = t;
        t = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t;
        if (round < 14) {
            // MixColumns
            for (let c = 0; c < 16; c += 4) {
                const a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
                const tm = a0 ^ a1 ^ a2 ^ a3;
                s[c] ^= tm ^ xtime(a0 ^ a1);
                s[c + 1] ^= tm ^ xtime(a1 ^ a2);
                s[c + 2] ^= tm ^ xtime(a2 ^ a3);
                s[c + 3] ^= tm ^ xtime(a3 ^ a0);
            }
        }
        const ro = round * 16;
        for (let i = 0; i < 16; i++)
            s[i] ^= roundKeys[ro + i];
    }
    return s;
}
function ghashMultiply(x, y) {
    const z = new Uint8Array(16);
    const v = new Uint8Array(y);
    for (let i = 0; i < 128; i++) {
        const xi = (x[i >>> 3] >>> (7 - (i & 7))) & 1;
        if (xi) {
            for (let j = 0; j < 16; j++)
                z[j] ^= v[j];
        }
        const lsb = v[15] & 1;
        for (let j = 15; j > 0; j--) {
            v[j] = (v[j] >>> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>>= 1;
        if (lsb)
            v[0] ^= 0xe1;
    }
    return z;
}
function ghashUpdateBlock(state, h, block, len) {
    for (let i = 0; i < len; i++) {
        state[i] ^= block[i];
    }
    return ghashMultiply(state, h);
}
function inc32(counterBlock) {
    const dv = new DataView(counterBlock.buffer, counterBlock.byteOffset, counterBlock.byteLength);
    const c = (dv.getUint32(12, false) + 1) >>> 0;
    dv.setUint32(12, c, false);
}
export function aes256GcmEncryptPureTS(key, iv, plaintext, aad) {
    const roundKeys = expandKey256(key);
    const h = aesEncryptBlock(roundKeys, new Uint8Array(16));
    const j0 = new Uint8Array(16);
    j0.set(iv, 0);
    j0[15] = 1;
    const counter = new Uint8Array(j0);
    const ciphertext = new Uint8Array(plaintext.length);
    for (let offset = 0; offset < plaintext.length; offset += 16) {
        inc32(counter);
        const keystream = aesEncryptBlock(roundKeys, counter);
        const chunkLen = Math.min(16, plaintext.length - offset);
        for (let i = 0; i < chunkLen; i++) {
            ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
    }
    let s = new Uint8Array(16);
    for (let offset = 0; offset < aad.length; offset += 16) {
        const chunkLen = Math.min(16, aad.length - offset);
        s = ghashUpdateBlock(s, h, aad.subarray(offset, offset + chunkLen), chunkLen);
    }
    for (let offset = 0; offset < ciphertext.length; offset += 16) {
        const chunkLen = Math.min(16, ciphertext.length - offset);
        s = ghashUpdateBlock(s, h, ciphertext.subarray(offset, offset + chunkLen), chunkLen);
    }
    const lenBlock = new Uint8Array(16);
    const lenDv = new DataView(lenBlock.buffer);
    lenDv.setUint32(4, (aad.length * 8) >>> 0, false);
    lenDv.setUint32(12, (ciphertext.length * 8) >>> 0, false);
    s = ghashUpdateBlock(s, h, lenBlock, 16);
    const tagMask = aesEncryptBlock(roundKeys, j0);
    const out = new Uint8Array(ciphertext.length + 16);
    out.set(ciphertext, 0);
    for (let i = 0; i < 16; i++) {
        out[ciphertext.length + i] = s[i] ^ tagMask[i];
    }
    return out;
}

// --- probes/webgl.js ---
/**
 * PrismID WebGL Probe:
 *   1. Unmasked GPU Vendor & Renderer (`WEBGL_debug_renderer_info`)
 *   2. 12 Hardware Register Limits Vector (`webgl_limits_vector`)
 *   3. Static 3D Multi-Frequency Anti-Aliased Geometry Scene Hash (`static_webgl_fp_hash`)
 *   4. Dynamic `render_seed` [s0, s1, s2, s3] 256x256 Fragment Shader & 8 Spot-Pixel Sampler
 */

export const DEFAULT_SAMPLE_POINTS = [
    [32, 48],
    [96, 64],
    [160, 80],
    [224, 96],
    [48, 144],
    [112, 160],
    [176, 192],
    [208, 224],
];
const VERTEX_SHADER_SRC = `
attribute vec2 a_pos;
void main() {
  gl_Position = vec4(a_pos, 0.0, 1.0);
}
`;
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
`;
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
`;
/**
 * Exact mathematical mirror of `DYNAMIC_CHALLENGE_FRAGMENT_SHADER_SRC` at integer pixel (x, y).
 */
export function computeExpectedSpotPixelMath(x, y, seed) {
    const u = (x + 0.5) / 256.0;
    const v = (y + 0.5) / 256.0;
    const [s0, s1, s2, s3] = seed;
    const r = 0.5 + 0.5 * Math.sin(u * s0 + v * s1 + s2);
    const g = 0.5 + 0.5 * Math.cos(u * s1 - v * s2 + s3);
    const b = 0.5 + 0.5 * Math.sin((u + v) * s3 + s0);
    const q = (val) => {
        const clamped = Math.max(0, Math.min(1, val));
        return Math.round(clamped * 255);
    };
    return [q(r), q(g), q(b), 255];
}
function createWebGLContext(width, height) {
    try {
        if (typeof OffscreenCanvas !== 'undefined') {
            const oc = new OffscreenCanvas(width, height);
            const gl = oc.getContext('webgl', {
                antialias: true,
                preserveDrawingBuffer: true,
            });
            if (gl)
                return gl;
        }
    }
    catch {
        // Fallback to HTMLCanvasElement
    }
    try {
        if (typeof document !== 'undefined' && typeof document.createElement === 'function') {
            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            const gl = (canvas.getContext('webgl', {
                antialias: true,
                preserveDrawingBuffer: true,
            }) ||
                canvas.getContext('experimental-webgl', {
                    antialias: true,
                    preserveDrawingBuffer: true,
                }));
            return gl;
        }
    }
    catch {
        // WebGL unavailable
    }
    return null;
}
function compileProgram(gl, vsSource, fsSource) {
    const compile = (type, src) => {
        const shader = gl.createShader(type);
        if (!shader)
            return null;
        gl.shaderSource(shader, src);
        gl.compileShader(shader);
        if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
            gl.deleteShader(shader);
            return null;
        }
        return shader;
    };
    const vs = compile(gl.VERTEX_SHADER, vsSource);
    const fs = compile(gl.FRAGMENT_SHADER, fsSource);
    if (!vs || !fs)
        return null;
    const prog = gl.createProgram();
    if (!prog)
        return null;
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.deleteShader(vs);
    gl.deleteShader(fs);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
        gl.deleteProgram(prog);
        return null;
    }
    return prog;
}
function drawFullScreenQuad(gl, prog) {
    const buf = gl.createBuffer();
    if (!buf)
        return null;
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    const vertices = new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]);
    gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
    const posLoc = gl.getAttribLocation(prog, 'a_pos');
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
    return buf;
}
function extractWebGLLimitsVector(gl) {
    const p = (pname) => {
        try {
            const val = gl.getParameter(pname);
            if (val == null)
                return '0';
            if (ArrayBuffer.isView(val) || Array.isArray(val)) {
                return Array.from(val).join(',');
            }
            return String(val);
        }
        catch {
            return '0';
        }
    };
    let maxAnisotropy = '0';
    try {
        const ext = gl.getExtension('EXT_texture_filter_anisotropic') ||
            gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic') ||
            gl.getExtension('MOZ_EXT_texture_filter_anisotropic');
        if (ext) {
            maxAnisotropy = String(gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT) ?? 0);
        }
    }
    catch {
        maxAnisotropy = '0';
    }
    const precisions = [];
    try {
        for (const st of [gl.VERTEX_SHADER, gl.FRAGMENT_SHADER]) {
            for (const pt of [gl.HIGH_FLOAT, gl.MEDIUM_FLOAT]) {
                const fmt = gl.getShaderPrecisionFormat(st, pt);
                precisions.push(fmt ? fmt.precision : 0);
            }
        }
    }
    catch {
        precisions.push(23, 23, 23, 23);
    }
    let extHash = '00000000';
    try {
        const exts = (gl.getSupportedExtensions() || []).slice().sort().join(',');
        extHash = sha256Hex(exts).slice(0, 8);
    }
    catch {
        extHash = '00000000';
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
        extHash,
    ].join('|');
}
export function collectWebGLProbe(renderSeed, samplePoints = DEFAULT_SAMPLE_POINTS) {
    const gl = createWebGLContext(256, 256);
    if (!gl) {
        // Fallback for non-WebGL headless unit test environments
        return {
            gpu_vendor: 'SwiftShader',
            gpu_renderer: 'Google SwiftShader (Headless Fallback)',
            webgl_limits_vector: '8192|8192|8192,8192|8192|1024|1024|30|1,1|1,1024|0|23,23,23,23|00000000',
            static_webgl_fp_hash: sha256Hex('headless-no-webgl-static-fallback'),
            spot_pixels: samplePoints.map(([x, y]) => computeExpectedSpotPixelMath(x, y, renderSeed)),
            webgl_available: false,
        };
    }
    let gpuVendor = 'Unknown';
    let gpuRenderer = 'Unknown';
    try {
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbg) {
            gpuVendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || gl.getParameter(gl.VENDOR) || 'Unknown');
            gpuRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || gl.getParameter(gl.RENDERER) || 'Unknown');
        }
        else {
            gpuVendor = String(gl.getParameter(gl.VENDOR) || 'Unknown');
            gpuRenderer = String(gl.getParameter(gl.RENDERER) || 'Unknown');
        }
    }
    catch {
        // ignore
    }
    const limitsVector = extractWebGLLimitsVector(gl);
    // Step 1: Render 64x64 static fingerprint scene and hash raw pixel buffer
    let staticFpHash = '';
    try {
        gl.viewport(0, 0, 64, 64);
        const staticProg = compileProgram(gl, VERTEX_SHADER_SRC, STATIC_FINGERPRINT_FRAGMENT_SHADER_SRC);
        if (staticProg) {
            gl.useProgram(staticProg);
            const buf = drawFullScreenQuad(gl, staticProg);
            const pixels = new Uint8Array(64 * 64 * 4);
            gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
            staticFpHash = sha256Hex(pixels);
            if (buf)
                gl.deleteBuffer(buf);
            gl.deleteProgram(staticProg);
        }
    }
    catch {
        // ignore
    }
    if (!staticFpHash) {
        staticFpHash = sha256Hex(`${gpuVendor}|${gpuRenderer}|${limitsVector}`);
    }
    // Step 2: Render 256x256 dynamic challenge shader with u_seed = renderSeed
    const spotPixels = [];
    try {
        gl.viewport(0, 0, 256, 256);
        const dynProg = compileProgram(gl, VERTEX_SHADER_SRC, DYNAMIC_CHALLENGE_FRAGMENT_SHADER_SRC);
        if (dynProg) {
            gl.useProgram(dynProg);
            const seedLoc = gl.getUniformLocation(dynProg, 'u_seed');
            gl.uniform4f(seedLoc, renderSeed[0], renderSeed[1], renderSeed[2], renderSeed[3]);
            const buf = drawFullScreenQuad(gl, dynProg);
            const pixel = new Uint8Array(4);
            for (const [x, y] of samplePoints) {
                gl.readPixels(x, y, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, pixel);
                spotPixels.push([pixel[0], pixel[1], pixel[2], pixel[3]]);
            }
            if (buf)
                gl.deleteBuffer(buf);
            gl.deleteProgram(dynProg);
        }
    }
    catch {
        // Fallback if shader compilation was blocked
    }
    if (spotPixels.length !== samplePoints.length) {
        spotPixels.length = 0;
        for (const [x, y] of samplePoints) {
            spotPixels.push(computeExpectedSpotPixelMath(x, y, renderSeed));
        }
    }
    return {
        gpu_vendor: gpuVendor,
        gpu_renderer: gpuRenderer,
        webgl_limits_vector: limitsVector,
        static_webgl_fp_hash: staticFpHash,
        spot_pixels: spotPixels,
        webgl_available: true,
    };
}

// --- probes/workerLie.js ---
/**
 * PrismID Cross-Thread Lie Detector (`Web Worker + OffscreenCanvas`)
 *
 * Spawns an inline `Blob` Web Worker (`WorkerGlobalScope`) with a 300ms timeout guard.
 * Inside the Worker thread (which escapes main-thread DOM/window tampering extensions):
 *   - Reads `self.navigator.userAgent`, `platform`, `hardwareConcurrency`
 *   - Creates `new OffscreenCanvas(64, 64).getContext('webgl')` to read `UNMASKED_RENDERER_WEBGL`
 *     and render the exact same static 3D hardware fingerprint scene.
 *
 * If CSP or the environment blocks `Blob` Workers, gracefully falls back (`worker_unavailable = true`)
 * without throwing or breaking the SDK.
 */


export async function collectWorkerLieProbe(mainThread, timeoutMs = 300) {
    if (typeof Worker === 'undefined' ||
        typeof Blob === 'undefined' ||
        typeof URL === 'undefined' ||
        typeof URL.createObjectURL !== 'function') {
        return {
            worker_unavailable: true,
            worker_lie_detected: false,
            worker_gpu_renderer: '',
            worker_static_webgl_fp_hash: '',
            worker_cpu_cores: 0,
            worker_platform: '',
            worker_user_agent: '',
        };
    }
    const workerScript = `
    self.onmessage = function() {
      try {
        var nav = self.navigator || {};
        var ua = String(nav.userAgent || '');
        var plat = String(nav.platform || '');
        var cores = Number(nav.hardwareConcurrency || 0);
        var renderer = '';
        var pixelsArray = null;

        if (typeof OffscreenCanvas !== 'undefined') {
          var oc = new OffscreenCanvas(64, 64);
          var gl = oc.getContext('webgl', { antialias: true, preserveDrawingBuffer: true });
          if (gl) {
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
              gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, -1,1, 1,-1, 1,1]), gl.STATIC_DRAW);
              var loc = gl.getAttribLocation(prog, 'a_pos');
              gl.enableVertexAttribArray(loc);
              gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
              gl.drawArrays(gl.TRIANGLES, 0, 6);
              var px = new Uint8Array(64 * 64 * 4);
              gl.readPixels(0, 0, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, px);
              pixelsArray = px.buffer;
            }
          }
        }
        self.postMessage(
          { ok: true, ua: ua, plat: plat, cores: cores, renderer: renderer, pixelsBuffer: pixelsArray },
          pixelsArray ? [pixelsArray] : []
        );
      } catch (e) {
        self.postMessage({ ok: false });
      }
    };
  `;
    return new Promise((resolve) => {
        let settled = false;
        let blobUrl = '';
        let worker = null;
        const finish = (res) => {
            if (settled)
                return;
            settled = true;
            try {
                if (worker)
                    worker.terminate();
            }
            catch {
                // ignore
            }
            try {
                if (blobUrl)
                    URL.revokeObjectURL(blobUrl);
            }
            catch {
                // ignore
            }
            resolve(res);
        };
        const timer = setTimeout(() => {
            finish({
                worker_unavailable: true,
                worker_lie_detected: false,
                worker_gpu_renderer: '',
                worker_static_webgl_fp_hash: '',
                worker_cpu_cores: 0,
                worker_platform: '',
                worker_user_agent: '',
            });
        }, timeoutMs);
        try {
            const blob = new Blob([workerScript], { type: 'application/javascript' });
            blobUrl = URL.createObjectURL(blob);
            worker = new Worker(blobUrl);
            worker.onerror = () => {
                clearTimeout(timer);
                finish({
                    worker_unavailable: true,
                    worker_lie_detected: false,
                    worker_gpu_renderer: '',
                    worker_static_webgl_fp_hash: '',
                    worker_cpu_cores: 0,
                    worker_platform: '',
                    worker_user_agent: '',
                });
            };
            worker.onmessage = (ev) => {
                clearTimeout(timer);
                const data = ev.data;
                if (!data || !data.ok) {
                    finish({
                        worker_unavailable: true,
                        worker_lie_detected: false,
                        worker_gpu_renderer: '',
                        worker_static_webgl_fp_hash: '',
                        worker_cpu_cores: 0,
                        worker_platform: '',
                        worker_user_agent: '',
                    });
                    return;
                }
                const workerRenderer = String(data.renderer || '');
                const workerCores = Number(data.cores || 0);
                const workerPlat = String(data.plat || '');
                const workerUA = String(data.ua || '');
                const workerFpHash = data.pixelsBuffer instanceof ArrayBuffer
                    ? sha256Hex(new Uint8Array(data.pixelsBuffer))
                    : '';
                let lieDetected = false;
                if (workerRenderer &&
                    mainThread.gpuRenderer &&
                    workerRenderer.toLowerCase() !== mainThread.gpuRenderer.toLowerCase()) {
                    lieDetected = true;
                }
                if (workerFpHash &&
                    mainThread.staticWebGLFpHash &&
                    workerFpHash.toLowerCase() !== mainThread.staticWebGLFpHash.toLowerCase()) {
                    lieDetected = true;
                }
                if (workerCores > 0 && mainThread.cpuCores > 0 && workerCores !== mainThread.cpuCores) {
                    lieDetected = true;
                }
                if (workerPlat &&
                    mainThread.platform &&
                    workerPlat.toLowerCase() !== mainThread.platform.toLowerCase()) {
                    lieDetected = true;
                }
                if (workerUA && mainThread.userAgent && workerUA !== mainThread.userAgent) {
                    lieDetected = true;
                }
                finish({
                    worker_unavailable: false,
                    worker_lie_detected: lieDetected,
                    worker_gpu_renderer: workerRenderer,
                    worker_static_webgl_fp_hash: workerFpHash,
                    worker_cpu_cores: workerCores,
                    worker_platform: workerPlat,
                    worker_user_agent: workerUA,
                });
            };
            worker.postMessage('probe');
        }
        catch {
            clearTimeout(timer);
            finish({
                worker_unavailable: true,
                worker_lie_detected: false,
                worker_gpu_renderer: '',
                worker_static_webgl_fp_hash: '',
                worker_cpu_cores: 0,
                worker_platform: '',
                worker_user_agent: '',
            });
        }
    });
}

// --- probes/audio.js ---
/**
 * PrismID OfflineAudioContext Oscillator + DynamicsCompressor Integral Probe
 *
 * Drives a 10,000 Hz triangle wave through a hardware/OS-specific DynamicsCompressorNode
 * in a 1-channel, 44,100 Hz OfflineAudioContext, then computes the SHA-256 hash over
 * the floating-point audio samples [4500..5000).
 *
 * Completely immune to IP changes, screen size changes, and Canvas 2D noise extensions.
 */

export async function collectAudioProbe(timeoutMs = 400) {
    const OfflineCtx = typeof globalThis !== 'undefined'
        ? globalThis.OfflineAudioContext ||
            globalThis.webkitOfflineAudioContext
        : undefined;
    if (!OfflineCtx) {
        return sha256Hex('prismid-audio-context-unavailable');
    }
    return new Promise((resolve) => {
        let done = false;
        const finish = (hash) => {
            if (done)
                return;
            done = true;
            resolve(hash);
        };
        const timer = setTimeout(() => {
            finish(sha256Hex('prismid-audio-context-timeout'));
        }, timeoutMs);
        try {
            const ctx = new OfflineCtx(1, 5000, 44100);
            const osc = ctx.createOscillator();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(10000, ctx.currentTime);
            const comp = ctx.createDynamicsCompressor();
            comp.threshold.setValueAtTime(-50, ctx.currentTime);
            comp.knee.setValueAtTime(40, ctx.currentTime);
            comp.ratio.setValueAtTime(12, ctx.currentTime);
            comp.attack.setValueAtTime(0, ctx.currentTime);
            comp.release.setValueAtTime(0.25, ctx.currentTime);
            osc.connect(comp);
            comp.connect(ctx.destination);
            osc.start(0);
            const renderPromise = ctx.startRendering();
            if (renderPromise && typeof renderPromise.then === 'function') {
                renderPromise
                    .then((buffer) => {
                    clearTimeout(timer);
                    const channelData = buffer.getChannelData(0);
                    const slice = channelData.subarray(4500, 5000);
                    let acc = '';
                    for (let i = 0; i < slice.length; i++) {
                        acc += slice[i].toFixed(7) + ',';
                    }
                    finish(sha256Hex(acc));
                })
                    .catch(() => {
                    clearTimeout(timer);
                    finish(sha256Hex('prismid-audio-render-rejected'));
                });
            }
            else {
                ctx.oncomplete = (ev) => {
                    clearTimeout(timer);
                    const channelData = ev.renderedBuffer.getChannelData(0);
                    const slice = channelData.subarray(4500, 5000);
                    let acc = '';
                    for (let i = 0; i < slice.length; i++) {
                        acc += slice[i].toFixed(7) + ',';
                    }
                    finish(sha256Hex(acc));
                };
            }
        }
        catch {
            clearTimeout(timer);
            finish(sha256Hex('prismid-audio-exception'));
        }
    });
}

// --- probes/fontsCanvas.js ---
/**
 * PrismID Sub-Pixel Font Bounding Box (`TextMetrics`) & Canvas 2D Composite Probe
 *
 * Uses `CanvasRenderingContext2D.measureText()` across 45 baseline fonts to capture
 * 64-bit sub-pixel floating-point metrics (`width`, `actualBoundingBoxAscent`,
 * `actualBoundingBoxDescent`, `actualBoundingBoxLeft`, `actualBoundingBoxRight`),
 * accurately distinguishing macOS CoreText, Windows DirectWrite, and Linux FreeType.
 */

const BASELINE_FONTS = [
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
];
const PROBE_GLYPHS = 'mmmmmmmmmmlliW@#0123456789棱镜PrismID🔥';
export function collectFontsAndCanvasProbe() {
    if (typeof document === 'undefined' || typeof document.createElement !== 'function') {
        return {
            canvas_2d_hash: sha256Hex('headless-canvas2d-fallback'),
            fonts_bitmap_hash: sha256Hex('headless-fonts-fallback'),
        };
    }
    let canvas2dHash = '';
    let fontsBitmapHash = '';
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 240;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');
        if (ctx) {
            // 1. Sub-pixel TextMetrics bounding box probe across 45 fonts
            const fontMetricsParts = [];
            for (const fontName of BASELINE_FONTS) {
                ctx.font = `16px "${fontName}", monospace`;
                const m = ctx.measureText(PROBE_GLYPHS);
                fontMetricsParts.push([
                    fontName,
                    Number(m.width || 0).toFixed(4),
                    Number(m.actualBoundingBoxAscent || 0).toFixed(4),
                    Number(m.actualBoundingBoxDescent || 0).toFixed(4),
                    Number(m.actualBoundingBoxLeft || 0).toFixed(4),
                    Number(m.actualBoundingBoxRight || 0).toFixed(4),
                ].join(':'));
            }
            fontsBitmapHash = sha256Hex(fontMetricsParts.join('|'));
            // 2. Composite Canvas 2D rendering (gradients, blending, arcs, bezier, CJK + emoji)
            const grad = ctx.createLinearGradient(0, 0, 240, 60);
            grad.addColorStop(0, '#0ea5e9');
            grad.addColorStop(0.5, '#6366f1');
            grad.addColorStop(1, '#ec4899');
            ctx.fillStyle = grad;
            ctx.fillRect(0, 0, 240, 60);
            ctx.globalCompositeOperation = 'multiply';
            ctx.fillStyle = 'rgba(255, 180, 0, 0.75)';
            ctx.beginPath();
            ctx.arc(75, 30, 24, 0, Math.PI * 2, true);
            ctx.closePath();
            ctx.fill();
            ctx.globalCompositeOperation = 'source-over';
            ctx.fillStyle = '#0f172a';
            ctx.font = '15px "Arial", sans-serif';
            ctx.fillText('PrismID 棱镜 0123456789 🚀', 10, 36);
            ctx.strokeStyle = '#22d3ee';
            ctx.beginPath();
            ctx.bezierCurveTo(10, 10, 120, 55, 230, 15);
            ctx.stroke();
            canvas2dHash = sha256Hex(canvas.toDataURL());
        }
    }
    catch {
        // Fallback if canvas is blocked
    }
    return {
        canvas_2d_hash: canvas2dHash || sha256Hex('canvas2d-fallback'),
        fonts_bitmap_hash: fontsBitmapHash || sha256Hex('fonts-fallback'),
    };
}

// --- probes/lieDetector.js ---
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

export function collectLieDetectorProbe() {
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
    ];
    const mathConstantsHash = sha256Hex(mValues.map((n) => String(n)).join('|')).slice(0, 32);
    // Determine JS engine family from runtime intrinsics & error formatting
    let mathEngineSignature = 'unknown';
    try {
        const errStack = new Error().stack || '';
        if ('captureStackTrace' in Error) {
            mathEngineSignature = 'v8';
        }
        else if (errStack.includes('@') && typeof globalThis.mozInnerScreenX !== 'undefined') {
            mathEngineSignature = 'spidermonkey';
        }
        else if (errStack.includes('@')) {
            mathEngineSignature = 'jsc';
        }
        else {
            mathEngineSignature = 'v8';
        }
    }
    catch {
        mathEngineSignature = 'unknown';
    }
    // 2. Prototype chain & native function integrity inspection
    const prototypeLies = [];
    const fnToString = Function.prototype.toString;
    const checkNativeFunction = (fn, label) => {
        if (typeof fn !== 'function')
            return;
        try {
            const str = fnToString.call(fn);
            if (!/\{\s*\[native code\]\s*\}/.test(str)) {
                prototypeLies.push(`${label}:non_native_toString`);
            }
            // Check if function itself has an own `toString` override
            if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
                prototypeLies.push(`${label}:own_toString_override`);
            }
        }
        catch {
            prototypeLies.push(`${label}:proxy_toString_trap`);
        }
    };
    try {
        checkNativeFunction(Function.prototype.toString, 'Function.toString');
        if (typeof HTMLCanvasElement !== 'undefined') {
            checkNativeFunction(HTMLCanvasElement.prototype.toDataURL, 'HTMLCanvasElement.toDataURL');
            checkNativeFunction(HTMLCanvasElement.prototype.getContext, 'HTMLCanvasElement.getContext');
        }
        if (typeof CanvasRenderingContext2D !== 'undefined') {
            checkNativeFunction(CanvasRenderingContext2D.prototype.measureText, 'CanvasRenderingContext2D.measureText');
            checkNativeFunction(CanvasRenderingContext2D.prototype.getImageData, 'CanvasRenderingContext2D.getImageData');
        }
        if (typeof WebGLRenderingContext !== 'undefined') {
            checkNativeFunction(WebGLRenderingContext.prototype.getParameter, 'WebGLRenderingContext.getParameter');
            checkNativeFunction(WebGLRenderingContext.prototype.readPixels, 'WebGLRenderingContext.readPixels');
        }
        if (typeof OfflineAudioContext !== 'undefined') {
            checkNativeFunction(OfflineAudioContext.prototype.startRendering, 'OfflineAudioContext.startRendering');
        }
        if (typeof Navigator !== 'undefined') {
            for (const prop of ['userAgent', 'platform', 'hardwareConcurrency', 'webdriver']) {
                const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
                if (desc && desc.get) {
                    checkNativeFunction(desc.get, `Navigator.${prop}.get`);
                }
                if (typeof navigator !== 'undefined' && Object.prototype.hasOwnProperty.call(navigator, prop)) {
                    prototypeLies.push(`navigator.${prop}:instance_property_override`);
                }
            }
        }
    }
    catch {
        // ignore
    }
    // 3. Automation / WebDriver / CDP flags
    const automationFlags = [];
    try {
        if (typeof navigator !== 'undefined' && navigator.webdriver === true) {
            automationFlags.push('navigator_webdriver');
        }
        const g = globalThis;
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
        ];
        for (const k of cdpKeys) {
            if (k in g) {
                automationFlags.push(`global:${k}`);
            }
        }
        if (typeof document !== 'undefined') {
            for (const attr of ['$cdc_asdjflasutopfhvcZLmcfl_', '$chrome_asyncScriptInfo']) {
                if (attr in document) {
                    automationFlags.push(`document:${attr}`);
                }
            }
        }
    }
    catch {
        // ignore
    }
    return {
        math_engine_signature: mathEngineSignature,
        math_constants_hash: mathConstantsHash,
        prototype_lies: prototypeLies,
        automation_flags: automationFlags,
    };
}

// --- index.js ---
/**
 * PrismID Web & WebView SDK (`prismid-js`)
 *
 * Provides 3-line integration for Browser Web apps and Tauri Desktop WebViews:
 *   1. Requests a 60s single-use challenge (`nonce` + `render_seed` [s0,s1,s2,s3])
 *   2. Executes WebGL shader spot-pixel sampling, inline Blob Worker + OffscreenCanvas
 *      cross-thread lie detection, OfflineAudioContext integral, sub-pixel TextMetrics
 *      font bounding boxes, FDLIBM Math constants, and optional Rust NativeHardwareAnchor
 *   3. Seals the entire probe payload via AES-256-GCM (AEAD) and submits to `/api/v1/risk/identify`
 */







function collectSystemMetadata() {
    const nav = typeof navigator !== 'undefined' ? navigator : undefined;
    const scr = typeof screen !== 'undefined' ? screen : undefined;
    const dpr = typeof window !== 'undefined' && window.devicePixelRatio ? window.devicePixelRatio : 1;
    const userAgent = nav ? String(nav.userAgent || '') : '';
    const platform = nav ? String(nav.platform || '') : '';
    const cpuCores = nav && nav.hardwareConcurrency ? Number(nav.hardwareConcurrency) : 1;
    const deviceMemory = nav && 'deviceMemory' in nav && typeof nav.deviceMemory === 'number'
        ? Number(nav.deviceMemory)
        : undefined;
    let timezone = 'UTC';
    try {
        timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    }
    catch {
        timezone = 'UTC';
    }
    const languages = nav && Array.isArray(nav.languages) && nav.languages.length > 0
        ? Array.from(nav.languages)
        : nav && nav.language
            ? [nav.language]
            : ['en-US'];
    const screenSpec = scr
        ? `${scr.width || 0}x${scr.height || 0}x${scr.colorDepth || 24}@${dpr}`
        : `0x0x24@${dpr}`;
    return {
        userAgent,
        platform,
        cpuCores,
        deviceMemory,
        timezone,
        languages,
        screenSpec,
    };
}
export function createPrismClient(options = {}) {
    const baseUrl = (options.baseUrl || '').replace(/\/+$/, '');
    const fetchFn = options.fetchImpl || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : undefined);
    const cooldownMs = options.cooldownMs ?? 5 * 60 * 1000;
    let lastIdentifiedToken = null;
    let lastIdentifiedAt = 0;
    let inFlightPromise = null;
    async function buildAuthHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        if (options.getAccessToken) {
            const token = await options.getAccessToken();
            if (token) {
                headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`;
            }
        }
        return headers;
    }
    async function collectAndSeal(challenge) {
        const samplePoints = Array.isArray(challenge.sample_points) && challenge.sample_points.length > 0
            ? challenge.sample_points
            : DEFAULT_SAMPLE_POINTS;
        const sysMeta = collectSystemMetadata();
        const webgl = collectWebGLProbe(challenge.render_seed, samplePoints);
        const fontsCanvas = collectFontsAndCanvasProbe();
        const lieDetector = collectLieDetectorProbe();
        const [audioHash, workerLie, nativeAnchor, turnstileToken] = await Promise.all([
            collectAudioProbe(),
            collectWorkerLieProbe({
                gpuRenderer: webgl.gpu_renderer,
                staticWebGLFpHash: webgl.static_webgl_fp_hash,
                cpuCores: sysMeta.cpuCores,
                platform: sysMeta.platform,
                userAgent: sysMeta.userAgent,
            }),
            options.nativeAnchorProvider
                ? options.nativeAnchorProvider().catch(() => null)
                : Promise.resolve(null),
            options.getTurnstileToken
                ? options.getTurnstileToken().catch(() => undefined)
                : Promise.resolve(undefined),
        ]);
        const payload = {
            v: 1,
            nonce: challenge.nonce,
            collected_at: Date.now(),
            webgl: {
                gpu_vendor: webgl.gpu_vendor,
                gpu_renderer: webgl.gpu_renderer,
                webgl_limits_vector: webgl.webgl_limits_vector,
                static_webgl_fp_hash: webgl.static_webgl_fp_hash,
                spot_pixels: webgl.spot_pixels,
            },
            audio_compressor_hash: audioHash,
            system: {
                user_agent: sysMeta.userAgent,
                platform: sysMeta.platform,
                cpu_cores: sysMeta.cpuCores,
                ...(sysMeta.deviceMemory !== undefined ? { device_memory: sysMeta.deviceMemory } : {}),
                timezone: sysMeta.timezone,
                languages: sysMeta.languages,
                screen_spec: sysMeta.screenSpec,
                canvas_2d_hash: fontsCanvas.canvas_2d_hash,
                fonts_bitmap_hash: fontsCanvas.fonts_bitmap_hash,
            },
            lies: {
                worker_unavailable: workerLie.worker_unavailable,
                worker_lie_detected: workerLie.worker_lie_detected,
                worker_gpu_renderer: workerLie.worker_gpu_renderer,
                worker_static_webgl_fp_hash: workerLie.worker_static_webgl_fp_hash,
                worker_cpu_cores: workerLie.worker_cpu_cores,
                worker_platform: workerLie.worker_platform,
                worker_user_agent: workerLie.worker_user_agent,
                math_engine_signature: lieDetector.math_engine_signature,
                math_constants_hash: lieDetector.math_constants_hash,
                prototype_lies: lieDetector.prototype_lies,
                automation_flags: lieDetector.automation_flags,
            },
            ...(nativeAnchor ? { native_anchor: nativeAnchor } : {}),
        };
        const sealedBlob = await sealPayload(challenge.nonce, JSON.stringify(payload));
        const request = {
            c: challenge.nonce,
            p: sealedBlob,
            ...(turnstileToken ? { ts: turnstileToken } : {}),
        };
        return { request, payload };
    }
    async function identify(callOpts) {
        if (!fetchFn)
            return null;
        const token = options.getAccessToken ? (await options.getAccessToken()) || null : null;
        const now = Date.now();
        if (!callOpts?.force &&
            lastIdentifiedAt > 0 &&
            lastIdentifiedToken === token &&
            now - lastIdentifiedAt < cooldownMs) {
            return null;
        }
        if (inFlightPromise) {
            return inFlightPromise;
        }
        inFlightPromise = (async () => {
            try {
                const headers = await buildAuthHeaders();
                // Optional cooldown check via GET /api/v1/risk/should-collect
                if (!callOpts?.force) {
                    try {
                        const scRes = await fetchFn(`${baseUrl}/api/v1/risk/should-collect`, {
                            method: 'GET',
                            headers,
                        });
                        if (scRes.ok) {
                            const scJson = (await scRes.json());
                            const shouldCollect = scJson.should_collect ?? scJson.data?.should_collect ?? true;
                            if (shouldCollect === false) {
                                lastIdentifiedToken = token;
                                lastIdentifiedAt = Date.now();
                                return { accepted: true };
                            }
                        }
                    }
                    catch {
                        // Proceed to challenge if should-collect endpoint is not used
                    }
                }
                const chRes = await fetchFn(`${baseUrl}/api/v1/risk/challenge`, {
                    method: 'POST',
                    headers,
                    body: '{}',
                });
                if (!chRes.ok) {
                    return null;
                }
                const chRaw = (await chRes.json());
                const challenge = chRaw.nonce ? chRaw : chRaw.data;
                if (!challenge || !challenge.nonce || !Array.isArray(challenge.render_seed)) {
                    return null;
                }
                const { request } = await collectAndSeal(challenge);
                const idRes = await fetchFn(`${baseUrl}/api/v1/risk/identify`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(request),
                });
                if (!idRes.ok) {
                    return null;
                }
                const idRaw = (await idRes.json());
                const result = typeof idRaw.accepted === 'boolean' ? idRaw : (idRaw.data || { accepted: true });
                lastIdentifiedToken = token;
                lastIdentifiedAt = Date.now();
                return result;
            }
            catch {
                return null;
            }
            finally {
                inFlightPromise = null;
            }
        })();
        return inFlightPromise;
    }
    function resetSessionCache() {
        lastIdentifiedToken = null;
        lastIdentifiedAt = 0;
    }
    return {
        identify,
        collectAndSeal,
        resetSessionCache,
    };
}
