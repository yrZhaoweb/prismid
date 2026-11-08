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

export const AEAD_KEY_DOMAIN_PREFIX = 'prismid-v1-aead:'

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

function rotr32(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n))
}

/**
 * Pure TypeScript SHA-256 implementation returning a 32-byte Uint8Array.
 * Works synchronously in any browser, WebView, Worker, or non-HTTPS LAN context.
 */
export function sha256Bytes(input: string | Uint8Array): Uint8Array {
  const msg = typeof input === 'string' ? new TextEncoder().encode(input) : input
  const bitLenHi = Math.floor((msg.length * 8) / 0x100000000)
  const bitLenLo = (msg.length * 8) >>> 0

  const padLen = ((msg.length + 9 + 63) & ~63)
  const padded = new Uint8Array(padLen)
  padded.set(msg)
  padded[msg.length] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padLen - 8, bitLenHi, false)
  dv.setUint32(padLen - 4, bitLenLo, false)

  let h0 = 0x6a09e667
  let h1 = 0xbb67ae85
  let h2 = 0x3c6ef372
  let h3 = 0xa54ff53a
  let h4 = 0x510e527f
  let h5 = 0x9b05688c
  let h6 = 0x1f83d9ab
  let h7 = 0x5be0cd19

  const w = new Uint32Array(64)

  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = dv.getUint32(offset + i * 4, false)
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3)
      const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10)
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0
    }

    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    let f = h5
    let g = h6
    let h = h7

    for (let i = 0; i < 64; i++) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      const ch = (e & f) ^ (~e & g)
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const temp2 = (S0 + maj) >>> 0

      h = g
      g = f
      f = e
      e = (d + temp1) >>> 0
      d = c
      c = b
      b = a
      a = (temp1 + temp2) >>> 0
    }

    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
    h5 = (h5 + f) >>> 0
    h6 = (h6 + g) >>> 0
    h7 = (h7 + h) >>> 0
  }

  const out = new Uint8Array(32)
  const outDv = new DataView(out.buffer)
  outDv.setUint32(0, h0, false)
  outDv.setUint32(4, h1, false)
  outDv.setUint32(8, h2, false)
  outDv.setUint32(12, h3, false)
  outDv.setUint32(16, h4, false)
  outDv.setUint32(20, h5, false)
  outDv.setUint32(24, h6, false)
  outDv.setUint32(28, h7, false)
  return out
}

export function sha256Hex(input: string | Uint8Array): string {
  const bytes = sha256Bytes(input)
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

export function deriveAEADKeyBytes(nonce: string): Uint8Array {
  return sha256Bytes(AEAD_KEY_DOMAIN_PREFIX + nonce)
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length)
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(buf)
    return buf
  }
  for (let i = 0; i < length; i++) {
    buf[i] = Math.floor(Math.random() * 256)
  }
  return buf
}

export function toBase64RawURL(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  const b64 =
    typeof btoa === 'function'
      ? btoa(binary)
      : Buffer.from(bytes).toString('base64')
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

/**
 * Seals plaintext UTF-8 string or bytes using AES-256-GCM and returns
 * `Base64RawURL(IV [12B] || Ciphertext || GCM_Tag [16B])`.
 */
export async function sealPayload(
  nonce: string,
  plaintext: string | Uint8Array,
  options?: { iv?: Uint8Array; forceFallback?: boolean }
): Promise<string> {
  const keyBytes = deriveAEADKeyBytes(nonce)
  const iv = options?.iv ?? randomBytes(12)
  if (iv.length !== 12) {
    throw new Error('AES-GCM IV must be 12 bytes')
  }
  const aad = new TextEncoder().encode(nonce)
  const ptBytes = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext

  const subtle = !options?.forceFallback && typeof globalThis.crypto !== 'undefined' ? globalThis.crypto.subtle : undefined
  if (subtle && typeof subtle.importKey === 'function' && typeof subtle.encrypt === 'function') {
    const cryptoKey = await subtle.importKey(
      'raw',
      keyBytes as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    )
    const encryptedBuffer = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        additionalData: aad as BufferSource,
        tagLength: 128,
      },
      cryptoKey,
      ptBytes as BufferSource
    )
    const ciphertextWithTag = new Uint8Array(encryptedBuffer)
    const envelope = new Uint8Array(12 + ciphertextWithTag.length)
    envelope.set(iv, 0)
    envelope.set(ciphertextWithTag, 12)
    return toBase64RawURL(envelope)
  }

  // Pure-TypeScript AES-256-GCM fallback for non-HTTPS LAN environments
  const ciphertextWithTag = aes256GcmEncryptPureTS(keyBytes, iv, ptBytes, aad)
  const envelope = new Uint8Array(12 + ciphertextWithTag.length)
  envelope.set(iv, 0)
  envelope.set(ciphertextWithTag, 12)
  return toBase64RawURL(envelope)
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
])

const AES_RCON = new Uint8Array([
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
])

function xtime(a: number): number {
  return ((a << 1) ^ (((a >> 7) & 1) * 0x1b)) & 0xff
}

function expandKey256(key: Uint8Array): Uint8Array {
  const roundKeys = new Uint8Array(240)
  roundKeys.set(key)
  let bytesGenerated = 32
  let rconIter = 1
  const temp = new Uint8Array(4)

  while (bytesGenerated < 240) {
    for (let i = 0; i < 4; i++) {
      temp[i] = roundKeys[bytesGenerated - 4 + i]
    }
    if (bytesGenerated % 32 === 0) {
      const t = temp[0]
      temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rconIter++]
      temp[1] = AES_SBOX[temp[2]]
      temp[2] = AES_SBOX[temp[3]]
      temp[3] = AES_SBOX[t]
    } else if (bytesGenerated % 32 === 16) {
      for (let i = 0; i < 4; i++) {
        temp[i] = AES_SBOX[temp[i]]
      }
    }
    for (let i = 0; i < 4; i++) {
      roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i]
      bytesGenerated++
    }
  }
  return roundKeys
}

function aesEncryptBlock(roundKeys: Uint8Array, block: Uint8Array): Uint8Array {
  const s = new Uint8Array(block)
  for (let i = 0; i < 16; i++) s[i] ^= roundKeys[i]

  for (let round = 1; round <= 14; round++) {
    // SubBytes
    for (let i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]]
    // ShiftRows
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t

    if (round < 14) {
      // MixColumns
      for (let c = 0; c < 16; c += 4) {
        const a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3]
        const tm = a0 ^ a1 ^ a2 ^ a3
        s[c] ^= tm ^ xtime(a0 ^ a1)
        s[c + 1] ^= tm ^ xtime(a1 ^ a2)
        s[c + 2] ^= tm ^ xtime(a2 ^ a3)
        s[c + 3] ^= tm ^ xtime(a3 ^ a0)
      }
    }
    const ro = round * 16
    for (let i = 0; i < 16; i++) s[i] ^= roundKeys[ro + i]
  }
  return s
}

function ghashMultiply(x: Uint8Array, y: Uint8Array): Uint8Array {
  const z = new Uint8Array(16)
  const v = new Uint8Array(y)
  for (let i = 0; i < 128; i++) {
    const xi = (x[i >>> 3] >>> (7 - (i & 7))) & 1
    if (xi) {
      for (let j = 0; j < 16; j++) z[j] ^= v[j]
    }
    const lsb = v[15] & 1
    for (let j = 15; j > 0; j--) {
      v[j] = (v[j] >>> 1) | ((v[j - 1] & 1) << 7)
    }
    v[0] >>>= 1
    if (lsb) v[0] ^= 0xe1
  }
  return z
}

function ghashUpdateBlock(state: Uint8Array, h: Uint8Array, block: Uint8Array, len: number): Uint8Array {
  for (let i = 0; i < len; i++) {
    state[i] ^= block[i]
  }
  return ghashMultiply(state, h)
}

function inc32(counterBlock: Uint8Array): void {
  const dv = new DataView(counterBlock.buffer, counterBlock.byteOffset, counterBlock.byteLength)
  const c = (dv.getUint32(12, false) + 1) >>> 0
  dv.setUint32(12, c, false)
}

export function aes256GcmEncryptPureTS(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  const roundKeys = expandKey256(key)
  const h = aesEncryptBlock(roundKeys, new Uint8Array(16))

  const j0 = new Uint8Array(16)
  j0.set(iv, 0)
  j0[15] = 1

  const counter = new Uint8Array(j0)
  const ciphertext = new Uint8Array(plaintext.length)

  for (let offset = 0; offset < plaintext.length; offset += 16) {
    inc32(counter)
    const keystream = aesEncryptBlock(roundKeys, counter)
    const chunkLen = Math.min(16, plaintext.length - offset)
    for (let i = 0; i < chunkLen; i++) {
      ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i]
    }
  }

  let s: Uint8Array = new Uint8Array(16)
  for (let offset = 0; offset < aad.length; offset += 16) {
    const chunkLen = Math.min(16, aad.length - offset)
    s = ghashUpdateBlock(s, h, aad.subarray(offset, offset + chunkLen), chunkLen)
  }
  for (let offset = 0; offset < ciphertext.length; offset += 16) {
    const chunkLen = Math.min(16, ciphertext.length - offset)
    s = ghashUpdateBlock(s, h, ciphertext.subarray(offset, offset + chunkLen), chunkLen)
  }

  const lenBlock = new Uint8Array(16)
  const lenDv = new DataView(lenBlock.buffer)
  lenDv.setUint32(4, (aad.length * 8) >>> 0, false)
  lenDv.setUint32(12, (ciphertext.length * 8) >>> 0, false)
  s = ghashUpdateBlock(s, h, lenBlock, 16)

  const tagMask = aesEncryptBlock(roundKeys, j0)
  const out = new Uint8Array(ciphertext.length + 16)
  out.set(ciphertext, 0)
  for (let i = 0; i < 16; i++) {
    out[ciphertext.length + i] = s[i] ^ tagMask[i]
  }
  return out
}
