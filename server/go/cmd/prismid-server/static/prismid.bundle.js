// PrismID Web SDK (prismid-js v1.1.0) Standalone ES Module Bundle

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
export function csprngBytes(length) {
    if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
        const buf = new Uint8Array(length);
        globalThis.crypto.getRandomValues(buf);
        return buf;
    }
    return null;
}
export function randomBytes(length) {
    const buf = csprngBytes(length);
    if (!buf) {
        throw new Error('Cryptographically secure PRNG (crypto.getRandomValues) is unavailable');
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

// --- crypto/deviceKey.js ---
/**
 * PrismID Non-Extractable WebCrypto ECDSA P-256 Device Trust Root (`d_key_*`)
 *
 * Generates a hardware/browser-backed `ECDSA P-256` keypair with `extractable: false` on the
 * private key and persists the `CryptoKey` object in `IndexedDB` (`_prismid_key_v1`).
 *
 * Security Properties:
 * 1. Because `privateKey.extractable === false`, injected scripts or attackers in DevTools
 *    cannot export the private key bytes via `crypto.subtle.exportKey`.
 * 2. Every `/api/v1/risk/identify` payload is signed over the canonical challenge transcript:
 *    `prismid-v2-sig|<nonce>|<beacon_id>|<static_webgl_fp_hash>|<audio_compressor_hash>`
 * 3. The Go server verifies the P-256 signature, derives `d_key_<hmac>`, and enforces
 *    Trust-On-First-Use (TOFU) binding between `d_bcn_*` and `d_key_*`.
 */
const KEY_DB_NAME = '_prismid_key_v1';
const KEY_STORE_NAME = 'keystore';
const KEY_RECORD_ID = 'hw_ecdsa_p256';
const IDB_KEY_TIMEOUT_MS = 150;
let memoryCachedKey = null;
/**
 * Clears the in-memory `CryptoKey` cache so subsequent operations re-read `IndexedDB`
 * (e.g. after in-page site-data clearing or explicit key recovery/rotation).
 */
export function resetDeviceKeyCache() {
    memoryCachedKey = null;
}
function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        out += bytes[i].toString(16).padStart(2, '0');
    }
    return out;
}
function getSubtleCrypto() {
    if (typeof globalThis !== 'undefined' &&
        typeof globalThis.crypto !== 'undefined' &&
        globalThis.crypto &&
        typeof globalThis.crypto.subtle !== 'undefined') {
        return globalThis.crypto.subtle;
    }
    return null;
}
function isStoredKey(value) {
    const rec = value;
    return !!rec && typeof rec === 'object' && !!rec.privateKey &&
        rec.privateKey.type === 'private' && rec.privateKey.extractable === false &&
        rec.privateKey.algorithm?.name === 'ECDSA' &&
        rec.privateKey.algorithm.namedCurve === 'P-256' &&
        Array.isArray(rec.privateKey.usages) && rec.privateKey.usages.includes('sign') && typeof rec.pubKeyHex === 'string' &&
        /^04[0-9a-f]{128}$/.test(rec.pubKeyHex);
}
// Fast read-only lookup BEFORE generating an ECDSA P-256 keypair so warm page loads
// never waste CPU/WebCrypto keygen work when a persisted key already exists (S2-23).
function readExistingPersistedKey() {
    if (typeof indexedDB === 'undefined' || !indexedDB) {
        return Promise.resolve({ status: 'error' });
    }
    return new Promise((resolve) => {
        let settled = false;
        let db;
        const finish = (outcome) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            try {
                db?.close();
            }
            catch { }
            resolve(outcome);
        };
        const timer = setTimeout(() => finish({ status: 'error' }), IDB_KEY_TIMEOUT_MS);
        try {
            const req = indexedDB.open(KEY_DB_NAME, 1);
            req.onblocked = req.onerror = () => finish({ status: 'error' });
            req.onupgradeneeded = () => {
                if (settled) {
                    req.transaction?.abort();
                    return;
                }
                if (!req.result.objectStoreNames.contains(KEY_STORE_NAME)) {
                    req.result.createObjectStore(KEY_STORE_NAME);
                }
            };
            req.onsuccess = () => {
                db = req.result;
                if (settled) {
                    db.close();
                    return;
                }
                db.onversionchange = () => db?.close();
                try {
                    if (db.objectStoreNames && typeof db.objectStoreNames.contains === 'function' && !db.objectStoreNames.contains(KEY_STORE_NAME)) {
                        finish({ status: 'missing' });
                        return;
                    }
                    const tx = db.transaction(KEY_STORE_NAME, 'readonly');
                    tx.onerror = tx.onabort = () => finish({ status: 'error' });
                    const store = tx.objectStore(KEY_STORE_NAME);
                    const read = store.get(KEY_RECORD_ID);
                    read.onerror = () => finish({ status: 'error' });
                    read.onsuccess = () => {
                        if (settled)
                            return;
                        if (read.result === undefined) {
                            finish({ status: 'missing' });
                        }
                        else if (isStoredKey(read.result)) {
                            finish({ status: 'found', record: read.result });
                        }
                        else {
                            finish({ status: 'corrupted' });
                        }
                    };
                }
                catch {
                    finish({ status: 'error' });
                }
            };
        }
        catch {
            finish({ status: 'error' });
        }
    });
}
// The read and conditional insert/repair share one readwrite transaction. IndexedDB serializes
// these transactions across tabs, so concurrent first visits all use the committed winner,
// and corrupted records are atomically repaired instead of permanently disabling `d_key_*` (S3-32).
function loadOrCreatePersistedKey(candidate, forceOverwrite = false) {
    if (typeof indexedDB === 'undefined' || !indexedDB)
        return Promise.resolve(null);
    return new Promise((resolve) => {
        let settled = false;
        let db;
        let tx;
        const finish = (value) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            if (!value) {
                try {
                    tx?.abort();
                }
                catch { }
            }
            try {
                db?.close();
            }
            catch { }
            resolve(value);
        };
        const timer = setTimeout(() => finish(null), IDB_KEY_TIMEOUT_MS);
        try {
            const req = indexedDB.open(KEY_DB_NAME, 1);
            req.onblocked = req.onerror = () => finish(null);
            req.onupgradeneeded = () => {
                if (settled) {
                    req.transaction?.abort();
                    return;
                }
                if (!req.result.objectStoreNames.contains(KEY_STORE_NAME)) {
                    req.result.createObjectStore(KEY_STORE_NAME);
                }
            };
            req.onsuccess = () => {
                db = req.result;
                if (settled) {
                    db.close();
                    return;
                }
                db.onversionchange = () => db?.close();
                try {
                    tx = db.transaction(KEY_STORE_NAME, 'readwrite');
                    const store = tx.objectStore(KEY_STORE_NAME);
                    let winner = null;
                    tx.oncomplete = () => finish(winner);
                    tx.onerror = tx.onabort = () => finish(null);
                    if (forceOverwrite) {
                        winner = candidate;
                        if (typeof store.put === 'function') {
                            store.put(candidate, KEY_RECORD_ID);
                        }
                        else {
                            store.add(candidate, KEY_RECORD_ID);
                        }
                        return;
                    }
                    const read = store.get(KEY_RECORD_ID);
                    read.onerror = () => finish(null);
                    read.onsuccess = () => {
                        if (settled)
                            return;
                        try {
                            if (read.result === undefined) {
                                winner = candidate;
                                store.add(candidate, KEY_RECORD_ID);
                            }
                            else if (isStoredKey(read.result)) {
                                winner = read.result;
                            }
                            else {
                                // Repair corrupted / schema-invalid IndexedDB record in place (S3-32).
                                winner = candidate;
                                if (typeof store.put === 'function') {
                                    store.put(candidate, KEY_RECORD_ID);
                                }
                                else {
                                    if (typeof store.delete === 'function')
                                        store.delete(KEY_RECORD_ID);
                                    store.add(candidate, KEY_RECORD_ID);
                                }
                            }
                        }
                        catch {
                            finish(null);
                        }
                    };
                }
                catch {
                    finish(null);
                }
            };
        }
        catch {
            finish(null);
        }
    });
}
async function generateCandidateKeyRecord(subtle) {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const rawPub = await subtle.exportKey('raw', pair.publicKey);
    return {
        privateKey: pair.privateKey,
        pubKeyHex: bytesToHex(new Uint8Array(rawPub)),
    };
}
let keyInitialization = null;
async function getOrCreateDeviceKeyRecord(options) {
    if (!options?.bypassMemoryCache && memoryCachedKey)
        return memoryCachedKey;
    if (keyInitialization)
        return keyInitialization;
    const subtle = getSubtleCrypto();
    if (!subtle || typeof indexedDB === 'undefined' || !indexedDB)
        return null;
    keyInitialization = (async () => {
        try {
            const existing = await readExistingPersistedKey();
            if (existing.status === 'found') {
                memoryCachedKey = existing.record;
                return existing.record;
            }
            if (existing.status === 'error') {
                // IndexedDB blocked/timed out/errored: do not open a second transaction or cache a temporary key.
                if (options?.bypassMemoryCache) {
                    memoryCachedKey = null;
                }
                return null;
            }
            // status === 'missing' || status === 'corrupted': generate fresh P-256 keypair & persist atomically.
            const candidate = await generateCandidateKeyRecord(subtle);
            const persisted = await loadOrCreatePersistedKey(candidate, false);
            // Only a confirmed transaction commit may establish a server-side TOFU binding.
            memoryCachedKey = persisted;
            return persisted;
        }
        catch {
            return null;
        }
    })();
    try {
        return await keyInitialization;
    }
    finally {
        keyInitialization = null;
    }
}
/**
 * Preloads or initializes the persisted ECDSA P-256 device key in parallel with other probes.
 */
export async function preloadDeviceKey() {
    const rec = await getOrCreateDeviceKeyRecord();
    return rec !== null;
}
export function buildDeviceKeyTranscript(params) {
    return [
        'prismid-v2-sig',
        params.nonce.trim(),
        params.beaconId.trim().toLowerCase(),
        params.staticWebGLFpHash.trim().toLowerCase(),
        params.audioCompressorHash.trim().toLowerCase(),
    ].join('|');
}
export function buildRebindKeyTranscript(params) {
    return [
        'prismid-v2-rebind',
        params.nonce.trim(),
        params.subjectId.trim(),
        params.beaconId.trim().toLowerCase(),
    ].join('|');
}
export function buildPreviousKeyRotationTranscript(params) {
    return [
        'prismid-v2-rebind-prev',
        params.nonce.trim(),
        params.subjectId.trim(),
        params.beaconId.trim().toLowerCase(),
    ].join('|');
}
async function signTranscript(subtle, rec, transcript) {
    try {
        const msgBytes = new TextEncoder().encode(transcript);
        const sigBuf = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, rec.privateKey, msgBytes);
        const sigHex = bytesToHex(new Uint8Array(sigBuf));
        if (sigHex.length !== 128) {
            return undefined;
        }
        return {
            alg: 'ecdsa-p256',
            pub_key: rec.pubKeyHex,
            signature: sigHex,
        };
    }
    catch {
        return undefined;
    }
}
export async function signRebindWithDeviceKey(params) {
    const subtle = getSubtleCrypto();
    if (!subtle) {
        return undefined;
    }
    // Always re-verify IndexedDB on rebind so in-session site-data clearing generates a fresh key
    // without requiring a page reload (S2-24).
    const rec = await getOrCreateDeviceKeyRecord({ bypassMemoryCache: true });
    if (!rec) {
        return undefined;
    }
    return signTranscript(subtle, rec, buildRebindKeyTranscript(params));
}
/**
 * Rotates the persisted ECDSA P-256 keypair in-place and signs both the new key PoP (`device_key`)
 * and, when a previous key was still accessible in IndexedDB or memory, the continuity proof
 * (`previous_device_key`) over `prismid-v2-rebind-prev|<nonce>|<subject>|<beacon>|<new_pub_key>` (S2-12).
 */
export async function rotateDeviceKeyAndSignRebind(params) {
    const subtle = getSubtleCrypto();
    if (!subtle || typeof indexedDB === 'undefined' || !indexedDB) {
        return undefined;
    }
    const existing = await readExistingPersistedKey();
    const prevRec = existing.status === 'found' ? existing.record : memoryCachedKey;
    try {
        const candidate = await generateCandidateKeyRecord(subtle);
        const committed = await loadOrCreatePersistedKey(candidate, true);
        if (!committed) {
            return undefined;
        }
        memoryCachedKey = committed;
        const newProof = await signTranscript(subtle, committed, buildRebindKeyTranscript(params));
        if (!newProof) {
            return undefined;
        }
        let prevProof;
        if (prevRec && prevRec.pubKeyHex !== committed.pubKeyHex) {
            prevProof = await signTranscript(subtle, prevRec, buildPreviousKeyRotationTranscript({
                nonce: params.nonce,
                subjectId: params.subjectId,
                beaconId: params.beaconId,
            }));
        }
        return {
            device_key: newProof,
            ...(prevProof ? { previous_device_key: prevProof } : {}),
        };
    }
    catch {
        return undefined;
    }
}
export async function signChallengeWithDeviceKey(params) {
    const subtle = getSubtleCrypto();
    if (!subtle) {
        return undefined;
    }
    const rec = await getOrCreateDeviceKeyRecord();
    if (!rec) {
        return undefined;
    }
    return signTranscript(subtle, rec, buildDeviceKeyTranscript(params));
}

// --- probes/storageBeacon.js ---
const STORAGE_KEY = '_prismid_bcn_v1';
const IDB_NAME = 'prismid_vault_v1';
const IDB_STORE = 'beacons';
const CACHE_NAME = 'prismid-beacon-cache-v1';
const CACHE_URL = 'https://prismid.invalid/__beacon_v1';
export const SILO_MASK = {
    localStorage: 1 << 0,
    sessionStorage: 1 << 1,
    cookie: 1 << 2,
    indexedDB: 1 << 3,
    cacheStorage: 1 << 4,
};
function isValidBeaconId(val) {
    return typeof val === 'string' && /^[0-9a-f]{32}$/.test(val.trim());
}
function generateBeaconId() {
    const bytes = csprngBytes(16);
    if (!bytes) {
        // Never fall back to predictable Math.random() when CSPRNG is absent (S3-34).
        return '';
    }
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
}
function readLocalStorage() {
    try {
        if (typeof localStorage === 'undefined')
            return { available: false, value: null };
        const v = localStorage.getItem(STORAGE_KEY);
        return { available: true, value: isValidBeaconId(v) ? v.trim() : null };
    }
    catch {
        return { available: false, value: null };
    }
}
function writeLocalStorage(id) {
    if (!id)
        return;
    try {
        if (typeof localStorage !== 'undefined') {
            localStorage.setItem(STORAGE_KEY, id);
        }
    }
    catch {
        // ignore
    }
}
function readSessionStorage() {
    try {
        if (typeof sessionStorage === 'undefined')
            return { available: false, value: null };
        const v = sessionStorage.getItem(STORAGE_KEY);
        return { available: true, value: isValidBeaconId(v) ? v.trim() : null };
    }
    catch {
        return { available: false, value: null };
    }
}
function writeSessionStorage(id) {
    if (!id)
        return;
    try {
        if (typeof sessionStorage !== 'undefined') {
            sessionStorage.setItem(STORAGE_KEY, id);
        }
    }
    catch {
        // ignore
    }
}
function readCookie() {
    try {
        if (typeof document === 'undefined' || typeof document.cookie !== 'string') {
            return { available: false, value: null };
        }
        const parts = document.cookie.split(';');
        for (const part of parts) {
            const eqIdx = part.indexOf('=');
            if (eqIdx < 0)
                continue;
            const k = part.slice(0, eqIdx).trim();
            const v = part.slice(eqIdx + 1).trim();
            if (k === STORAGE_KEY && isValidBeaconId(v)) {
                return { available: true, value: v };
            }
        }
        return { available: true, value: null };
    }
    catch {
        return { available: false, value: null };
    }
}
function writeCookie(id) {
    if (!id)
        return;
    try {
        if (typeof document !== 'undefined') {
            const isHttps = typeof globalThis.location !== 'undefined' && globalThis.location?.protocol === 'https:';
            const secureAttr = isHttps ? '; Secure' : '';
            document.cookie = `${STORAGE_KEY}=${id}; path=/; max-age=34560000; SameSite=Lax${secureAttr}`;
        }
    }
    catch {
        // ignore
    }
}
function readIndexedDB(timeoutMs = 150) {
    if (typeof indexedDB === 'undefined' || !indexedDB) {
        return Promise.resolve({ available: false, value: null });
    }
    return new Promise((resolve) => {
        let settled = false;
        let db;
        const finish = (res) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            try {
                db?.close();
            }
            catch { }
            resolve(res);
        };
        const timer = setTimeout(() => finish({ available: false, value: null }), timeoutMs);
        try {
            const req = indexedDB.open(IDB_NAME, 1);
            req.onblocked = () => finish({ available: false, value: null });
            req.onupgradeneeded = () => {
                if (settled) {
                    try {
                        req.transaction?.abort();
                    }
                    catch { }
                    return;
                }
                try {
                    const upgDb = req.result;
                    if (!upgDb.objectStoreNames.contains(IDB_STORE)) {
                        upgDb.createObjectStore(IDB_STORE);
                    }
                }
                catch {
                    // ignore
                }
            };
            req.onerror = () => finish({ available: false, value: null });
            req.onsuccess = () => {
                db = req.result;
                if (settled) {
                    try {
                        db.close();
                    }
                    catch { }
                    return;
                }
                try {
                    const tx = db.transaction(IDB_STORE, 'readonly');
                    const store = tx.objectStore(IDB_STORE);
                    const getReq = store.get(STORAGE_KEY);
                    getReq.onsuccess = () => {
                        const val = getReq.result;
                        finish({ available: true, value: isValidBeaconId(val) ? val.trim() : null });
                    };
                    getReq.onerror = () => {
                        finish({ available: true, value: null });
                    };
                }
                catch {
                    finish({ available: false, value: null });
                }
            };
        }
        catch {
            finish({ available: false, value: null });
        }
    });
}
function writeIndexedDB(id, timeoutMs = 150, isAborted) {
    if (!id || typeof indexedDB === 'undefined' || !indexedDB || isAborted?.()) {
        return Promise.resolve();
    }
    return new Promise((resolve) => {
        let settled = false;
        let db;
        const finish = () => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            try {
                db?.close();
            }
            catch { }
            resolve();
        };
        const timer = setTimeout(finish, timeoutMs);
        try {
            const req = indexedDB.open(IDB_NAME, 1);
            req.onblocked = () => finish();
            req.onupgradeneeded = () => {
                if (settled || isAborted?.()) {
                    try {
                        req.transaction?.abort();
                    }
                    catch { }
                    return;
                }
                try {
                    const upgDb = req.result;
                    if (!upgDb.objectStoreNames.contains(IDB_STORE)) {
                        upgDb.createObjectStore(IDB_STORE);
                    }
                }
                catch {
                    // ignore
                }
            };
            req.onerror = () => finish();
            req.onsuccess = () => {
                db = req.result;
                if (settled || isAborted?.()) {
                    finish();
                    return;
                }
                try {
                    const tx = db.transaction(IDB_STORE, 'readwrite');
                    tx.objectStore(IDB_STORE).put(id, STORAGE_KEY);
                    tx.oncomplete = () => finish();
                    tx.onerror = () => finish();
                    tx.onabort = () => finish();
                }
                catch {
                    finish();
                }
            };
        }
        catch {
            finish();
        }
    });
}
async function readCacheStorage(timeoutMs = 150) {
    if (typeof caches === 'undefined' || typeof Response === 'undefined') {
        return { available: false, value: null };
    }
    return new Promise((resolve) => {
        let settled = false;
        const finish = (res) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve(res);
        };
        const timer = setTimeout(() => finish({ available: false, value: null }), timeoutMs);
        caches
            .open(CACHE_NAME)
            .then((cache) => cache.match(CACHE_URL))
            .then((resp) => (resp ? resp.text() : null))
            .then((text) => {
            finish({ available: true, value: isValidBeaconId(text) ? text.trim() : null });
        })
            .catch(() => {
            finish({ available: false, value: null });
        });
    });
}
function writeCacheStorage(id, timeoutMs = 150, isAborted) {
    if (!id || typeof caches === 'undefined' || typeof Response === 'undefined' || isAborted?.()) {
        return Promise.resolve();
    }
    return new Promise((resolve) => {
        let settled = false;
        const finish = () => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve();
        };
        const timer = setTimeout(finish, timeoutMs);
        caches
            .open(CACHE_NAME)
            .then((cache) => {
            if (settled || isAborted?.())
                return;
            return cache.put(CACHE_URL, new Response(id, {
                headers: {
                    'Content-Type': 'text/plain',
                    ETag: `"${id}"`,
                    'Cache-Control': 'max-age=31536000',
                },
            }));
        })
            .then(() => finish())
            .catch(() => finish());
    });
}
function evaluateSilos(silos, fallbackId) {
    const survivingSilos = [];
    let survivingMask = 0;
    const freq = new Map();
    let missingPrimarySilo = false;
    for (const s of silos) {
        if (s.value) {
            survivingSilos.push(s.name);
            survivingMask |= SILO_MASK[s.name];
            freq.set(s.value, (freq.get(s.value) || 0) + 1);
        }
        else if (s.available &&
            (s.name === 'localStorage' || s.name === 'cookie' || s.name === 'indexedDB')) {
            missingPrimarySilo = true;
        }
    }
    let canonicalId = '';
    let storageHealed = false;
    if (freq.size > 0) {
        let bestCount = -1;
        for (const [id, count] of freq.entries()) {
            if (count > bestCount) {
                bestCount = count;
                canonicalId = id;
            }
        }
        if (missingPrimarySilo || freq.size > 1) {
            storageHealed = true;
        }
    }
    else {
        canonicalId = fallbackId;
    }
    return {
        beacon_id: canonicalId,
        storage_healed: storageHealed,
        surviving_silos: survivingSilos,
        surviving_silos_mask: survivingMask,
    };
}
export async function collectAndHealStorageBeacon(timeoutMs = 350) {
    // Read synchronous silos FIRST so even if async IndexedDB/CacheStorage hang past `timeoutMs`,
    // we preserve the existing synchronous beacon rather than clobbering it with a random ID,
    // and `aborted = true` stops late async tasks from overwriting storage afterwards (S3-35).
    const ls = readLocalStorage();
    const ss = readSessionStorage();
    const ck = readCookie();
    const fallbackId = generateBeaconId();
    const syncSnapshot = evaluateSilos([
        { name: 'localStorage', ...ls },
        { name: 'sessionStorage', ...ss },
        { name: 'cookie', ...ck },
    ], fallbackId);
    let aborted = false;
    let timer;
    const work = (async () => {
        const perSiloMs = Math.max(40, Math.floor(timeoutMs * 0.4));
        const [idb, cs] = await Promise.all([readIndexedDB(perSiloMs), readCacheStorage(perSiloMs)]);
        if (aborted) {
            return syncSnapshot;
        }
        const resolved = evaluateSilos([
            { name: 'localStorage', ...ls },
            { name: 'sessionStorage', ...ss },
            { name: 'cookie', ...ck },
            { name: 'indexedDB', ...idb },
            { name: 'cacheStorage', ...cs },
        ], fallbackId);
        if (resolved.beacon_id && !aborted) {
            writeLocalStorage(resolved.beacon_id);
            writeSessionStorage(resolved.beacon_id);
            writeCookie(resolved.beacon_id);
            await Promise.all([
                writeIndexedDB(resolved.beacon_id, perSiloMs, () => aborted),
                writeCacheStorage(resolved.beacon_id, perSiloMs, () => aborted),
            ]);
        }
        return resolved;
    })();
    const deadline = new Promise((resolve) => {
        timer = setTimeout(() => {
            aborted = true;
            if (syncSnapshot.beacon_id) {
                writeLocalStorage(syncSnapshot.beacon_id);
                writeSessionStorage(syncSnapshot.beacon_id);
                writeCookie(syncSnapshot.beacon_id);
            }
            resolve(syncSnapshot);
        }, timeoutMs);
    });
    try {
        return await Promise.race([work, deadline]);
    }
    finally {
        if (timer !== undefined)
            clearTimeout(timer);
    }
}

// --- probes/webgl.js ---
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
const DETERMINISTIC_CONTEXT_ATTRS = {
    antialias: false,
    depth: false,
    stencil: false,
    preserveDrawingBuffer: true,
};
function createWebGLContext(width, height) {
    try {
        if (typeof OffscreenCanvas !== 'undefined') {
            const oc = new OffscreenCanvas(width, height);
            const gl = oc.getContext('webgl', DETERMINISTIC_CONTEXT_ATTRS);
            if (gl && (typeof gl.isContextLost !== 'function' || !gl.isContextLost()))
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
            const gl = (canvas.getContext('webgl', DETERMINISTIC_CONTEXT_ATTRS) ||
                canvas.getContext('experimental-webgl', DETERMINISTIC_CONTEXT_ATTRS));
            if (gl && (typeof gl.isContextLost !== 'function' || !gl.isContextLost()))
                return gl;
        }
    }
    catch {
        // WebGL unavailable
    }
    return null;
}
function releaseWebGLContext(gl) {
    try {
        const ext = gl.getExtension('WEBGL_lose_context');
        if (ext && typeof ext.loseContext === 'function') {
            ext.loseContext();
        }
    }
    catch {
        // ignore
    }
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
// Single oversized clip-space triangle avoids any diagonal 2-triangle seam across [0..W, 0..H].
function drawFullScreenTriangle(gl, prog) {
    const buf = gl.createBuffer();
    if (!buf)
        return null;
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    const vertices = new Float32Array([-1, -1, 3, -1, -1, 3]);
    gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
    const posLoc = gl.getAttribLocation(prog, 'a_pos');
    gl.enableVertexAttribArray(posLoc);
    gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    return buf;
}
function hasAnyNonZeroByte(buf) {
    for (let i = 0; i < buf.length; i++) {
        if (buf[i] !== 0)
            return true;
    }
    return false;
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
    ].join('|');
}
function extractWebGLExtensionsHash(gl) {
    try {
        const exts = (gl.getSupportedExtensions() || []).slice().sort().join(',');
        return sha256Hex(exts).slice(0, 16);
    }
    catch {
        return '0000000000000000';
    }
}
export function collectWebGLProbe(renderSeed, samplePoints = DEFAULT_SAMPLE_POINTS) {
    const gl = createWebGLContext(256, 256);
    if (!gl) {
        // Non-WebGL environment fallback (hardened Firefox / enterprise policy / headless without GPU).
        // Reported honestly as `webgl_available: false` and `Unavailable / WebGL Disabled` rather than
        // impersonating `SwiftShader` so server/go can distinguish bound privacy browsers from software GPU farms (S2-18).
        return {
            gpu_vendor: 'Unavailable',
            gpu_renderer: 'WebGL Disabled',
            webgl_limits_vector: '8192|8192|8192,8192|8192|1024|1024|30|1,1|1,1024|0|23,23,23,23',
            webgl_extensions_hash: '0000000000000000',
            static_webgl_fp_hash: sha256Hex('no-webgl-disabled-static-fallback'),
            spot_pixels: samplePoints.map(([x, y]) => computeExpectedSpotPixelMath(x, y, renderSeed)),
            webgl_available: false,
            webgl_noise_injected: false,
        };
    }
    try {
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
        const extensionsHash = extractWebGLExtensionsHash(gl);
        // Step 1: Render 64x64 static fingerprint scene on a matching 64x64 non-MSAA context
        // so main-thread and Worker OffscreenCanvas(64, 64) produce bit-identical buffers across
        // Chromium, Firefox (Gecko), and Safari (WebKit) (S2-17, S3-38).
        let staticFpHash = '';
        let webglNoiseInjected = false;
        const staticGl = createWebGLContext(64, 64);
        if (staticGl) {
            try {
                staticGl.viewport(0, 0, 64, 64);
                const staticProg = compileProgram(staticGl, VERTEX_SHADER_SRC, STATIC_FINGERPRINT_FRAGMENT_SHADER_SRC);
                if (staticProg) {
                    staticGl.useProgram(staticProg);
                    const buf = drawFullScreenTriangle(staticGl, staticProg);
                    const pixels1 = new Uint8Array(64 * 64 * 4);
                    const pixels2 = new Uint8Array(64 * 64 * 4);
                    staticGl.readPixels(0, 0, 64, 64, staticGl.RGBA, staticGl.UNSIGNED_BYTE, pixels1);
                    const err1 = typeof staticGl.getError === 'function' ? staticGl.getError() : 0;
                    staticGl.readPixels(0, 0, 64, 64, staticGl.RGBA, staticGl.UNSIGNED_BYTE, pixels2);
                    const err2 = typeof staticGl.getError === 'function' ? staticGl.getError() : 0;
                    const lost = typeof staticGl.isContextLost === 'function' && staticGl.isContextLost();
                    if (!lost && err1 === 0 && err2 === 0 && hasAnyNonZeroByte(pixels1)) {
                        const hash1 = sha256Hex(pixels1);
                        const hash2 = sha256Hex(pixels2);
                        staticFpHash = hash1;
                        if (hash1 !== hash2) {
                            webglNoiseInjected = true;
                        }
                    }
                    if (buf)
                        staticGl.deleteBuffer(buf);
                    staticGl.deleteProgram(staticProg);
                }
            }
            catch {
                // ignore
            }
            finally {
                releaseWebGLContext(staticGl);
            }
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
                const buf = drawFullScreenTriangle(gl, dynProg);
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
        // Do NOT fall back to CPU math when a WebGL context exists but failed/blocked shader rendering:
        // fill with [0,0,0,0] so broken/stubbed WebGL mocks fail spot-pixel verification honestly.
        while (spotPixels.length < samplePoints.length) {
            spotPixels.push([0, 0, 0, 0]);
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
        };
    }
    finally {
        releaseWebGLContext(gl);
    }
}

// --- probes/workerLie.js ---
export async function collectWorkerLieProbe(mainThread, timeoutMs = 300) {
    const emptyUnavailable = {
        worker_unavailable: true,
        worker_webgl_available: false,
        worker_lie_detected: false,
        worker_gpu_renderer: '',
        worker_static_webgl_fp_hash: '',
        worker_cpu_cores: 0,
        worker_platform: '',
        worker_user_agent: '',
        worker_timezone: '',
    };
    if (typeof Worker === 'undefined' ||
        typeof Blob === 'undefined' ||
        typeof URL === 'undefined' ||
        typeof URL.createObjectURL !== 'function') {
        return emptyUnavailable;
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
            finish(emptyUnavailable);
        }, timeoutMs);
        try {
            const blob = new Blob([workerScript], { type: 'application/javascript' });
            blobUrl = URL.createObjectURL(blob);
            worker = new Worker(blobUrl);
            worker.onerror = () => {
                clearTimeout(timer);
                finish(emptyUnavailable);
            };
            worker.onmessage = (ev) => {
                clearTimeout(timer);
                const data = ev.data;
                if (!data || !data.ok) {
                    finish(emptyUnavailable);
                    return;
                }
                const workerCores = Number(data.cores || 0);
                const workerPlat = String(data.plat || '');
                const workerUA = String(data.ua || '');
                const workerTZ = String(data.tz || '');
                const rawWorkerWebglOk = Boolean(data.webglOk) && data.pixelsBuffer instanceof ArrayBuffer;
                const workerFpHash = rawWorkerWebglOk
                    ? sha256Hex(new Uint8Array(data.pixelsBuffer))
                    : '';
                // Only expose worker_gpu_renderer / worker_static_webgl_fp_hash when Worker WebGL actually
                // completed cleanly AND main-thread WebGL was also enabled (avoids false positives on GPU reset, S3-38).
                const mainWebglAvailable = mainThread.webglAvailable !== false;
                const workerRenderer = rawWorkerWebglOk ? String(data.renderer || '') : '';
                const isGenericMaskedRenderer = (r) => {
                    const low = r.trim().toLowerCase();
                    return (low === '' ||
                        low === 'webkit webgl' ||
                        low === 'mozilla' ||
                        low === 'webgl' ||
                        low === 'unknown' ||
                        low === 'unavailable' ||
                        low === 'webgl disabled');
                };
                let lieDetected = false;
                if (mainWebglAvailable &&
                    rawWorkerWebglOk &&
                    workerRenderer &&
                    mainThread.gpuRenderer &&
                    !isGenericMaskedRenderer(workerRenderer) &&
                    !isGenericMaskedRenderer(mainThread.gpuRenderer) &&
                    workerRenderer.toLowerCase() !== mainThread.gpuRenderer.toLowerCase()) {
                    lieDetected = true;
                }
                if (mainWebglAvailable &&
                    rawWorkerWebglOk &&
                    workerFpHash &&
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
                if (workerTZ && mainThread.timezone && workerTZ !== mainThread.timezone) {
                    lieDetected = true;
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
                });
            };
            worker.postMessage('probe');
        }
        catch {
            clearTimeout(timer);
            finish(emptyUnavailable);
        }
    });
}

// --- probes/audio.js ---
export async function collectAudioProbeWithTrap(timeoutMs = 400) {
    const OfflineCtx = typeof globalThis !== 'undefined'
        ? globalThis.OfflineAudioContext ||
            globalThis.webkitOfflineAudioContext
        : undefined;
    if (!OfflineCtx) {
        const fallbackHash = sha256Hex('prismid-audio-context-unavailable');
        return {
            audio_compressor_hash: fallbackHash,
            audio_copy_hash: fallbackHash,
            audio_silent_delta: 0,
            audio_noise_injected: false,
            audio_muted: false,
        };
    }
    return new Promise((resolve) => {
        let done = false;
        const finish = (res) => {
            if (done)
                return;
            done = true;
            resolve(res);
        };
        const timer = setTimeout(() => {
            const timeoutHash = sha256Hex('prismid-audio-context-timeout');
            finish({
                audio_compressor_hash: timeoutHash,
                audio_copy_hash: timeoutHash,
                audio_silent_delta: 0,
                audio_noise_injected: false,
                audio_muted: false,
            });
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
            const inspectBuffer = (buffer) => {
                const ch0A = buffer.getChannelData(0);
                const sliceA = new Float32Array(500);
                for (let i = 0; i < 500; i++) {
                    sliceA[i] = ch0A[4500 + i];
                }
                let noiseInjected = false;
                let copyMismatch = false;
                let copyAcc = '';
                let silentDelta = 0;
                // Trap 1: Cross-Surface `copyFromChannel` vs `getChannelData` consistency
                if (typeof buffer.copyFromChannel === 'function') {
                    try {
                        const copySlice = new Float32Array(500);
                        buffer.copyFromChannel(copySlice, 0, 4500);
                        for (let i = 0; i < 500; i++) {
                            if (copySlice[i] !== sliceA[i]) {
                                noiseInjected = true;
                                copyMismatch = true;
                            }
                            copyAcc += copySlice[i].toFixed(7) + ',';
                        }
                    }
                    catch {
                        // ignore
                    }
                }
                // Trap 2: Second `getChannelData(0)` call determinism check
                const ch0B = buffer.getChannelData(0);
                for (let i = 0; i < 500; i++) {
                    if (ch0B[4500 + i] !== sliceA[i]) {
                        noiseInjected = true;
                        break;
                    }
                }
                // Trap 3: Pristine Silent AudioBuffer Invariant
                try {
                    const silentBuf = ctx.createBuffer(1, 16, 44100);
                    const silentData = silentBuf.getChannelData(0);
                    for (let i = 0; i < silentData.length; i++) {
                        if (silentData[i] !== 0) {
                            noiseInjected = true;
                            silentDelta += Math.abs(silentData[i]);
                            break;
                        }
                    }
                }
                catch {
                    // ignore
                }
                // Trap 4: Realistic magnitude & NaN/Infinity check.
                // Note: An all-zero buffer (`nonZeroCount === 0`) occurs legitimately on muted enterprise
                // policies, Lockdown Mode, or privacy-hardened browsers; record `audio_muted: true`
                // instead of falsely accusing the user of audio noise injection (S3-37).
                let nonZeroCount = 0;
                let acc = '';
                for (let i = 0; i < 500; i++) {
                    const v = sliceA[i];
                    if (!Number.isFinite(v) || Math.abs(v) > 2.0) {
                        noiseInjected = true;
                    }
                    if (v !== 0)
                        nonZeroCount++;
                    acc += v.toFixed(7) + ',';
                }
                const audioMuted = nonZeroCount === 0 && !noiseInjected;
                const primaryHash = audioMuted
                    ? sha256Hex('prismid-audio-output-muted')
                    : sha256Hex(acc);
                const copyHash = audioMuted && !copyMismatch
                    ? primaryHash
                    : copyAcc
                        ? sha256Hex(copyAcc)
                        : primaryHash;
                return {
                    audio_compressor_hash: primaryHash,
                    audio_copy_hash: copyHash,
                    audio_silent_delta: silentDelta,
                    audio_noise_injected: noiseInjected,
                    audio_muted: audioMuted,
                };
            };
            const renderPromise = ctx.startRendering();
            if (renderPromise && typeof renderPromise.then === 'function') {
                renderPromise
                    .then((buffer) => {
                    clearTimeout(timer);
                    finish(inspectBuffer(buffer));
                })
                    .catch(() => {
                    clearTimeout(timer);
                    const rejHash = sha256Hex('prismid-audio-render-rejected');
                    finish({
                        audio_compressor_hash: rejHash,
                        audio_copy_hash: rejHash,
                        audio_silent_delta: 0,
                        audio_noise_injected: false,
                        audio_muted: false,
                    });
                });
            }
            else {
                ctx.oncomplete = (ev) => {
                    clearTimeout(timer);
                    finish(inspectBuffer(ev.renderedBuffer));
                };
            }
        }
        catch {
            clearTimeout(timer);
            const excHash = sha256Hex('prismid-audio-exception');
            finish({
                audio_compressor_hash: excHash,
                audio_copy_hash: excHash,
                audio_silent_delta: 0,
                audio_noise_injected: false,
                audio_muted: false,
            });
        }
    });
}
export async function collectAudioProbe(timeoutMs = 400) {
    const res = await collectAudioProbeWithTrap(timeoutMs);
    return res.audio_compressor_hash;
}

// --- probes/fontsCanvas.js ---
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
let cachedFontsBitmapHash = null;
export function resetFontsProbeCache() {
    cachedFontsBitmapHash = null;
}
function renderCompositeScene(canvas) {
    canvas.width = 240;
    canvas.height = 60;
    const ctx = canvas.getContext('2d');
    if (!ctx)
        return '';
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
    return canvas.toDataURL();
}
function inspectSolidPatch(data) {
    if (data.length < 4) {
        return { tampered: false, sampleRgba: [17, 136, 221, 255], nonUniformDelta: 0 };
    }
    const r0 = data[0];
    const g0 = data[1];
    const b0 = data[2];
    const a0 = data[3];
    // Allow ±2 uniform ICC / wide-gamut color management rounding (matching server/go/engine.go S3-36).
    if (Math.abs(r0 - 17) > 2 ||
        Math.abs(g0 - 136) > 2 ||
        Math.abs(b0 - 221) > 2 ||
        Math.abs(a0 - 255) > 2) {
        return { tampered: true, sampleRgba: [r0, g0, b0, a0], nonUniformDelta: 0 };
    }
    // Every pixel in a pure solid fillRect MUST be identical across all 256 pixels;
    // catches per-pixel farbling or single-pixel +1 noise hooks.
    for (let i = 4; i < data.length; i += 4) {
        const diff = Math.abs(data[i] - r0) +
            Math.abs(data[i + 1] - g0) +
            Math.abs(data[i + 2] - b0) +
            Math.abs(data[i + 3] - a0);
        if (diff !== 0) {
            return {
                tampered: true,
                sampleRgba: [data[i], data[i + 1], data[i + 2], data[i + 3]],
                nonUniformDelta: diff,
            };
        }
    }
    return { tampered: false, sampleRgba: [r0, g0, b0, a0], nonUniformDelta: 0 };
}
function detectCanvasNoiseWithRawMeasurements() {
    let noiseInjected = false;
    let controlRgba = [0, 0, 0, 0, 17, 136, 221, 255];
    let readbackDelta = 0;
    try {
        // Trap 1: 16x16 Pure Solid-Color Uniformity + ±2 ICC Tolerance Trap
        const trapCanvas = document.createElement('canvas');
        trapCanvas.width = 16;
        trapCanvas.height = 16;
        const trapCtx = trapCanvas.getContext('2d');
        if (!trapCtx) {
            return { noiseInjected, controlRgba, readbackDelta };
        }
        trapCtx.globalCompositeOperation = 'copy';
        trapCtx.fillStyle = 'rgb(17, 136, 221)';
        trapCtx.fillRect(0, 0, 16, 16);
        const imgData = trapCtx.getImageData(0, 0, 16, 16).data;
        const patch1 = inspectSolidPatch(imgData);
        if (patch1.tampered) {
            noiseInjected = true;
            controlRgba = [0, 0, 0, 0, ...patch1.sampleRgba];
            readbackDelta += patch1.nonUniformDelta;
        }
        // Trap 2: In-Scene Complex Text+Arc Deterministic Seed Trap
        const c1 = document.createElement('canvas');
        const c2 = document.createElement('canvas');
        const url1 = renderCompositeScene(c1);
        const url2 = renderCompositeScene(c2);
        if (url1 !== url2) {
            noiseInjected = true;
            readbackDelta += 1;
        }
        const ctx1 = c1.getContext('2d');
        if (ctx1) {
            ctx1.globalCompositeOperation = 'source-over';
            ctx1.clearRect(224, 0, 16, 32);
            ctx1.fillStyle = 'rgb(17, 136, 221)';
            ctx1.fillRect(224, 16, 16, 16);
            const blankData = ctx1.getImageData(224, 0, 16, 16).data;
            const solidInScene = ctx1.getImageData(224, 16, 16, 16).data;
            const patch2 = inspectSolidPatch(solidInScene);
            controlRgba = [
                blankData[0] ?? 0,
                blankData[1] ?? 0,
                blankData[2] ?? 0,
                blankData[3] ?? 0,
                ...patch2.sampleRgba,
            ];
            for (let i = 0; i < blankData.length; i++) {
                if (blankData[i] !== 0) {
                    noiseInjected = true;
                    controlRgba[i % 4] = blankData[i];
                    break;
                }
            }
            if (patch2.tampered) {
                noiseInjected = true;
                readbackDelta += patch2.nonUniformDelta;
            }
            // Trap 3: Stateful PRNG Seed Advance Trap
            const readA = ctx1.getImageData(0, 0, 220, 60).data;
            const readB = ctx1.getImageData(0, 0, 220, 60).data;
            for (let i = 0; i < readA.length; i += 16) {
                const diff = Math.abs(readA[i] - readB[i]) +
                    Math.abs(readA[i + 1] - readB[i + 1]) +
                    Math.abs(readA[i + 2] - readB[i + 2]);
                if (diff !== 0) {
                    noiseInjected = true;
                    readbackDelta += diff;
                    break;
                }
            }
        }
    }
    catch {
        // ignore
    }
    return { noiseInjected, controlRgba, readbackDelta };
}
export function collectFontsAndCanvasProbe() {
    if (typeof document === 'undefined' || typeof document.createElement !== 'function') {
        return {
            canvas_2d_hash: sha256Hex('headless-canvas2d-fallback'),
            fonts_bitmap_hash: sha256Hex('headless-fonts-fallback'),
            canvas_noise_injected: false,
            canvas_control_rgba: [0, 0, 0, 0, 17, 136, 221, 255],
            canvas_readback_delta: 0,
        };
    }
    let canvas2dHash = '';
    let fontsBitmapHash = cachedFontsBitmapHash || '';
    let canvasNoiseInjected = false;
    let canvasControlRgba = [0, 0, 0, 0, 17, 136, 221, 255];
    let canvasReadbackDelta = 0;
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 240;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');
        if (ctx) {
            // 1. Sub-pixel TextMetrics bounding box probe across 45 fonts (memoized per session, S3-41)
            if (!fontsBitmapHash) {
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
                cachedFontsBitmapHash = fontsBitmapHash;
            }
            // 2. Composite Canvas 2D rendering
            const dataUrl = renderCompositeScene(canvas);
            if (dataUrl) {
                canvas2dHash = sha256Hex(dataUrl);
            }
        }
        // 3. Anti-detect Canvas Noise Injection Trap + Raw Measurements
        const rawCheck = detectCanvasNoiseWithRawMeasurements();
        canvasNoiseInjected = rawCheck.noiseInjected;
        canvasControlRgba = rawCheck.controlRgba;
        canvasReadbackDelta = rawCheck.readbackDelta;
    }
    catch {
        // Fallback if canvas is blocked
    }
    return {
        canvas_2d_hash: canvas2dHash || sha256Hex('canvas2d-fallback'),
        fonts_bitmap_hash: fontsBitmapHash || sha256Hex('fonts-fallback'),
        canvas_noise_injected: canvasNoiseInjected,
        canvas_control_rgba: canvasControlRgba,
        canvas_readback_delta: canvasReadbackDelta,
    };
}

// --- probes/lieDetector.js ---
function sampleMathConstants() {
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
    ];
}
export function collectLieDetectorProbe() {
    // 1. FDLIBM Math floating-point boundary fingerprint + active tamper check (S3-29)
    const mValues = sampleMathConstants();
    const mValuesRepeat = sampleMathConstants();
    const mathConstantsHash = sha256Hex(mValues.map((n) => String(n)).join('|')).slice(0, 32);
    let mathTampered = Math.cos(0) !== 1 ||
        Math.sin(0) !== 0 ||
        Math.atan2(0, 1) !== 0 ||
        Math.expm1(0) !== 0 ||
        Math.log1p(0) !== 0 ||
        mValues.some((v) => !Number.isFinite(v));
    if (!mathTampered) {
        for (let i = 0; i < mValues.length; i++) {
            if (mValues[i] !== mValuesRepeat[i]) {
                mathTampered = true;
                break;
            }
        }
    }
    // Determine JS engine family from stack-frame grammar & engine-exclusive intrinsics.
    // Note: Safari 18.2+ (JSC) and Firefox 135+ (SpiderMonkey) also expose `Error.captureStackTrace`,
    // so we NEVER rely on `'captureStackTrace' in Error` alone (S2-17)!
    let mathEngineSignature = 'unknown';
    try {
        const errStack = new Error().stack || '';
        const hasV8AtFrames = /^\s*(?:Error|TypeError)\b[\s\S]*\n\s+at\s+/m.test(errStack);
        const g = globalThis;
        if (hasV8AtFrames) {
            mathEngineSignature = 'v8';
        }
        else if (typeof g.InternalError === 'function' ||
            typeof g.mozInnerScreenX !== 'undefined') {
            mathEngineSignature = 'spidermonkey';
        }
        else if (errStack.includes('@')) {
            mathEngineSignature = 'jsc';
        }
        else if ('captureStackTrace' in Error) {
            mathEngineSignature = 'v8';
        }
    }
    catch {
        mathEngineSignature = 'unknown';
    }
    // 2. Prototype chain & native function integrity inspection
    const prototypeLies = [];
    const fnToString = Function.prototype.toString;
    const checkNativeFunction = (fn, label, expectedName) => {
        if (typeof fn !== 'function')
            return false;
        const beforeLen = prototypeLies.length;
        try {
            const str = fnToString.call(fn);
            if (!/\{\s*\[native code\]\s*\}/.test(str)) {
                prototypeLies.push(`${label}:non_native_toString`);
            }
            if (Object.prototype.hasOwnProperty.call(fn, 'toString')) {
                prototypeLies.push(`${label}:own_toString_override`);
            }
            // Native WebIDL methods, getters & Math functions do not have a `.prototype` property
            if ('prototype' in fn) {
                prototypeLies.push(`${label}:has_prototype_property`);
            }
            if (expectedName &&
                fn.name !== expectedName &&
                fn.name !== expectedName.replace(/^get /, '')) {
                prototypeLies.push(`${label}:unexpected_name_${fn.name || 'empty'}`);
            }
            if (fn.toString !== fnToString || fn.toString !== fn.toString) {
                prototypeLies.push(`${label}:toString_proxy_getter`);
            }
            // Guard setPrototypeOf probes with `Object.isExtensible(fn)` so SES / Lockdown
            // frozen-intrinsics environments never suffer false positives (S2-17).
            if (Object.isExtensible(fn)) {
                const origProto = Object.getPrototypeOf(fn);
                try {
                    if (Reflect.setPrototypeOf(fn, origProto) !== true) {
                        prototypeLies.push(`${label}:non_cyclic_setPrototypeOf_rejected`);
                    }
                    Object.setPrototypeOf(fn, origProto);
                }
                catch {
                    prototypeLies.push(`${label}:fake_cyclic_proto_trap`);
                }
                try {
                    Object.setPrototypeOf(fn, Object.create(fn));
                    prototypeLies.push(`${label}:es6_proxy_detected`);
                }
                catch (err) {
                    const stack = err?.stack || '';
                    if (stack.includes('Proxy.')) {
                        prototypeLies.push(`${label}:proxy_setPrototypeOf_trap`);
                    }
                }
                finally {
                    try {
                        Object.setPrototypeOf(fn, origProto);
                    }
                    catch {
                        // ignore
                    }
                }
            }
        }
        catch {
            prototypeLies.push(`${label}:proxy_toString_trap`);
        }
        return prototypeLies.length > beforeLen;
    };
    try {
        checkNativeFunction(Function.prototype.toString, 'Function.toString', 'toString');
        // Verify Math transcendental functions have not been monkey-patched or proxied (S3-29)
        if (checkNativeFunction(Math.acos, 'Math.acos', 'acos') ||
            checkNativeFunction(Math.sin, 'Math.sin', 'sin') ||
            checkNativeFunction(Math.cos, 'Math.cos', 'cos') ||
            checkNativeFunction(Math.tan, 'Math.tan', 'tan') ||
            checkNativeFunction(Math.expm1, 'Math.expm1', 'expm1')) {
            mathTampered = true;
        }
        if (typeof HTMLCanvasElement !== 'undefined') {
            checkNativeFunction(HTMLCanvasElement.prototype.toDataURL, 'HTMLCanvasElement.toDataURL', 'toDataURL');
            checkNativeFunction(HTMLCanvasElement.prototype.getContext, 'HTMLCanvasElement.getContext', 'getContext');
        }
        if (typeof CanvasRenderingContext2D !== 'undefined') {
            checkNativeFunction(CanvasRenderingContext2D.prototype.measureText, 'CanvasRenderingContext2D.measureText', 'measureText');
            checkNativeFunction(CanvasRenderingContext2D.prototype.getImageData, 'CanvasRenderingContext2D.getImageData', 'getImageData');
        }
        if (typeof WebGLRenderingContext !== 'undefined') {
            checkNativeFunction(WebGLRenderingContext.prototype.getParameter, 'WebGLRenderingContext.getParameter', 'getParameter');
            checkNativeFunction(WebGLRenderingContext.prototype.readPixels, 'WebGLRenderingContext.readPixels', 'readPixels');
        }
        if (typeof WebGL2RenderingContext !== 'undefined') {
            checkNativeFunction(WebGL2RenderingContext.prototype.getParameter, 'WebGL2RenderingContext.getParameter', 'getParameter');
        }
        if (typeof HTMLMediaElement !== 'undefined') {
            checkNativeFunction(HTMLMediaElement.prototype.canPlayType, 'HTMLMediaElement.canPlayType', 'canPlayType');
        }
        if (typeof Document !== 'undefined' && typeof document !== 'undefined') {
            checkNativeFunction(Document.prototype.createElement, 'Document.createElement', 'createElement');
            if (Object.prototype.hasOwnProperty.call(document, 'createElement')) {
                prototypeLies.push('document.createElement:instance_property_override');
            }
        }
        if (typeof window !== 'undefined') {
            for (const dimProp of ['outerWidth', 'outerHeight', 'innerWidth', 'innerHeight']) {
                const wDesc = Object.getOwnPropertyDescriptor(window, dimProp);
                if (wDesc && ('value' in wDesc || typeof wDesc.get !== 'function')) {
                    prototypeLies.push(`window.${dimProp}:replaceable_data_override`);
                }
            }
        }
        if (typeof OfflineAudioContext !== 'undefined') {
            checkNativeFunction(OfflineAudioContext.prototype.startRendering, 'OfflineAudioContext.startRendering', 'startRendering');
        }
        if (typeof AudioBuffer !== 'undefined') {
            checkNativeFunction(AudioBuffer.prototype.getChannelData, 'AudioBuffer.prototype.getChannelData', 'getChannelData');
            if (typeof AudioBuffer.prototype.copyFromChannel === 'function') {
                checkNativeFunction(AudioBuffer.prototype.copyFromChannel, 'AudioBuffer.copyFromChannel', 'copyFromChannel');
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
            ];
            for (const prop of navProps) {
                const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
                if (!desc) {
                    if (prop !== 'deviceMemory') {
                        prototypeLies.push(`Navigator.${prop}:descriptor_deleted`);
                    }
                }
                else if ('value' in desc || typeof desc.get !== 'function') {
                    prototypeLies.push(`Navigator.${prop}:data_descriptor_override`);
                }
                else {
                    checkNativeFunction(desc.get, `Navigator.${prop}.get`, `get ${prop}`);
                    if (typeof navigator !== 'undefined' &&
                        prop !== 'plugins' &&
                        prop !== 'mimeTypes') {
                        try {
                            const v0 = desc.get.call(navigator);
                            const v1 = desc.get.call(navigator, 1);
                            if (JSON.stringify(v0) !== JSON.stringify(v1)) {
                                prototypeLies.push(`Navigator.${prop}:getter_arity_lie`);
                            }
                        }
                        catch {
                            // ignore
                        }
                    }
                }
                if (typeof navigator !== 'undefined' && Object.prototype.hasOwnProperty.call(navigator, prop)) {
                    prototypeLies.push(`navigator.${prop}:instance_property_override`);
                }
            }
        }
        if (typeof Screen !== 'undefined' && typeof screen !== 'undefined') {
            const scrProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
            for (const prop of scrProps) {
                const desc = Object.getOwnPropertyDescriptor(Screen.prototype, prop);
                if (!desc) {
                    prototypeLies.push(`Screen.${prop}:descriptor_deleted`);
                }
                else if ('value' in desc || typeof desc.get !== 'function') {
                    prototypeLies.push(`Screen.${prop}:data_descriptor_override`);
                }
                else {
                    checkNativeFunction(desc.get, `Screen.${prop}.get`, `get ${prop}`);
                }
                if (Object.prototype.hasOwnProperty.call(screen, prop)) {
                    prototypeLies.push(`screen.${prop}:instance_property_override`);
                }
            }
            if ((screen.width > 0 && screen.availWidth > screen.width) ||
                (screen.height > 0 && screen.availHeight > screen.height)) {
                prototypeLies.push('screen:avail_exceeds_total_dimensions');
            }
        }
    }
    catch {
        // ignore
    }
    if (mathTampered) {
        mathEngineSignature = 'unknown_tampered_math';
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
function inferSubjectIdFromToken(token) {
    if (!token)
        return '';
    const raw = token.startsWith('Bearer ') ? token.slice(7).trim() : token.trim();
    if (!raw)
        return '';
    // 1. PrismID signed bearer token: `<subject_id>.<exp_unix>.<64hex>`
    const prismMatch = /^(.+)\.\d{9,12}\.[0-9a-f]{64}$/i.exec(raw);
    if (prismMatch && prismMatch[1]) {
        return prismMatch[1];
    }
    // 2. Standard 3-segment JWT (`header.payload.signature`) with `sub` claim
    const parts = raw.split('.');
    if (parts.length === 3 && parts[0].startsWith('eyJ')) {
        try {
            const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
            const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
            const jsonStr = typeof atob === 'function'
                ? atob(padded)
                : Buffer.from(padded, 'base64').toString('utf8');
            const parsed = JSON.parse(jsonStr);
            if (typeof parsed.sub === 'string' && parsed.sub.trim()) {
                return parsed.sub.trim();
            }
        }
        catch {
            // fall through
        }
    }
    return raw;
}
function collectDisplayGamutSpec() {
    try {
        if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
            return 'srgb|standard|fine';
        }
        const gamut = window.matchMedia('(color-gamut: rec2020)').matches
            ? 'rec2020'
            : window.matchMedia('(color-gamut: p3)').matches
                ? 'p3'
                : 'srgb';
        const hdr = window.matchMedia('(dynamic-range: high)').matches ? 'hdr' : 'standard';
        const ptr = window.matchMedia('(pointer: coarse)').matches ? 'coarse' : 'fine';
        return `${gamut}|${hdr}|${ptr}`;
    }
    catch {
        return 'srgb|standard|fine';
    }
}
function collectIntlHash() {
    try {
        const dtf = Intl.DateTimeFormat().resolvedOptions();
        const nf = Intl.NumberFormat().resolvedOptions();
        const numSample = new Intl.NumberFormat(undefined, {
            style: 'currency',
            currency: 'USD',
        }).format(123456.78);
        return sha256Hex([
            dtf.locale || '',
            dtf.calendar || '',
            dtf.numberingSystem || '',
            dtf.timeZone || '',
            nf.locale || '',
            numSample,
        ].join('|')).slice(0, 32);
    }
    catch {
        return '';
    }
}
function collectVoicesHash() {
    try {
        if (typeof speechSynthesis === 'undefined' ||
            typeof speechSynthesis.getVoices !== 'function') {
            return '';
        }
        const voices = speechSynthesis.getVoices() || [];
        if (voices.length === 0)
            return '';
        const canonical = voices
            .map((v) => `${v.voiceURI}|${v.lang}|${v.localService ? 1 : 0}`)
            .sort()
            .join(';');
        return sha256Hex(canonical).slice(0, 32);
    }
    catch {
        return '';
    }
}
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
        displayGamutSpec: collectDisplayGamutSpec(),
        intlHash: collectIntlHash(),
        voicesHash: collectVoicesHash(),
    };
}
export function createPrismClient(options = {}) {
    const baseUrl = (options.baseUrl || '').replace(/\/+$/, '');
    const fetchFn = options.fetchImpl || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : undefined);
    const cooldownMs = options.cooldownMs ?? 5 * 60 * 1000;
    const requestTimeoutMs = options.requestTimeoutMs ?? 5000;
    const probeTimeoutMs = options.probeTimeoutMs ?? 800;
    let lastIdentifiedToken = null;
    let lastIdentifiedAt = 0;
    let lastError = null;
    let inFlightPromise = null;
    function recordError(err) {
        lastError = err;
        try {
            options.onError?.(err);
        }
        catch {
            // ignore observer exceptions
        }
        return err;
    }
    function withDeadline(promise, timeoutMs, fallback) {
        let timer;
        const deadline = new Promise((resolve) => {
            timer = setTimeout(() => resolve(fallback), timeoutMs);
        });
        return Promise.race([promise, deadline]).finally(() => {
            if (timer !== undefined)
                clearTimeout(timer);
        });
    }
    // Covers both HTTP response headers AND full response body reading within a single deadline!
    async function fetchJsonWithDeadline(url, init) {
        if (!fetchFn)
            throw new Error('fetch unavailable');
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined;
        let timer;
        const timeoutPromise = new Promise((_, reject) => {
            timer = setTimeout(() => {
                if (controller)
                    controller.abort();
                const err = new Error('request deadline exceeded');
                err.isTimeout = true;
                reject(err);
            }, requestTimeoutMs);
        });
        try {
            const work = (async () => {
                const res = await fetchFn(url, controller ? { ...init, signal: controller.signal } : init);
                const text = await res.text();
                if (!text) {
                    return { ok: res.ok, status: res.status, data: null };
                }
                try {
                    return { ok: res.ok, status: res.status, data: JSON.parse(text) };
                }
                catch {
                    return { ok: res.ok, status: res.status, data: null };
                }
            })();
            return await Promise.race([work, timeoutPromise]);
        }
        finally {
            if (timer !== undefined)
                clearTimeout(timer);
        }
    }
    // Resolves access token AT MOST ONCE per client operation (S3-39).
    async function resolveAccessToken() {
        if (!options.getAccessToken)
            return null;
        const tok = await withDeadline(Promise.resolve(options.getAccessToken()).catch(() => null), Math.min(requestTimeoutMs, 1500), null);
        return tok ? String(tok) : null;
    }
    function buildAuthHeadersFromToken(token) {
        const headers = {
            'Content-Type': 'application/json',
        };
        if (token) {
            headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`;
        }
        return headers;
    }
    async function collectAndSeal(challenge) {
        const samplePoints = Array.isArray(challenge.sample_points) && challenge.sample_points.length > 0
            ? challenge.sample_points
            : DEFAULT_SAMPLE_POINTS;
        // Enforce bounded aggregate probe budget across synchronous & asynchronous probes (S3-41).
        const aggregateBudgetMs = Math.max(120, Math.min(probeTimeoutMs, requestTimeoutMs));
        const audioBudgetMs = Math.min(400, Math.floor(aggregateBudgetMs * 0.65));
        const workerBudgetMs = Math.min(300, Math.floor(aggregateBudgetMs * 0.5));
        const storageBudgetMs = Math.min(350, Math.floor(aggregateBudgetMs * 0.55));
        const providerTimeoutMs = Math.min(requestTimeoutMs, aggregateBudgetMs);
        const sysMeta = collectSystemMetadata();
        const webgl = collectWebGLProbe(challenge.render_seed, samplePoints);
        const fontsCanvas = collectFontsAndCanvasProbe();
        const lieDetector = collectLieDetectorProbe();
        const fallbackAudio = {
            audio_compressor_hash: sha256Hex('prismid-audio-aggregate-deadline'),
            audio_copy_hash: sha256Hex('prismid-audio-aggregate-deadline'),
            audio_silent_delta: 0,
            audio_noise_injected: false,
            audio_muted: false,
        };
        const fallbackWorker = {
            worker_unavailable: true,
            worker_webgl_available: false,
            worker_lie_detected: false,
            worker_gpu_renderer: '',
            worker_static_webgl_fp_hash: '',
            worker_cpu_cores: 0,
            worker_platform: '',
            worker_user_agent: '',
            worker_timezone: '',
        };
        const fallbackBeacon = {
            beacon_id: '',
            storage_healed: false,
            surviving_silos: [],
            surviving_silos_mask: 0,
        };
        // Preload persistent deviceKey in parallel with async probes so IndexedDB I/O overlaps (S3-41).
        const [audioRes, workerLie, storageBeacon, nativeAnchor, turnstileToken] = await withDeadline(Promise.all([
            collectAudioProbeWithTrap(audioBudgetMs),
            collectWorkerLieProbe({
                gpuRenderer: webgl.gpu_renderer,
                staticWebGLFpHash: webgl.static_webgl_fp_hash,
                webglAvailable: webgl.webgl_available,
                cpuCores: sysMeta.cpuCores,
                platform: sysMeta.platform,
                userAgent: sysMeta.userAgent,
                timezone: sysMeta.timezone,
            }, workerBudgetMs),
            collectAndHealStorageBeacon(storageBudgetMs),
            options.nativeAnchorProvider
                ? withDeadline(Promise.resolve(options.nativeAnchorProvider()).catch(() => null), providerTimeoutMs, null)
                : Promise.resolve(null),
            options.getTurnstileToken
                ? withDeadline(Promise.resolve(options.getTurnstileToken()).catch(() => undefined), providerTimeoutMs, undefined)
                : Promise.resolve(undefined),
            preloadDeviceKey().catch(() => false),
        ]).then(([a, w, s, n, t]) => [a, w, s, n, t]), aggregateBudgetMs, [fallbackAudio, fallbackWorker, fallbackBeacon, null, undefined]);
        const deviceKey = await withDeadline(signChallengeWithDeviceKey({
            nonce: challenge.nonce,
            beaconId: storageBeacon.beacon_id,
            staticWebGLFpHash: webgl.static_webgl_fp_hash,
            audioCompressorHash: audioRes.audio_compressor_hash,
        }), 200, undefined);
        const payload = {
            v: 1,
            nonce: challenge.nonce,
            collected_at: Date.now(),
            beacon_id: storageBeacon.beacon_id,
            ...(deviceKey ? { device_key: deviceKey } : {}),
            webgl: {
                gpu_vendor: webgl.gpu_vendor,
                gpu_renderer: webgl.gpu_renderer,
                webgl_limits_vector: webgl.webgl_limits_vector,
                webgl_extensions_hash: webgl.webgl_extensions_hash,
                webgl_available: webgl.webgl_available,
                static_webgl_fp_hash: webgl.static_webgl_fp_hash,
                spot_pixels: webgl.spot_pixels,
            },
            audio_compressor_hash: audioRes.audio_compressor_hash,
            audio_copy_hash: audioRes.audio_copy_hash,
            audio_silent_delta: audioRes.audio_silent_delta,
            ...(audioRes.audio_muted ? { audio_muted: true } : {}),
            system: {
                user_agent: sysMeta.userAgent,
                platform: sysMeta.platform,
                cpu_cores: sysMeta.cpuCores,
                ...(sysMeta.deviceMemory !== undefined ? { device_memory: sysMeta.deviceMemory } : {}),
                timezone: sysMeta.timezone,
                languages: sysMeta.languages,
                screen_spec: sysMeta.screenSpec,
                display_gamut_spec: sysMeta.displayGamutSpec,
                ...(sysMeta.voicesHash ? { voices_hash: sysMeta.voicesHash } : {}),
                ...(sysMeta.intlHash ? { intl_hash: sysMeta.intlHash } : {}),
                canvas_2d_hash: fontsCanvas.canvas_2d_hash,
                fonts_bitmap_hash: fontsCanvas.fonts_bitmap_hash,
                canvas_control_rgba: fontsCanvas.canvas_control_rgba,
                canvas_readback_delta: fontsCanvas.canvas_readback_delta,
            },
            lies: {
                worker_unavailable: workerLie.worker_unavailable,
                worker_webgl_available: workerLie.worker_webgl_available,
                worker_lie_detected: workerLie.worker_lie_detected,
                worker_gpu_renderer: workerLie.worker_gpu_renderer,
                worker_static_webgl_fp_hash: workerLie.worker_static_webgl_fp_hash,
                worker_cpu_cores: workerLie.worker_cpu_cores,
                worker_platform: workerLie.worker_platform,
                worker_user_agent: workerLie.worker_user_agent,
                worker_timezone: workerLie.worker_timezone,
                canvas_noise_injected: fontsCanvas.canvas_noise_injected,
                webgl_noise_injected: webgl.webgl_noise_injected,
                audio_noise_injected: audioRes.audio_noise_injected,
                storage_healed: storageBeacon.storage_healed,
                storage_silos_mask: storageBeacon.surviving_silos_mask,
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
    async function identifyDetailed(callOpts) {
        if (!fetchFn) {
            return {
                result: null,
                error: recordError({ kind: 'network', message: 'fetch implementation unavailable' }),
            };
        }
        // Resolve access token ONCE and reuse for cooldown check + HTTP Authorization header (S3-39).
        const token = await resolveAccessToken();
        const now = Date.now();
        if (!callOpts?.force &&
            lastIdentifiedAt > 0 &&
            lastIdentifiedToken === token &&
            now - lastIdentifiedAt < cooldownMs) {
            return { result: null, error: null };
        }
        if (inFlightPromise) {
            return inFlightPromise;
        }
        inFlightPromise = (async () => {
            try {
                lastError = null;
                const headers = buildAuthHeadersFromToken(token);
                if (!callOpts?.force) {
                    try {
                        const scRes = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/should-collect`, {
                            method: 'GET',
                            headers,
                        });
                        if (scRes.ok && scRes.data) {
                            const shouldCollect = scRes.data.should_collect ?? scRes.data.data?.should_collect ?? true;
                            if (shouldCollect === false) {
                                lastIdentifiedToken = token;
                                lastIdentifiedAt = Date.now();
                                // Never synthesize `{ accepted: true }` when collection was skipped (S3-53).
                                return {
                                    result: {
                                        accepted: false,
                                        skipped: true,
                                        code: 'COLLECTION_SKIPPED',
                                        message: 'collection skipped by should-collect policy',
                                    },
                                    error: null,
                                };
                            }
                        }
                    }
                    catch {
                        // Proceed to challenge if should-collect endpoint is unreachable or unused
                    }
                }
                const chRes = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/challenge`, {
                    method: 'POST',
                    headers,
                    body: '{}',
                });
                if (!chRes.ok || !chRes.data) {
                    const err = recordError({
                        kind: chRes.ok ? 'malformed_response' : 'http',
                        status: chRes.status,
                        code: chRes.data?.code,
                        message: chRes.data?.error || `challenge HTTP ${chRes.status}`,
                    });
                    return { result: null, error: err };
                }
                const chRaw = chRes.data;
                const challenge = chRaw.nonce ? chRaw : chRaw.data;
                if (!challenge || !challenge.nonce || !Array.isArray(challenge.render_seed)) {
                    const err = recordError({
                        kind: 'malformed_response',
                        status: chRes.status,
                        message: 'invalid challenge schema',
                    });
                    return { result: null, error: err };
                }
                const { request } = await collectAndSeal(challenge);
                const idRes = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/identify`, {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(request),
                });
                const idRaw = idRes.data;
                if (!idRaw || typeof idRaw !== 'object') {
                    const err = recordError({
                        kind: idRes.ok ? 'malformed_response' : 'http',
                        status: idRes.status,
                        message: `identify HTTP ${idRes.status} without valid JSON body`,
                    });
                    return { result: null, error: err };
                }
                const candidate = typeof idRaw.accepted === 'boolean'
                    ? idRaw
                    : idRaw.data && typeof idRaw.data.accepted === 'boolean'
                        ? idRaw.data
                        : undefined;
                // Strict schema check: never synthesize `{ accepted: true }` from an empty `{}` response!
                if (!candidate || typeof candidate.accepted !== 'boolean') {
                    const err = recordError({
                        kind: idRes.ok ? 'malformed_response' : 'http',
                        status: idRes.status,
                        code: idRaw.code,
                        message: idRaw.error || idRaw.message || `identify HTTP ${idRes.status}`,
                    });
                    return { result: null, error: err };
                }
                if (!idRes.ok && candidate.accepted !== false) {
                    const err = recordError({
                        kind: 'http',
                        status: idRes.status,
                        code: candidate.code,
                        message: candidate.message || `identify HTTP ${idRes.status}`,
                    });
                    return { result: null, error: err };
                }
                if (!idRes.ok) {
                    const err = recordError({
                        kind: 'http',
                        status: idRes.status,
                        code: candidate.code,
                        message: candidate.message || idRaw.error || `identify HTTP ${idRes.status}`,
                    });
                    // Preserve structured `accepted: false` rejection payloads (e.g. HTTP 409/403) when non-429/401,
                    // while return null on 401/429 gateway rejections without domain error code if no `code` was set.
                    if (idRes.status === 401 || idRes.status === 429) {
                        if (!candidate.code) {
                            return { result: null, error: err };
                        }
                    }
                    return { result: candidate, error: err };
                }
                if (candidate.accepted && !candidate.risk_pending && !candidate.device_key_recovery_required) {
                    lastIdentifiedToken = token;
                    lastIdentifiedAt = Date.now();
                }
                return { result: candidate, error: null };
            }
            catch (caught) {
                const isTimeout = Boolean(caught?.isTimeout);
                const err = recordError({
                    kind: isTimeout ? 'timeout' : 'network',
                    message: caught instanceof Error ? caught.message : 'network error',
                });
                return { result: null, error: err };
            }
            finally {
                inFlightPromise = null;
            }
        })();
        return inFlightPromise;
    }
    async function identify(callOpts) {
        const { result } = await identifyDetailed(callOpts);
        return result;
    }
    function getLastError() {
        return lastError;
    }
    async function rebindKey(rebindOpts) {
        if (!fetchFn) {
            return { accepted: false, error: 'fetch unavailable' };
        }
        try {
            const token = await resolveAccessToken();
            const headers = buildAuthHeadersFromToken(token);
            let subjectId = (rebindOpts?.subjectId || '').trim();
            if (!subjectId && options.getSubjectId) {
                const resolvedSub = await withDeadline(Promise.resolve(options.getSubjectId()).catch(() => null), 1500, null);
                if (resolvedSub)
                    subjectId = String(resolvedSub).trim();
            }
            if (!subjectId) {
                subjectId = inferSubjectIdFromToken(token);
            }
            if (!subjectId) {
                return { accepted: false, error: 'subjectId is required to sign rebind proof' };
            }
            const beaconId = rebindOpts?.beaconId?.trim().toLowerCase() ||
                (await collectAndHealStorageBeacon(Math.min(350, probeTimeoutMs))).beacon_id;
            if (!beaconId) {
                return { accepted: false, error: 'storage beacon unavailable' };
            }
            const chRes = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/challenge`, {
                method: 'POST',
                headers,
                body: '{}',
            });
            const chRaw = chRes.data;
            const challenge = chRaw?.nonce ? chRaw : chRaw?.data;
            if (!chRes.ok || !challenge?.nonce) {
                return { accepted: false, error: chRaw?.error || `challenge HTTP ${chRes.status}` };
            }
            let deviceKey;
            let previousDeviceKey;
            if (rebindOpts?.rotate) {
                const rotated = await rotateDeviceKeyAndSignRebind({
                    nonce: challenge.nonce,
                    subjectId,
                    beaconId,
                });
                deviceKey = rotated?.device_key;
                previousDeviceKey = rotated?.previous_device_key;
            }
            else {
                deviceKey = await signRebindWithDeviceKey({
                    nonce: challenge.nonce,
                    subjectId,
                    beaconId,
                });
            }
            if (!deviceKey) {
                return { accepted: false, error: 'failed to initialize or sign with persistent WebCrypto device key' };
            }
            let stepUpToken = rebindOpts?.stepUpToken?.trim() || '';
            if (!stepUpToken && !previousDeviceKey && options.getStepUpToken) {
                const fetchedStepUp = await withDeadline(Promise.resolve(options.getStepUpToken('rebind_key', { subjectId, beaconId })).catch(() => null), requestTimeoutMs, null);
                if (fetchedStepUp)
                    stepUpToken = String(fetchedStepUp).trim();
            }
            const rbRes = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/rebind-key`, {
                method: 'POST',
                headers: {
                    ...headers,
                    ...(stepUpToken ? { 'X-PrismID-StepUp-Token': stepUpToken } : {}),
                },
                body: JSON.stringify({
                    challenge_nonce: challenge.nonce,
                    beacon_id: beaconId,
                    step_up_token: stepUpToken || undefined,
                    device_key: deviceKey,
                    ...(previousDeviceKey ? { previous_device_key: previousDeviceKey } : {}),
                }),
            });
            if (!rbRes.data) {
                return { accepted: false, error: `rebind-key HTTP ${rbRes.status}` };
            }
            resetSessionCache();
            return {
                ...rbRes.data,
                accepted: rbRes.ok && rbRes.data.accepted !== false,
            };
        }
        catch (err) {
            return {
                accepted: false,
                error: err instanceof Error ? err.message : 'rebindKey request failed',
            };
        }
    }
    async function clearSpoof(clearOpts) {
        if (!fetchFn) {
            return { accepted: false, error: 'fetch unavailable' };
        }
        try {
            const token = await resolveAccessToken();
            const headers = buildAuthHeadersFromToken(token);
            const subjectId = inferSubjectIdFromToken(token);
            let stepUpToken = clearOpts?.stepUpToken?.trim() || '';
            if (!stepUpToken && options.getStepUpToken) {
                const fetched = await withDeadline(Promise.resolve(options.getStepUpToken('clear_spoof', { subjectId })).catch(() => null), requestTimeoutMs, null);
                if (fetched)
                    stepUpToken = String(fetched).trim();
            }
            const res = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/clear-spoof`, {
                method: 'POST',
                headers: {
                    ...headers,
                    ...(stepUpToken ? { 'X-PrismID-StepUp-Token': stepUpToken } : {}),
                },
                body: JSON.stringify({ step_up_token: stepUpToken }),
            });
            if (!res.data) {
                return { accepted: false, error: `clear-spoof HTTP ${res.status}` };
            }
            resetSessionCache();
            return {
                ...res.data,
                accepted: res.ok && res.data.accepted !== false,
            };
        }
        catch (err) {
            return {
                accepted: false,
                error: err instanceof Error ? err.message : 'clearSpoof request failed',
            };
        }
    }
    async function deleteSubject() {
        if (!fetchFn) {
            return { accepted: false, error: 'fetch unavailable' };
        }
        try {
            const token = await resolveAccessToken();
            const headers = buildAuthHeadersFromToken(token);
            const res = await fetchJsonWithDeadline(`${baseUrl}/api/v1/risk/subject`, {
                method: 'DELETE',
                headers,
            });
            if (!res.data) {
                return { accepted: false, error: `delete-subject HTTP ${res.status}` };
            }
            resetSessionCache({ includeDeviceKey: true });
            return {
                ...res.data,
                accepted: res.ok && res.data.accepted !== false,
            };
        }
        catch (err) {
            return {
                accepted: false,
                error: err instanceof Error ? err.message : 'deleteSubject request failed',
            };
        }
    }
    function resetSessionCache(resetOpts) {
        lastIdentifiedToken = null;
        lastIdentifiedAt = 0;
        if (resetOpts?.includeDeviceKey) {
            resetDeviceKeyCache();
        }
    }
    return {
        identify,
        identifyDetailed,
        getLastError,
        collectAndSeal,
        rebindKey,
        clearSpoof,
        deleteSubject,
        resetSessionCache,
    };
}
