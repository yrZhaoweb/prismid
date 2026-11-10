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

export interface DeviceKeyProof {
  alg: 'ecdsa-p256'
  pub_key: string
  signature: string
}

interface StoredDeviceKeyRecord {
  privateKey: CryptoKey
  pubKeyHex: string
}

const KEY_DB_NAME = '_prismid_key_v1'
const KEY_STORE_NAME = 'keystore'
const KEY_RECORD_ID = 'hw_ecdsa_p256'
const IDB_KEY_TIMEOUT_MS = 150

let memoryCachedKey: StoredDeviceKeyRecord | null = null

function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0')
  }
  return out
}

function getSubtleCrypto(): SubtleCrypto | null {
  if (
    typeof globalThis !== 'undefined' &&
    typeof globalThis.crypto !== 'undefined' &&
    globalThis.crypto &&
    typeof globalThis.crypto.subtle !== 'undefined'
  ) {
    return globalThis.crypto.subtle
  }
  return null
}

function readKeyFromIDB(): Promise<StoredDeviceKeyRecord | null> {
  return new Promise((resolve) => {
    if (typeof indexedDB === 'undefined' || !indexedDB) {
      resolve(null)
      return
    }
    let settled = false
    const done = (val: StoredDeviceKeyRecord | null) => {
      if (settled) return
      settled = true
      resolve(val)
    }
    const timer = setTimeout(() => done(null), IDB_KEY_TIMEOUT_MS)

    try {
      const req = indexedDB.open(KEY_DB_NAME, 1)
      req.onupgradeneeded = () => {
        const db = req.result
        if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
          db.createObjectStore(KEY_STORE_NAME)
        }
      }
      req.onerror = () => {
        clearTimeout(timer)
        done(null)
      }
      req.onblocked = () => {
        clearTimeout(timer)
        done(null)
      }
      req.onsuccess = () => {
        const db = req.result
        try {
          const tx = db.transaction(KEY_STORE_NAME, 'readonly')
          const store = tx.objectStore(KEY_STORE_NAME)
          const getReq = store.get(KEY_RECORD_ID)
          getReq.onsuccess = () => {
            clearTimeout(timer)
            const rec = getReq.result as StoredDeviceKeyRecord | undefined
            db.close()
            if (
              rec &&
              typeof rec === 'object' &&
              rec.privateKey &&
              typeof rec.pubKeyHex === 'string' &&
              /^[0-9a-f]{130}$/.test(rec.pubKeyHex)
            ) {
              done(rec)
            } else {
              done(null)
            }
          }
          getReq.onerror = () => {
            clearTimeout(timer)
            db.close()
            done(null)
          }
        } catch {
          clearTimeout(timer)
          db.close()
          done(null)
        }
      }
    } catch {
      clearTimeout(timer)
      done(null)
    }
  })
}

function writeKeyToIDB(rec: StoredDeviceKeyRecord): Promise<void> {
  return new Promise((resolve) => {
    if (typeof indexedDB === 'undefined' || !indexedDB) {
      resolve()
      return
    }
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      resolve()
    }
    const timer = setTimeout(done, IDB_KEY_TIMEOUT_MS)

    try {
      const req = indexedDB.open(KEY_DB_NAME, 1)
      req.onupgradeneeded = () => {
        const db = req.result
        if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
          db.createObjectStore(KEY_STORE_NAME)
        }
      }
      req.onerror = () => {
        clearTimeout(timer)
        done()
      }
      req.onblocked = () => {
        clearTimeout(timer)
        done()
      }
      req.onsuccess = () => {
        const db = req.result
        try {
          const tx = db.transaction(KEY_STORE_NAME, 'readwrite')
          const store = tx.objectStore(KEY_STORE_NAME)
          store.put(rec, KEY_RECORD_ID)
          tx.oncomplete = () => {
            clearTimeout(timer)
            db.close()
            done()
          }
          tx.onerror = () => {
            clearTimeout(timer)
            db.close()
            done()
          }
          tx.onabort = () => {
            clearTimeout(timer)
            db.close()
            done()
          }
        } catch {
          clearTimeout(timer)
          db.close()
          done()
        }
      }
    } catch {
      clearTimeout(timer)
      done()
    }
  })
}

async function getOrCreateDeviceKeyRecord(): Promise<StoredDeviceKeyRecord | null> {
  if (memoryCachedKey) {
    return memoryCachedKey
  }
  const subtle = getSubtleCrypto()
  if (!subtle) {
    return null
  }

  const existing = await readKeyFromIDB()
  if (existing) {
    memoryCachedKey = existing
    return existing
  }

  try {
    const keyPair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, // non-extractable private key!
      ['sign', 'verify']
    )
    const rawPub = await subtle.exportKey('raw', keyPair.publicKey)
    const pubKeyHex = bytesToHex(new Uint8Array(rawPub))
    const record: StoredDeviceKeyRecord = {
      privateKey: keyPair.privateKey,
      pubKeyHex,
    }
    memoryCachedKey = record
    await writeKeyToIDB(record)
    return record
  } catch {
    return null
  }
}

export function buildDeviceKeyTranscript(params: {
  nonce: string
  beaconId: string
  staticWebGLFpHash: string
  audioCompressorHash: string
}): string {
  return [
    'prismid-v2-sig',
    params.nonce.trim(),
    params.beaconId.trim().toLowerCase(),
    params.staticWebGLFpHash.trim().toLowerCase(),
    params.audioCompressorHash.trim().toLowerCase(),
  ].join('|')
}

export async function signChallengeWithDeviceKey(params: {
  nonce: string
  beaconId: string
  staticWebGLFpHash: string
  audioCompressorHash: string
}): Promise<DeviceKeyProof | undefined> {
  const subtle = getSubtleCrypto()
  if (!subtle) {
    return undefined
  }
  const rec = await getOrCreateDeviceKeyRecord()
  if (!rec) {
    return undefined
  }
  try {
    const transcript = buildDeviceKeyTranscript(params)
    const msgBytes = new TextEncoder().encode(transcript)
    const sigBuf = await subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      rec.privateKey,
      msgBytes
    )
    const sigHex = bytesToHex(new Uint8Array(sigBuf))
    if (sigHex.length !== 128) {
      return undefined
    }
    return {
      alg: 'ecdsa-p256',
      pub_key: rec.pubKeyHex,
      signature: sigHex,
    }
  } catch {
    return undefined
  }
}
