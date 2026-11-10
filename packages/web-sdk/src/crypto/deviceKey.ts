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

function isStoredKey(value: unknown): value is StoredDeviceKeyRecord {
  const rec = value as StoredDeviceKeyRecord | undefined
  return !!rec && typeof rec === 'object' && !!rec.privateKey &&
    rec.privateKey.type === 'private' && rec.privateKey.extractable === false &&
    rec.privateKey.algorithm?.name === 'ECDSA' &&
    (rec.privateKey.algorithm as EcKeyAlgorithm).namedCurve === 'P-256' &&
    Array.isArray(rec.privateKey.usages) && rec.privateKey.usages.includes('sign') && typeof rec.pubKeyHex === 'string' &&
    /^04[0-9a-f]{128}$/.test(rec.pubKeyHex)
}

// The read and conditional insert share one readwrite transaction. IndexedDB serializes
// these transactions across tabs, so concurrent first visits all use the committed winner.
function loadOrCreatePersistedKey(candidate: StoredDeviceKeyRecord): Promise<StoredDeviceKeyRecord | null> {
  if (typeof indexedDB === 'undefined' || !indexedDB) return Promise.resolve(null)
  return new Promise((resolve) => {
    let settled = false
    let db: IDBDatabase | undefined
    let tx: IDBTransaction | undefined
    const finish = (value: StoredDeviceKeyRecord | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (!value) {
        try { tx?.abort() } catch {}
      }
      try { db?.close() } catch {}
      resolve(value)
    }
    const timer = setTimeout(() => finish(null), IDB_KEY_TIMEOUT_MS)
    try {
      const req = indexedDB.open(KEY_DB_NAME, 1)
      req.onblocked = req.onerror = () => finish(null)
      req.onupgradeneeded = () => {
        if (settled) { req.transaction?.abort(); return }
        if (!req.result.objectStoreNames.contains(KEY_STORE_NAME)) {
          req.result.createObjectStore(KEY_STORE_NAME)
        }
      }
      req.onsuccess = () => {
        db = req.result
        if (settled) { db.close(); return }
        db.onversionchange = () => db?.close()
        try {
          tx = db.transaction(KEY_STORE_NAME, 'readwrite')
          const store = tx.objectStore(KEY_STORE_NAME)
          let winner: StoredDeviceKeyRecord | null = null
          tx.oncomplete = () => finish(winner)
          tx.onerror = tx.onabort = () => finish(null)
          const read = store.get(KEY_RECORD_ID)
          read.onerror = () => finish(null)
          read.onsuccess = () => {
            if (settled) return
            try {
              if (read.result === undefined) {
                winner = candidate
                // Never overwrite another page's existing key (or an unreadable record).
                store.add(candidate, KEY_RECORD_ID)
              } else if (isStoredKey(read.result)) {
                winner = read.result
              }
            } catch { finish(null) }
          }
        } catch { finish(null) }
      }
    } catch { finish(null) }
  })
}

let keyInitialization: Promise<StoredDeviceKeyRecord | null> | null = null

async function getOrCreateDeviceKeyRecord(): Promise<StoredDeviceKeyRecord | null> {
  if (memoryCachedKey) return memoryCachedKey
  if (keyInitialization) return keyInitialization
  const subtle = getSubtleCrypto()
  if (!subtle || typeof indexedDB === 'undefined' || !indexedDB) return null
  keyInitialization = (async () => {
    try {
      const pair = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']
      )
      const rawPub = await subtle.exportKey('raw', pair.publicKey)
      const persisted = await loadOrCreatePersistedKey({
        privateKey: pair.privateKey,
        pubKeyHex: bytesToHex(new Uint8Array(rawPub)),
      })
      // Only a confirmed transaction commit may establish a server-side TOFU binding.
      if (persisted) memoryCachedKey = persisted
      return persisted
    } catch { return null }
  })()
  try { return await keyInitialization } finally { keyInitialization = null }
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
