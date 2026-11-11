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
const IDB_KEY_TIMEOUT_MS = 250

let memoryCachedKey: StoredDeviceKeyRecord | null = null

/**
 * Clears the in-memory `CryptoKey` cache so subsequent operations re-read `IndexedDB`
 * (e.g. after in-page site-data clearing or explicit key recovery/rotation).
 */
export function resetDeviceKeyCache(): void {
  memoryCachedKey = null
}

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
  const usages = rec?.privateKey?.usages
  const hasSignUsage = Array.isArray(usages)
    ? usages.includes('sign')
    : Array.from<string>(usages ?? []).includes('sign')
  return !!rec && typeof rec === 'object' && !!rec.privateKey &&
    rec.privateKey.type === 'private' && rec.privateKey.extractable === false &&
    rec.privateKey.algorithm?.name === 'ECDSA' &&
    (rec.privateKey.algorithm as EcKeyAlgorithm).namedCurve === 'P-256' &&
    hasSignUsage && typeof rec.pubKeyHex === 'string' &&
    /^04[0-9a-f]{128}$/.test(rec.pubKeyHex)
}

type ReadKeyOutcome =
  | { status: 'found'; record: StoredDeviceKeyRecord }
  | { status: 'missing' }
  | { status: 'corrupted' }
  | { status: 'error' }

// Fast read-only lookup BEFORE generating an ECDSA P-256 keypair so warm page loads
// never waste CPU/WebCrypto keygen work when a persisted key already exists (S2-23).
function readExistingPersistedKey(timeoutMs: number = IDB_KEY_TIMEOUT_MS): Promise<ReadKeyOutcome> {
  if (typeof indexedDB === 'undefined' || !indexedDB) {
    return Promise.resolve({ status: 'error' })
  }
  const budgetMs = Math.max(25, timeoutMs)
  return new Promise((resolve) => {
    let settled = false
    let db: IDBDatabase | undefined
    const finish = (outcome: ReadKeyOutcome) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { db?.close() } catch {}
      resolve(outcome)
    }
    const timer = setTimeout(() => finish({ status: 'error' }), budgetMs)
    try {
      const req = indexedDB.open(KEY_DB_NAME, 1)
      req.onblocked = req.onerror = () => finish({ status: 'error' })
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
          if (db.objectStoreNames && typeof db.objectStoreNames.contains === 'function' && !db.objectStoreNames.contains(KEY_STORE_NAME)) {
            finish({ status: 'missing' })
            return
          }
          const tx = db.transaction(KEY_STORE_NAME, 'readonly')
          tx.onerror = tx.onabort = () => finish({ status: 'error' })
          const store = tx.objectStore(KEY_STORE_NAME)
          const read = store.get(KEY_RECORD_ID)
          read.onerror = () => finish({ status: 'error' })
          read.onsuccess = () => {
            if (settled) return
            if (read.result === undefined) {
              finish({ status: 'missing' })
            } else if (isStoredKey(read.result)) {
              finish({ status: 'found', record: read.result })
            } else {
              finish({ status: 'corrupted' })
            }
          }
        } catch {
          finish({ status: 'error' })
        }
      }
    } catch {
      finish({ status: 'error' })
    }
  })
}

// The read and conditional insert/repair share one readwrite transaction. IndexedDB serializes
// these transactions across tabs, so concurrent first visits all use the committed winner,
// and corrupted records are atomically repaired instead of permanently disabling `d_key_*` (S3-32).
function loadOrCreatePersistedKey(
  candidate: StoredDeviceKeyRecord,
  forceOverwrite = false,
  timeoutMs: number = IDB_KEY_TIMEOUT_MS
): Promise<StoredDeviceKeyRecord | null> {
  if (typeof indexedDB === 'undefined' || !indexedDB) return Promise.resolve(null)
  const budgetMs = Math.max(25, timeoutMs)
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
    const timer = setTimeout(() => finish(null), budgetMs)
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
          if (forceOverwrite) {
            winner = candidate
            if (typeof store.put === 'function') {
              store.put(candidate, KEY_RECORD_ID)
            } else {
              store.add(candidate, KEY_RECORD_ID)
            }
            return
          }
          const read = store.get(KEY_RECORD_ID)
          read.onerror = () => finish(null)
          read.onsuccess = () => {
            if (settled) return
            try {
              if (read.result === undefined) {
                winner = candidate
                store.add(candidate, KEY_RECORD_ID)
              } else if (isStoredKey(read.result)) {
                winner = read.result
              } else {
                // Repair corrupted / schema-invalid IndexedDB record in place (S3-32).
                winner = candidate
                if (typeof store.put === 'function') {
                  store.put(candidate, KEY_RECORD_ID)
                } else {
                  if (typeof store.delete === 'function') store.delete(KEY_RECORD_ID)
                  store.add(candidate, KEY_RECORD_ID)
                }
              }
            } catch { finish(null) }
          }
        } catch { finish(null) }
      }
    } catch { finish(null) }
  })
}

async function generateCandidateKeyRecord(subtle: SubtleCrypto): Promise<StoredDeviceKeyRecord> {
  const pair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify']
  )
  const rawPub = await subtle.exportKey('raw', pair.publicKey)
  return {
    privateKey: pair.privateKey,
    pubKeyHex: bytesToHex(new Uint8Array(rawPub)),
  }
}

let keyInitialization: Promise<StoredDeviceKeyRecord | null> | null = null

async function getOrCreateDeviceKeyRecord(options?: {
  bypassMemoryCache?: boolean
  timeoutMs?: number
}): Promise<StoredDeviceKeyRecord | null> {
  if (!options?.bypassMemoryCache && memoryCachedKey) return memoryCachedKey
  if (keyInitialization) return keyInitialization
  const subtle = getSubtleCrypto()
  if (!subtle || typeof indexedDB === 'undefined' || !indexedDB) return null
  const idbTimeoutMs = options?.timeoutMs ?? IDB_KEY_TIMEOUT_MS
  keyInitialization = (async () => {
    try {
      const existing = await readExistingPersistedKey(idbTimeoutMs)
      if (existing.status === 'found') {
        memoryCachedKey = existing.record
        return existing.record
      }
      if (existing.status === 'error') {
        // IndexedDB blocked/timed out/errored: do not open a second transaction or cache a temporary key.
        if (options?.bypassMemoryCache) {
          memoryCachedKey = null
        }
        return null
      }
      // status === 'missing' || status === 'corrupted': generate fresh P-256 keypair & persist atomically.
      const candidate = await generateCandidateKeyRecord(subtle)
      const persisted = await loadOrCreatePersistedKey(candidate, false, idbTimeoutMs)
      // Only a confirmed transaction commit may establish a server-side TOFU binding.
      memoryCachedKey = persisted
      return persisted
    } catch {
      return null
    }
  })()
  try { return await keyInitialization } finally { keyInitialization = null }
}

/**
 * Preloads or initializes the persisted ECDSA P-256 device key in parallel with other probes.
 */
export async function preloadDeviceKey(timeoutMs?: number): Promise<boolean> {
  const rec = await getOrCreateDeviceKeyRecord({ timeoutMs })
  return rec !== null
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

export function buildRebindKeyTranscript(params: {
  nonce: string
  subjectId: string
  beaconId: string
}): string {
  return [
    'prismid-v2-rebind',
    params.nonce.trim(),
    params.subjectId.trim(),
    params.beaconId.trim().toLowerCase(),
  ].join('|')
}

export function buildPreviousKeyRotationTranscript(params: {
  nonce: string
  subjectId: string
  beaconId: string
}): string {
  return [
    'prismid-v2-rebind-prev',
    params.nonce.trim(),
    params.subjectId.trim(),
    params.beaconId.trim().toLowerCase(),
  ].join('|')
}

async function signTranscript(
  subtle: SubtleCrypto,
  rec: StoredDeviceKeyRecord,
  transcript: string
): Promise<DeviceKeyProof | undefined> {
  try {
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

export async function signRebindWithDeviceKey(
  params: {
    nonce: string
    subjectId: string
    beaconId: string
  },
  timeoutMs?: number
): Promise<DeviceKeyProof | undefined> {
  const subtle = getSubtleCrypto()
  if (!subtle) {
    return undefined
  }
  // Always re-verify IndexedDB on rebind so in-session site-data clearing generates a fresh key
  // without requiring a page reload (S2-24).
  const rec = await getOrCreateDeviceKeyRecord({ bypassMemoryCache: true, timeoutMs })
  if (!rec) {
    return undefined
  }
  return signTranscript(subtle, rec, buildRebindKeyTranscript(params))
}

/**
 * Rotates the persisted ECDSA P-256 keypair in-place and signs both the new key PoP (`device_key`)
 * and, when a previous key was still accessible in IndexedDB or memory, the continuity proof
 * (`previous_device_key`) over `prismid-v2-rebind-prev|<nonce>|<subject>|<beacon>|<new_pub_key>` (S2-12).
 */
export async function rotateDeviceKeyAndSignRebind(
  params: {
    nonce: string
    subjectId: string
    beaconId: string
  },
  timeoutMs?: number
): Promise<{ device_key: DeviceKeyProof; previous_device_key?: DeviceKeyProof } | undefined> {
  const subtle = getSubtleCrypto()
  if (!subtle || typeof indexedDB === 'undefined' || !indexedDB) {
    return undefined
  }
  const idbTimeoutMs = timeoutMs ?? IDB_KEY_TIMEOUT_MS
  const existing = await readExistingPersistedKey(idbTimeoutMs)
  const prevRec =
    existing.status === 'found' ? existing.record : memoryCachedKey

  try {
    const candidate = await generateCandidateKeyRecord(subtle)
    const committed = await loadOrCreatePersistedKey(candidate, true, idbTimeoutMs)
    if (!committed) {
      return undefined
    }
    memoryCachedKey = committed
    const newProof = await signTranscript(subtle, committed, buildRebindKeyTranscript(params))
    if (!newProof) {
      return undefined
    }
    let prevProof: DeviceKeyProof | undefined
    if (prevRec && prevRec.pubKeyHex !== committed.pubKeyHex) {
      prevProof = await signTranscript(
        subtle,
        prevRec,
        buildPreviousKeyRotationTranscript({
          nonce: params.nonce,
          subjectId: params.subjectId,
          beaconId: params.beaconId,
        })
      )
    }
    return {
      device_key: newProof,
      ...(prevProof ? { previous_device_key: prevProof } : {}),
    }
  } catch {
    return undefined
  }
}

export async function signChallengeWithDeviceKey(
  params: {
    nonce: string
    beaconId: string
    staticWebGLFpHash: string
    audioCompressorHash: string
  },
  timeoutMs?: number
): Promise<DeviceKeyProof | undefined> {
  const subtle = getSubtleCrypto()
  if (!subtle) {
    return undefined
  }
  const rec = await getOrCreateDeviceKeyRecord({ timeoutMs })
  if (!rec) {
    return undefined
  }
  return signTranscript(subtle, rec, buildDeviceKeyTranscript(params))
}
