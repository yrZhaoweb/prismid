/**
 * PrismID 5-Silo Self-Healing Cryptographic Beacon (`storageBeacon.ts`)
 *
 * Persists a 128-bit (32 hex chars) device installation beacon across 5 browser storage silos:
 *   1. `localStorage`   (bit 0 = 1)
 *   2. `sessionStorage` (bit 1 = 2)
 *   3. `cookie`         (bit 2 = 4)
 *   4. `indexedDB`      (bit 3 = 8)
 *   5. `cacheStorage`   (bit 4 = 16)
 *
 * All asynchronous reads and writes enforce strict per-operation and overall deadlines,
 * abort late background writes after timeout, and never fall back to non-cryptographic PRNGs.
 */

import { csprngBytes } from '../crypto/aead.js'

const STORAGE_KEY = '_prismid_bcn_v1'
const IDB_NAME = 'prismid_vault_v1'
const IDB_STORE = 'beacons'
const CACHE_NAME = 'prismid-beacon-cache-v1'
const CACHE_URL = 'https://prismid.invalid/__beacon_v1'

export const SILO_MASK = {
  localStorage: 1 << 0,
  sessionStorage: 1 << 1,
  cookie: 1 << 2,
  indexedDB: 1 << 3,
  cacheStorage: 1 << 4,
} as const

export interface StorageBeaconResult {
  beacon_id: string
  storage_healed: boolean
  surviving_silos: string[]
  surviving_silos_mask: number
}

function isValidBeaconId(val: unknown): val is string {
  return typeof val === 'string' && /^[0-9a-f]{32}$/.test(val.trim())
}

function generateBeaconId(): string {
  const bytes = csprngBytes(16)
  if (!bytes) {
    // Never fall back to predictable Math.random() when CSPRNG is absent (S3-34).
    return ''
  }
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}

function readLocalStorage(): { available: boolean; value: string | null } {
  try {
    if (typeof localStorage === 'undefined') return { available: false, value: null }
    const v = localStorage.getItem(STORAGE_KEY)
    return { available: true, value: isValidBeaconId(v) ? v.trim() : null }
  } catch {
    return { available: false, value: null }
  }
}

function writeLocalStorage(id: string): void {
  if (!id) return
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, id)
    }
  } catch {
    // ignore
  }
}

function readSessionStorage(): { available: boolean; value: string | null } {
  try {
    if (typeof sessionStorage === 'undefined') return { available: false, value: null }
    const v = sessionStorage.getItem(STORAGE_KEY)
    return { available: true, value: isValidBeaconId(v) ? v.trim() : null }
  } catch {
    return { available: false, value: null }
  }
}

function writeSessionStorage(id: string): void {
  if (!id) return
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(STORAGE_KEY, id)
    }
  } catch {
    // ignore
  }
}

function readCookie(): { available: boolean; value: string | null } {
  try {
    if (typeof document === 'undefined' || typeof document.cookie !== 'string') {
      return { available: false, value: null }
    }
    const parts = document.cookie.split(';')
    for (const part of parts) {
      const eqIdx = part.indexOf('=')
      if (eqIdx < 0) continue
      const k = part.slice(0, eqIdx).trim()
      const v = part.slice(eqIdx + 1).trim()
      if (k === STORAGE_KEY && isValidBeaconId(v)) {
        return { available: true, value: v }
      }
    }
    return { available: true, value: null }
  } catch {
    return { available: false, value: null }
  }
}

function writeCookie(id: string): void {
  if (!id) return
  try {
    if (typeof document !== 'undefined') {
      const isHttps =
        typeof globalThis.location !== 'undefined' && globalThis.location?.protocol === 'https:'
      const secureAttr = isHttps ? '; Secure' : ''
      document.cookie = `${STORAGE_KEY}=${id}; path=/; max-age=34560000; SameSite=Lax${secureAttr}`
    }
  } catch {
    // ignore
  }
}

function readIndexedDB(timeoutMs = 150): Promise<{ available: boolean; value: string | null }> {
  if (typeof indexedDB === 'undefined' || !indexedDB) {
    return Promise.resolve({ available: false, value: null })
  }
  return new Promise((resolve) => {
    let settled = false
    let db: IDBDatabase | undefined
    const finish = (res: { available: boolean; value: string | null }) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        db?.close()
      } catch {}
      resolve(res)
    }
    const timer = setTimeout(() => finish({ available: false, value: null }), timeoutMs)

    try {
      const req = indexedDB.open(IDB_NAME, 1)
      req.onblocked = () => finish({ available: false, value: null })
      req.onupgradeneeded = () => {
        if (settled) {
          try { req.transaction?.abort() } catch {}
          return
        }
        try {
          const upgDb = req.result
          if (!upgDb.objectStoreNames.contains(IDB_STORE)) {
            upgDb.createObjectStore(IDB_STORE)
          }
        } catch {
          // ignore
        }
      }
      req.onerror = () => finish({ available: false, value: null })
      req.onsuccess = () => {
        db = req.result
        if (settled) {
          try { db.close() } catch {}
          return
        }
        try {
          const tx = db.transaction(IDB_STORE, 'readonly')
          const store = tx.objectStore(IDB_STORE)
          const getReq = store.get(STORAGE_KEY)
          getReq.onsuccess = () => {
            const val = getReq.result
            finish({ available: true, value: isValidBeaconId(val) ? val.trim() : null })
          }
          getReq.onerror = () => {
            finish({ available: true, value: null })
          }
        } catch {
          finish({ available: false, value: null })
        }
      }
    } catch {
      finish({ available: false, value: null })
    }
  })
}

function writeIndexedDB(
  id: string,
  timeoutMs = 150,
  isAborted?: () => boolean
): Promise<void> {
  if (!id || typeof indexedDB === 'undefined' || !indexedDB || isAborted?.()) {
    return Promise.resolve()
  }
  return new Promise((resolve) => {
    let settled = false
    let db: IDBDatabase | undefined
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        db?.close()
      } catch {}
      resolve()
    }
    const timer = setTimeout(finish, timeoutMs)

    try {
      const req = indexedDB.open(IDB_NAME, 1)
      req.onblocked = () => finish()
      req.onupgradeneeded = () => {
        if (settled || isAborted?.()) {
          try { req.transaction?.abort() } catch {}
          return
        }
        try {
          const upgDb = req.result
          if (!upgDb.objectStoreNames.contains(IDB_STORE)) {
            upgDb.createObjectStore(IDB_STORE)
          }
        } catch {
          // ignore
        }
      }
      req.onerror = () => finish()
      req.onsuccess = () => {
        db = req.result
        if (settled || isAborted?.()) {
          finish()
          return
        }
        try {
          const tx = db.transaction(IDB_STORE, 'readwrite')
          tx.objectStore(IDB_STORE).put(id, STORAGE_KEY)
          tx.oncomplete = () => finish()
          tx.onerror = () => finish()
          tx.onabort = () => finish()
        } catch {
          finish()
        }
      }
    } catch {
      finish()
    }
  })
}

async function readCacheStorage(timeoutMs = 150): Promise<{ available: boolean; value: string | null }> {
  if (typeof caches === 'undefined' || typeof Response === 'undefined') {
    return { available: false, value: null }
  }
  return new Promise((resolve) => {
    let settled = false
    const finish = (res: { available: boolean; value: string | null }) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(res)
    }
    const timer = setTimeout(() => finish({ available: false, value: null }), timeoutMs)
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.match(CACHE_URL))
      .then((resp) => (resp ? resp.text() : null))
      .then((text) => {
        finish({ available: true, value: isValidBeaconId(text) ? text.trim() : null })
      })
      .catch(() => {
        finish({ available: false, value: null })
      })
  })
}

function writeCacheStorage(
  id: string,
  timeoutMs = 150,
  isAborted?: () => boolean
): Promise<void> {
  if (!id || typeof caches === 'undefined' || typeof Response === 'undefined' || isAborted?.()) {
    return Promise.resolve()
  }
  return new Promise((resolve) => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve()
    }
    const timer = setTimeout(finish, timeoutMs)
    caches
      .open(CACHE_NAME)
      .then((cache) => {
        if (settled || isAborted?.()) return
        return cache.put(
          CACHE_URL,
          new Response(id, {
            headers: {
              'Content-Type': 'text/plain',
              ETag: `"${id}"`,
              'Cache-Control': 'max-age=31536000',
            },
          })
        )
      })
      .then(() => finish())
      .catch(() => finish())
  })
}

function evaluateSilos(
  silos: { name: keyof typeof SILO_MASK; available: boolean; value: string | null }[],
  fallbackId: string
): StorageBeaconResult {
  const survivingSilos: string[] = []
  let survivingMask = 0
  const freq = new Map<string, number>()
  let missingPrimarySilo = false

  for (const s of silos) {
    if (s.value) {
      survivingSilos.push(s.name)
      survivingMask |= SILO_MASK[s.name]
      freq.set(s.value, (freq.get(s.value) || 0) + 1)
    } else if (
      s.available &&
      (s.name === 'localStorage' || s.name === 'cookie' || s.name === 'indexedDB')
    ) {
      missingPrimarySilo = true
    }
  }

  let canonicalId = ''
  let storageHealed = false

  if (freq.size > 0) {
    let bestCount = -1
    for (const [id, count] of freq.entries()) {
      if (count > bestCount) {
        bestCount = count
        canonicalId = id
      }
    }
    if (missingPrimarySilo || freq.size > 1) {
      storageHealed = true
    }
  } else {
    canonicalId = fallbackId
  }

  return {
    beacon_id: canonicalId,
    storage_healed: storageHealed,
    surviving_silos: survivingSilos,
    surviving_silos_mask: survivingMask,
  }
}

export async function collectAndHealStorageBeacon(timeoutMs = 350): Promise<StorageBeaconResult> {
  // Read synchronous silos FIRST so even if async IndexedDB/CacheStorage hang past `timeoutMs`,
  // we preserve the existing synchronous beacon rather than clobbering it with a random ID,
  // and `aborted = true` stops late async tasks from overwriting storage afterwards (S3-35).
  const ls = readLocalStorage()
  const ss = readSessionStorage()
  const ck = readCookie()
  const fallbackId = generateBeaconId()
  const syncSnapshot = evaluateSilos(
    [
      { name: 'localStorage', ...ls },
      { name: 'sessionStorage', ...ss },
      { name: 'cookie', ...ck },
    ],
    fallbackId
  )

  let aborted = false
  let timer: ReturnType<typeof setTimeout> | undefined

  const work = (async (): Promise<StorageBeaconResult> => {
    const perSiloMs = Math.max(40, Math.floor(timeoutMs * 0.4))
    const [idb, cs] = await Promise.all([readIndexedDB(perSiloMs), readCacheStorage(perSiloMs)])
    if (aborted) {
      return syncSnapshot
    }

    const resolved = evaluateSilos(
      [
        { name: 'localStorage', ...ls },
        { name: 'sessionStorage', ...ss },
        { name: 'cookie', ...ck },
        { name: 'indexedDB', ...idb },
        { name: 'cacheStorage', ...cs },
      ],
      fallbackId
    )

    if (resolved.beacon_id && !aborted) {
      writeLocalStorage(resolved.beacon_id)
      writeSessionStorage(resolved.beacon_id)
      writeCookie(resolved.beacon_id)
      await Promise.all([
        writeIndexedDB(resolved.beacon_id, perSiloMs, () => aborted),
        writeCacheStorage(resolved.beacon_id, perSiloMs, () => aborted),
      ])
    }

    return resolved
  })()

  const deadline = new Promise<StorageBeaconResult>((resolve) => {
    timer = setTimeout(() => {
      aborted = true
      if (syncSnapshot.beacon_id) {
        writeLocalStorage(syncSnapshot.beacon_id)
        writeSessionStorage(syncSnapshot.beacon_id)
        writeCookie(syncSnapshot.beacon_id)
      }
      resolve(syncSnapshot)
    }, timeoutMs)
  })

  try {
    return await Promise.race([work, deadline])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}
