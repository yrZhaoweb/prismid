/**
 * PrismID 5-Silo Self-Healing Cryptographic Beacon (`storageBeacon.ts`)
 *
 * Persists a 128-bit (32 hex chars) device beacon across 5 independent browser storage silos:
 *   1. `localStorage`
 *   2. `sessionStorage`
 *   3. `IndexedDB` (`prismid_vault` -> `beacons`)
 *   4. `CacheStorage` (`prismid-cache-v1` -> `https://prismid.local/__beacon`)
 *   5. `document.cookie` (`_prismid_bcn`)
 *
 * Accuracy benefits:
 *   - Eliminates False Negatives (FNR) from browser version upgrades (e.g. Chrome 130 -> 131)
 *     and partial storage clearing (when a fraudster clears Cookies or localStorage in F12,
 *     IndexedDB or CacheStorage resurrects the original ID and flags `storage_healed = true`).
 *   - Eliminates False Positives (FPR) across identical hardware models (two innocent users
 *     with the same MacBook Pro M3 model have distinct cryptographic `beacon_id`s).
 */

import { randomBytes } from '../crypto/aead.js'

const STORAGE_KEY = '_prismid_bcn_v1'
const IDB_NAME = 'prismid_vault_v1'
const IDB_STORE = 'beacons'
const CACHE_NAME = 'prismid-beacon-cache-v1'
const CACHE_URL = 'https://prismid.invalid/__beacon_v1'

export interface StorageBeaconResult {
  beacon_id: string
  storage_healed: boolean
  surviving_silos: string[]
}

function isValidBeaconId(val: unknown): val is string {
  return typeof val === 'string' && /^[0-9a-f]{32}$/.test(val.trim())
}

function generateBeaconId(): string {
  const bytes = randomBytes(16)
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
      const [k, v] = part.trim().split('=')
      if (k === STORAGE_KEY && isValidBeaconId(v)) {
        return { available: true, value: v.trim() }
      }
    }
    return { available: true, value: null }
  } catch {
    return { available: false, value: null }
  }
}

function writeCookie(id: string): void {
  try {
    if (typeof document !== 'undefined') {
      document.cookie = `${STORAGE_KEY}=${id}; path=/; max-age=34560000; SameSite=Lax`
    }
  } catch {
    // ignore
  }
}

function readIndexedDB(timeoutMs = 150): Promise<{ available: boolean; value: string | null }> {
  if (typeof indexedDB === 'undefined') {
    return Promise.resolve({ available: false, value: null })
  }
  return new Promise((resolve) => {
    let settled = false
    const finish = (res: { available: boolean; value: string | null }) => {
      if (settled) return
      settled = true
      resolve(res)
    }
    const timer = setTimeout(() => finish({ available: false, value: null }), timeoutMs)

    try {
      const req = indexedDB.open(IDB_NAME, 1)
      req.onupgradeneeded = () => {
        const db = req.result
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          db.createObjectStore(IDB_STORE)
        }
      }
      req.onerror = () => {
        clearTimeout(timer)
        finish({ available: false, value: null })
      }
      req.onsuccess = () => {
        try {
          const db = req.result
          const tx = db.transaction(IDB_STORE, 'readonly')
          const store = tx.objectStore(IDB_STORE)
          const getReq = store.get(STORAGE_KEY)
          getReq.onsuccess = () => {
            clearTimeout(timer)
            const val = getReq.result
            db.close()
            finish({ available: true, value: isValidBeaconId(val) ? val.trim() : null })
          }
          getReq.onerror = () => {
            clearTimeout(timer)
            db.close()
            finish({ available: true, value: null })
          }
        } catch {
          clearTimeout(timer)
          finish({ available: false, value: null })
        }
      }
    } catch {
      clearTimeout(timer)
      finish({ available: false, value: null })
    }
  })
}

function writeIndexedDB(id: string): Promise<void> {
  if (typeof indexedDB === 'undefined') return Promise.resolve()
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(IDB_NAME, 1)
      req.onupgradeneeded = () => {
        const db = req.result
        if (!db.objectStoreNames.contains(IDB_STORE)) {
          db.createObjectStore(IDB_STORE)
        }
      }
      req.onerror = () => resolve()
      req.onsuccess = () => {
        try {
          const db = req.result
          const tx = db.transaction(IDB_STORE, 'readwrite')
          tx.objectStore(IDB_STORE).put(id, STORAGE_KEY)
          tx.oncomplete = () => {
            db.close()
            resolve()
          }
          tx.onerror = () => {
            db.close()
            resolve()
          }
        } catch {
          resolve()
        }
      }
    } catch {
      resolve()
    }
  })
}

async function readCacheStorage(timeoutMs = 150): Promise<{ available: boolean; value: string | null }> {
  if (typeof caches === 'undefined' || typeof Response === 'undefined') {
    return { available: false, value: null }
  }
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ available: false, value: null }), timeoutMs)
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.match(CACHE_URL))
      .then((resp) => (resp ? resp.text() : null))
      .then((text) => {
        clearTimeout(timer)
        resolve({ available: true, value: isValidBeaconId(text) ? text.trim() : null })
      })
      .catch(() => {
        clearTimeout(timer)
        resolve({ available: false, value: null })
      })
  })
}

async function writeCacheStorage(id: string): Promise<void> {
  if (typeof caches === 'undefined' || typeof Response === 'undefined') return
  try {
    const cache = await caches.open(CACHE_NAME)
    await cache.put(
      CACHE_URL,
      new Response(id, {
        headers: {
          'Content-Type': 'text/plain',
          'ETag': `"${id}"`,
          'Cache-Control': 'max-age=31536000',
        },
      })
    )
  } catch {
    // ignore
  }
}

export async function collectAndHealStorageBeacon(): Promise<StorageBeaconResult> {
  const ls = readLocalStorage()
  const ss = readSessionStorage()
  const ck = readCookie()
  const [idb, cs] = await Promise.all([readIndexedDB(), readCacheStorage()])

  const silos: { name: string; available: boolean; value: string | null }[] = [
    { name: 'localStorage', ...ls },
    { name: 'sessionStorage', ...ss },
    { name: 'cookie', ...ck },
    { name: 'indexedDB', ...idb },
    { name: 'cacheStorage', ...cs },
  ]

  const survivingSilos: string[] = []
  const freq = new Map<string, number>()
  let missingPrimarySilo = false

  for (const s of silos) {
    if (s.value) {
      survivingSilos.push(s.name)
      freq.set(s.value, (freq.get(s.value) || 0) + 1)
    } else if (s.available && (s.name === 'localStorage' || s.name === 'cookie' || s.name === 'indexedDB')) {
      missingPrimarySilo = true
    }
  }

  let canonicalId = ''
  let storageHealed = false

  if (freq.size > 0) {
    // Pick the majority / first surviving beacon ID
    let bestCount = -1
    for (const [id, count] of freq.entries()) {
      if (count > bestCount) {
        bestCount = count
        canonicalId = id
      }
    }
    // If at least one silo survived while a primary silo (like localStorage or cookie) was wiped,
    // or if multiple conflicting beacons existed, mark storage_healed = true!
    if (missingPrimarySilo || freq.size > 1) {
      storageHealed = true
    }
  } else {
    canonicalId = generateBeaconId()
  }

  // Heal / synchronize all 5 silos with the canonical beacon ID
  writeLocalStorage(canonicalId)
  writeSessionStorage(canonicalId)
  writeCookie(canonicalId)
  await Promise.all([writeIndexedDB(canonicalId), writeCacheStorage(canonicalId)])

  return {
    beacon_id: canonicalId,
    storage_healed: storageHealed,
    surviving_silos: survivingSilos,
  }
}
