/**
 * PrismID 5-Silo Self-Healing Cryptographic Beacon (`storageBeacon.ts`)
 *
 * Persists a 128-bit (32 hex chars) device installation beacon across 5 browser storage silos:
 *   1. `localStorage`
 *   2. `sessionStorage`
 *   3. `IndexedDB` (`prismid_vault_v1` -> `beacons`)
 *   4. `CacheStorage` (`prismid-beacon-cache-v1` -> `https://prismid.invalid/__beacon_v1`)
 *   5. `document.cookie` (`_prismid_bcn_v1`)
 *
 * All asynchronous reads and writes enforce strict per-operation and overall deadlines
 * so blocked/corrupted browser storage engines can never hang `identify()`.
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
      req.onblocked = () => {
        clearTimeout(timer)
        finish({ available: false, value: null })
      }
      req.onupgradeneeded = () => {
        try {
          const db = req.result
          if (!db.objectStoreNames.contains(IDB_STORE)) {
            db.createObjectStore(IDB_STORE)
          }
        } catch {
          // ignore
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
            try {
              db.close()
            } catch {}
            finish({ available: true, value: isValidBeaconId(val) ? val.trim() : null })
          }
          getReq.onerror = () => {
            clearTimeout(timer)
            try {
              db.close()
            } catch {}
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

function writeIndexedDB(id: string, timeoutMs = 150): Promise<void> {
  if (typeof indexedDB === 'undefined') return Promise.resolve()
  return new Promise((resolve) => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      resolve()
    }
    const timer = setTimeout(finish, timeoutMs)

    try {
      const req = indexedDB.open(IDB_NAME, 1)
      req.onblocked = () => {
        clearTimeout(timer)
        finish()
      }
      req.onupgradeneeded = () => {
        try {
          const db = req.result
          if (!db.objectStoreNames.contains(IDB_STORE)) {
            db.createObjectStore(IDB_STORE)
          }
        } catch {
          // ignore
        }
      }
      req.onerror = () => {
        clearTimeout(timer)
        finish()
      }
      req.onsuccess = () => {
        try {
          const db = req.result
          const tx = db.transaction(IDB_STORE, 'readwrite')
          tx.objectStore(IDB_STORE).put(id, STORAGE_KEY)
          tx.oncomplete = () => {
            clearTimeout(timer)
            try {
              db.close()
            } catch {}
            finish()
          }
          tx.onerror = () => {
            clearTimeout(timer)
            try {
              db.close()
            } catch {}
            finish()
          }
          tx.onabort = () => {
            clearTimeout(timer)
            try {
              db.close()
            } catch {}
            finish()
          }
        } catch {
          clearTimeout(timer)
          finish()
        }
      }
    } catch {
      clearTimeout(timer)
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
      resolve(res)
    }
    const timer = setTimeout(() => finish({ available: false, value: null }), timeoutMs)
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.match(CACHE_URL))
      .then((resp) => (resp ? resp.text() : null))
      .then((text) => {
        clearTimeout(timer)
        finish({ available: true, value: isValidBeaconId(text) ? text.trim() : null })
      })
      .catch(() => {
        clearTimeout(timer)
        finish({ available: false, value: null })
      })
  })
}

function writeCacheStorage(id: string, timeoutMs = 150): Promise<void> {
  if (typeof caches === 'undefined' || typeof Response === 'undefined') return Promise.resolve()
  return new Promise((resolve) => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      resolve()
    }
    const timer = setTimeout(finish, timeoutMs)
    caches
      .open(CACHE_NAME)
      .then((cache) =>
        cache.put(
          CACHE_URL,
          new Response(id, {
            headers: {
              'Content-Type': 'text/plain',
              ETag: `"${id}"`,
              'Cache-Control': 'max-age=31536000',
            },
          })
        )
      )
      .then(() => {
        clearTimeout(timer)
        finish()
      })
      .catch(() => {
        clearTimeout(timer)
        finish()
      })
  })
}

export async function collectAndHealStorageBeacon(timeoutMs = 350): Promise<StorageBeaconResult> {
  const fallbackId = generateBeaconId()
  let timer: ReturnType<typeof setTimeout> | undefined

  const work = (async (): Promise<StorageBeaconResult> => {
    const ls = readLocalStorage()
    const ss = readSessionStorage()
    const ck = readCookie()
    const perSiloMs = Math.max(40, Math.floor(timeoutMs * 0.4))
    const [idb, cs] = await Promise.all([readIndexedDB(perSiloMs), readCacheStorage(perSiloMs)])

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

    writeLocalStorage(canonicalId)
    writeSessionStorage(canonicalId)
    writeCookie(canonicalId)
    await Promise.all([
      writeIndexedDB(canonicalId, perSiloMs),
      writeCacheStorage(canonicalId, perSiloMs),
    ])

    return {
      beacon_id: canonicalId,
      storage_healed: storageHealed,
      surviving_silos: survivingSilos,
    }
  })()

  const deadline = new Promise<StorageBeaconResult>((resolve) => {
    timer = setTimeout(() => {
      writeLocalStorage(fallbackId)
      writeSessionStorage(fallbackId)
      writeCookie(fallbackId)
      resolve({
        beacon_id: fallbackId,
        storage_healed: false,
        surviving_silos: [],
      })
    }, timeoutMs)
  })

  try {
    return await Promise.race([work, deadline])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}
