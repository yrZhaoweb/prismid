import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const params = {
  nonce: 'review-nonce',
  beaconId: '1234567890abcdef1234567890abcdef',
  staticWebGLFpHash: 'gpu',
  audioCompressorHash: 'audio',
}

function createInMemoryIDB(initialValue: unknown = undefined) {
  let storedValue: unknown = initialValue
  return {
    getStored: () => storedValue,
    setStored: (v: unknown) => {
      storedValue = v
    },
    idb: {
      open() {
        const req: any = {}
        queueMicrotask(() => {
          req.result = {
            objectStoreNames: { contains: () => true },
            close() {},
            transaction(_storeName: string, _mode: string) {
              const tx: any = { abort() {} }
              tx.objectStore = () => ({
                get() {
                  const read: any = { result: storedValue }
                  queueMicrotask(() => read.onsuccess?.())
                  return read
                },
                add(val: unknown) {
                  storedValue = val
                  queueMicrotask(() => tx.oncomplete?.())
                },
                put(val: unknown) {
                  storedValue = val
                  queueMicrotask(() => tx.oncomplete?.())
                },
                delete() {
                  storedValue = undefined
                },
              })
              return tx
            },
          }
          req.onsuccess?.()
        })
        return req
      },
    },
  }
}

describe('persistent device-key lifecycle', () => {
  beforeEach(() => {
    vi.resetModules()
    vi.stubGlobal('crypto', webcrypto)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('does not sign with a temporary key when IndexedDB is unavailable', async () => {
    vi.stubGlobal('indexedDB', undefined)
    const { signChallengeWithDeviceKey } = await import('../src/crypto/deviceKey.js')
    expect(await signChallengeWithDeviceKey(params)).toBeUndefined()
  })

  it('does not sign before the persistence transaction commits, including aborts', async () => {
    vi.stubGlobal('indexedDB', {
      open() {
        const req: any = {}
        queueMicrotask(() => {
          req.result = {
            close() {},
            transaction() {
              const tx: any = { abort() {} }
              tx.objectStore = () => ({
                get() {
                  const read: any = { result: undefined }
                  queueMicrotask(() => read.onsuccess?.())
                  return read
                },
                add() { queueMicrotask(() => tx.onabort?.()) },
              })
              return tx
            },
          }
          req.onsuccess?.()
        })
        return req
      },
    })
    const { signChallengeWithDeviceKey } = await import('../src/crypto/deviceKey.js')
    expect(await signChallengeWithDeviceKey(params)).toBeUndefined()
  })

  it('bounds a blocked IndexedDB initialization and retries later without caching a temporary key', async () => {
    const open = vi.fn(() => ({}))
    vi.stubGlobal('indexedDB', { open })
    const { signChallengeWithDeviceKey } = await import('../src/crypto/deviceKey.js')
    const results = await Promise.all([
      signChallengeWithDeviceKey(params),
      signChallengeWithDeviceKey({ ...params, nonce: 'second-nonce' }),
    ])
    expect(results).toEqual([undefined, undefined])
    expect(open).toHaveBeenCalledTimes(1) // one initialization shared within the page
    expect(await signChallengeWithDeviceKey(params)).toBeUndefined()
    expect(open).toHaveBeenCalledTimes(2)
  })

  it('closes late open callbacks without writing a key after the deadline', async () => {
    const req: any = {}
    vi.stubGlobal('indexedDB', { open: () => req })
    const { signChallengeWithDeviceKey } = await import('../src/crypto/deviceKey.js')
    expect(await signChallengeWithDeviceKey(params)).toBeUndefined()
    const close = vi.fn()
    const transaction = vi.fn()
    req.result = { close, transaction }
    req.onsuccess()
    expect(close).toHaveBeenCalledOnce()
    expect(transaction).not.toHaveBeenCalled()
  })

  it('S2-23: reads existing IndexedDB key BEFORE calling subtle.generateKey (zero wasted keygen on warm loads)', async () => {
    const mem = createInMemoryIDB()
    vi.stubGlobal('indexedDB', mem.idb)

    // Cold load creates and persists key once:
    const mod1 = await import('../src/crypto/deviceKey.js')
    const firstProof = await mod1.signChallengeWithDeviceKey(params)
    expect(firstProof?.pub_key).toMatch(/^04[0-9a-f]{128}$/)

    // Simulate new page reload (fresh module instance, warm IndexedDB):
    vi.resetModules()
    vi.stubGlobal('crypto', webcrypto)
    vi.stubGlobal('indexedDB', mem.idb)
    const genSpy = vi.spyOn(webcrypto.subtle, 'generateKey')

    const mod2 = await import('../src/crypto/deviceKey.js')
    const warmProof = await mod2.signChallengeWithDeviceKey({ ...params, nonce: 'warm-nonce' })
    expect(warmProof?.pub_key).toBe(firstProof?.pub_key)
    expect(genSpy).not.toHaveBeenCalled()
  })

  it('S3-32: repairs corrupted IndexedDB key record in-place instead of permanently failing', async () => {
    const mem = createInMemoryIDB({ corrupted: true, pubKeyHex: 'not-a-valid-key' })
    vi.stubGlobal('indexedDB', mem.idb)

    const { signChallengeWithDeviceKey } = await import('../src/crypto/deviceKey.js')
    const repairedProof = await signChallengeWithDeviceKey(params)
    expect(repairedProof?.pub_key).toMatch(/^04[0-9a-f]{128}$/)
    expect((mem.getStored() as any)?.pubKeyHex).toBe(repairedProof?.pub_key)
  })

  it('S2-24 & S2-12: handles in-session IDB clear without page reload and signs previous-key continuity proof on rotation', async () => {
    const mem = createInMemoryIDB()
    vi.stubGlobal('indexedDB', mem.idb)

    const {
      signChallengeWithDeviceKey,
      signRebindWithDeviceKey,
      rotateDeviceKeyAndSignRebind,
      resetDeviceKeyCache,
    } = await import('../src/crypto/deviceKey.js')

    const initial = await signChallengeWithDeviceKey(params)
    expect(initial?.pub_key).toMatch(/^04[0-9a-f]{128}$/)

    // Proactive key rotation produces both new `device_key` and `previous_device_key` proofs:
    const rotated = await rotateDeviceKeyAndSignRebind({
      nonce: 'rot-nonce-1',
      subjectId: 'alice',
      beaconId: params.beaconId,
    })
    expect(rotated?.device_key.pub_key).toMatch(/^04[0-9a-f]{128}$/)
    expect(rotated?.device_key.pub_key).not.toBe(initial?.pub_key)
    expect(rotated?.previous_device_key?.pub_key).toBe(initial?.pub_key)

    // Simulate user clearing site data (IndexedDB) inside the SAME open tab:
    mem.setStored(undefined)
    // Calling signRebindWithDeviceKey automatically bypasses stale memory cache and persists a fresh key:
    const recovered = await signRebindWithDeviceKey({
      nonce: 'rec-nonce-2',
      subjectId: 'alice',
      beaconId: params.beaconId,
    })
    expect(recovered?.pub_key).toMatch(/^04[0-9a-f]{128}$/)
    expect(recovered?.pub_key).not.toBe(rotated?.device_key.pub_key)

    // Explicit resetDeviceKeyCache() also forces subsequent identify signing to re-read IDB:
    mem.setStored(undefined)
    resetDeviceKeyCache()
    const afterReset = await signChallengeWithDeviceKey({ ...params, nonce: 'post-reset' })
    expect(afterReset?.pub_key).toMatch(/^04[0-9a-f]{128}$/)
    expect(afterReset?.pub_key).not.toBe(recovered?.pub_key)
  })
})
