import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const params = {
  nonce: 'review-nonce',
  beaconId: '1234567890abcdef1234567890abcdef',
  staticWebGLFpHash: 'gpu',
  audioCompressorHash: 'audio',
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
})
