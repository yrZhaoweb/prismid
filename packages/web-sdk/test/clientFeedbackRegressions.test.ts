import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  createPrismClient,
  MAX_PRISM_WIRE_BYTES,
  measureJsonWireBytes,
} from '../src/index.js'

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
            transaction() {
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

describe('PrismID client feedback regressions (M1/M2/M3/M4)', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('M2: parses yrBridge error envelope reason/Retry-After accurately and never misclassifies generic 409 as REBIND_FORBIDDEN', async () => {
    const mem = createInMemoryIDB()
    vi.stubGlobal('indexedDB', mem.idb)

    let mode: 'rebind_forbidden' | 'other_409' | 'rate_limit_429' = 'rebind_forbidden'
    const mockFetch: typeof fetch = async (input) => {
      const url = String(input)
      if (url.endsWith('/challenge')) {
        return new Response(
          JSON.stringify({
            nonce: 'a'.repeat(64),
            render_seed: [2.1, 3.2, 4.3, 5.4],
          }),
          { status: 200 }
        )
      }
      if (url.endsWith('/rebind-key')) {
        if (mode === 'rebind_forbidden') {
          return new Response(
            JSON.stringify({
              code: 409,
              reason: 'REBIND_FORBIDDEN',
              message: 'beacon is not owned by authenticated subject',
            }),
            { status: 409 }
          )
        }
        return new Response(
          JSON.stringify({
            code: 409,
            reason: 'BEACON_STATE_CONFLICT',
            message: 'other conflict',
          }),
          { status: 409 }
        )
      }
      return new Response(
        JSON.stringify({
          code: 429,
          reason: 'RATE_LIMITED',
          message: 'too many requests',
        }),
        { status: 429, headers: { 'Retry-After': '7' } }
      )
    }

    const client = createPrismClient({
      baseUrl: 'https://api.example.test',
      getAccessToken: () => 'jwt.token',
      getSubjectId: () => '1001',
      fetchImpl: mockFetch,
    })

    // 1. yrBridge 409 REBIND_FORBIDDEN
    mode = 'rebind_forbidden'
    const resForbidden = await client.rebindKey({
      beaconId: '1'.repeat(32),
      stepUpToken: 'step',
    })
    expect(resForbidden.accepted).toBe(false)
    expect(resForbidden.http_status).toBe(409)
    expect(resForbidden.code).toBe('REBIND_FORBIDDEN')

    // 2. yrBridge 409 with another reason
    mode = 'other_409'
    const resOther409 = await client.rebindKey({
      beaconId: '1'.repeat(32),
      stepUpToken: 'step',
    })
    expect(resOther409.accepted).toBe(false)
    expect(resOther409.http_status).toBe(409)
    expect(resOther409.code).toBe('BEACON_STATE_CONFLICT')

    // 3. yrBridge 429 with Retry-After on identifyDetailed
    const detailed = await client.identifyDetailed({ force: true })
    expect(detailed.result).toBeNull()
    expect(detailed.error?.kind).toBe('http')
    expect(detailed.error?.status).toBe(429)
    expect(detailed.error?.code).toBe('RATE_LIMITED')
    expect(detailed.error?.retryAfterMs).toBe(7000)
  })

  it('M1/M3: AbortSignal immediately stops identifyDetailed and rebindKey without committing rotation', async () => {
    const mem = createInMemoryIDB()
    vi.stubGlobal('indexedDB', mem.idb)

    let rebindCalls = 0
    const controller = new AbortController()
    const client = createPrismClient({
      baseUrl: 'https://api.example.test',
      getAccessToken: () => 'jwt.token',
      getSubjectId: () => '1001',
      fetchImpl: async (input) => {
        const url = String(input)
        if (url.endsWith('/challenge')) {
          return new Promise<Response>(() => {
            // simulate slow IPC / HTTP response that never finishes before account switch
          })
        }
        rebindCalls++
        return new Response(JSON.stringify({ accepted: true, rebound: true }), { status: 200 })
      },
    })

    const identifyPromise = client.identifyDetailed({ force: true, signal: controller.signal })
    const rebindPromise = client.rebindKey({
      beaconId: '2'.repeat(32),
      stepUpToken: 'step',
      rotate: true,
      signal: controller.signal,
    })

    setTimeout(() => controller.abort(), 15)

    const [idRes, rbRes] = await Promise.all([identifyPromise, rebindPromise])
    expect(idRes.result).toBeNull()
    expect(idRes.error?.kind).toBe('aborted')
    expect(idRes.error?.code).toBe('ABORTED')
    expect(rbRes.accepted).toBe(false)
    expect(rbRes.code).toBe('ABORTED')
    expect(rebindCalls).toBe(0)
  })

  it('M4: enforces 65536-byte JSON wire limit locally before issuing network fetch', async () => {
    const mem = createInMemoryIDB()
    vi.stubGlobal('indexedDB', mem.idb)

    let networkCalled = false
    const client = createPrismClient({
      baseUrl: 'https://api.example.test',
      getAccessToken: () => 'jwt.token',
      getSubjectId: () => '1001',
      fetchImpl: async (input) => {
        const url = String(input)
        if (url.endsWith('/challenge')) {
          return new Response(
            JSON.stringify({
              nonce: 'b'.repeat(64),
              render_seed: [2.1, 3.2, 4.3, 5.4],
            }),
            { status: 200 }
          )
        }
        networkCalled = true
        return new Response(JSON.stringify({ accepted: true }), { status: 200 })
      },
    })

    expect(MAX_PRISM_WIRE_BYTES).toBe(65_536)
    const oversizedStepUp = 'x'.repeat(65_600)
    expect(measureJsonWireBytes({ step_up_token: oversizedStepUp })).toBeGreaterThan(
      MAX_PRISM_WIRE_BYTES
    )

    const res = await client.rebindKey({
      beaconId: '3'.repeat(32),
      stepUpToken: oversizedStepUp,
    })
    expect(res.accepted).toBe(false)
    expect(res.http_status).toBe(413)
    expect(res.code).toBe('PAYLOAD_TOO_LARGE')
    expect(networkCalled).toBe(false)
  })
})
