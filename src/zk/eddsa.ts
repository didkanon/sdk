/**
 * BabyJubjub EdDSA primitives for Mode B (Groth16 non-revocation).
 *
 * The `non_revocation.circom` circuit verifies a tagged
 *   `Poseidon(LEAF_TAG=1, credDefId, credId, attrHash)`
 * leaf signed by the issuer's BabyJubjub key — so the SDK must produce
 * signatures the circuit accepts bit-for-bit. This module wraps `circomlibjs`
 * (lazy-loaded so callers who don't need Mode B don't pay the cost).
 *
 * Format:
 *   - Private key:   32 random bytes (the secret scalar in big-endian)
 *   - Public key:    BabyJubjub point (Ax, Ay) over the BN254 scalar field
 *   - Signature:     EdDSA over Poseidon(2) — `R8 = (R8x, R8y)`, `S`
 *   - Field element: a `bigint` in [0, p) where p is the BN254 scalar field
 *
 * Persistence: the wire form is `KanonZkSig` (a flat hex tuple). It packs
 * `(R8x, R8y, S)` so it fits in a single AnonCreds attribute value. Issuers
 * also persist `(privateKey, Ax, Ay)` per cred-def in their agent's secure
 * storage; the persisted record shape is `KanonZkIssuerKey`.
 */

// `bigint` is the universal field-element type because circomlibjs's
// `babyJub.F.toString(...)` / `.e(...)` round-trip through it cleanly without
// either side caring about the underlying buffer representation.
export type Felt = bigint

export interface KanonZkIssuerKey {
  /** 32-byte BabyJubjub private key, hex-encoded with 0x prefix. */
  privateKeyHex: string
  /** Public key A = sk · G, point on BabyJubjub. */
  publicKey: { Ax: Felt; Ay: Felt }
}

export interface KanonZkSignature {
  /** `R8 = r·G` — the nonce commitment. */
  R8x: Felt
  R8y: Felt
  /** `S = r + H(R8, A, M) · sk` mod L — the response scalar. */
  S: Felt
}

/**
 * Generate a fresh BabyJubjub keypair suitable for signing Mode B leaves.
 * `globalThis.crypto.getRandomValues` is the entropy source; Node ≥ 19 and
 * every modern browser / React Native runtime expose it.
 */
export async function generateZkIssuerKey(): Promise<KanonZkIssuerKey> {
  const cl = await loadCircomlibjs()
  const sk = randomScalarBytes()
  const pub = cl.eddsa.prv2pub(sk)
  return {
    privateKeyHex: '0x' + bufferToHex(sk),
    publicKey: {
      Ax: feltFromBuffer(cl.babyJub.F, pub[0]),
      Ay: feltFromBuffer(cl.babyJub.F, pub[1]),
    },
  }
}

/** Restore a keypair from a persisted private key hex. */
export async function restoreZkIssuerKey(privateKeyHex: string): Promise<KanonZkIssuerKey> {
  const cl = await loadCircomlibjs()
  const sk = hexToBuffer(privateKeyHex)
  if (sk.length !== 32) {
    throw new Error('kanon-zk: private key must be 32 bytes')
  }
  const pub = cl.eddsa.prv2pub(sk)
  return {
    privateKeyHex,
    publicKey: {
      Ax: feltFromBuffer(cl.babyJub.F, pub[0]),
      Ay: feltFromBuffer(cl.babyJub.F, pub[1]),
    },
  }
}

/**
 * `LEAF_TAG = 1` — domain separation constant that MUST match
 * `non_revocation.circom` (`var LEAF_TAG = 1;`). Tags prevent any internal
 * Merkle node value from being structurally interpretable as a leaf.
 */
export const KANON_ZK_LEAF_TAG: Felt = 1n

/**
 * Compute
 *   `leaf = Poseidon(LEAF_TAG, credDefId, credId, Poseidon(attributes))`
 * — the field element the circuit and the issuer agree to sign. Matches
 * `non_revocation.circom` step 2 of `NonRevocation`.
 *
 * Binding `credDefId` into the leaf means an issuer's BabyJubjub signature
 * over one credDef's leaf can never be replayed under a different credDef
 * even if the issuer reuses the same key.
 *
 * Inputs are field elements (BN254 scalar field, < 2^254). Callers
 * holding raw byte-strings (e.g. AnonCreds credDef URIs) must first encode
 * to a felt via the protocol's canonical hash — see the schema helpers in
 * `@ajna-inc/kanon-sdk/anoncreds`.
 *
 * The `attributes` array length must match the compiled circuit
 * (16 in the current build).
 */
export async function computeZkLeaf(
  credDefId: Felt,
  credId: Felt,
  attributes: Felt[]
): Promise<Felt> {
  const cl = await loadCircomlibjs()
  const F = cl.babyJub.F
  const attrHash = cl.poseidon(attributes.map((a) => F.e(a)))
  const leaf = cl.poseidon([
    F.e(KANON_ZK_LEAF_TAG),
    F.e(credDefId),
    F.e(credId),
    attrHash,
  ])
  return feltFromBuffer(F, leaf)
}

/**
 * Sign a Mode B leaf with the issuer's BabyJubjub key. The signature is what
 * the holder later passes as `(sigR8x, sigR8y, sigS)` private inputs to the
 * circuit; the `non_revocation.circom` `EdDSAPoseidonVerifier()` constraint
 * is what validates it.
 */
export async function signZkLeaf(
  privateKeyHex: string,
  leaf: Felt
): Promise<KanonZkSignature> {
  const cl = await loadCircomlibjs()
  const F = cl.babyJub.F
  const sk = hexToBuffer(privateKeyHex)
  const sig = cl.eddsa.signPoseidon(sk, F.e(leaf))
  return {
    R8x: feltFromBuffer(F, sig.R8[0]),
    R8y: feltFromBuffer(F, sig.R8[1]),
    S: BigInt(sig.S),
  }
}

/** Verify a Mode B signature — mirrors the circuit's EdDSAPoseidon check. */
export async function verifyZkSignature(
  publicKey: { Ax: Felt; Ay: Felt },
  leaf: Felt,
  signature: KanonZkSignature
): Promise<boolean> {
  const cl = await loadCircomlibjs()
  const F = cl.babyJub.F
  return cl.eddsa.verifyPoseidon(
    F.e(leaf),
    {
      R8: [F.e(signature.R8x), F.e(signature.R8y)],
      S: signature.S,
    },
    [F.e(publicKey.Ax), F.e(publicKey.Ay)]
  )
}

/**
 * Encode a signature as a single base64 string for transport as an AnonCreds
 * attribute value. The CL signature on the credential will then cover this
 * encoded form — exactly the integrity property kanon needs.
 */
export function encodeZkSignature(sig: KanonZkSignature): string {
  return base64FromFelts([sig.R8x, sig.R8y, sig.S])
}

/** Inverse of `encodeZkSignature` — used at presentation time by the holder. */
export function decodeZkSignature(value: string): KanonZkSignature {
  const felts = feltsFromBase64(value, 3)
  return { R8x: felts[0]!, R8y: felts[1]!, S: felts[2]! }
}

// ─── lazy circomlibjs loader ──────────────────────────────────────────────

interface CircomlibSurface {
  babyJub: { F: { e: (x: bigint | number | string) => unknown; toString: (x: unknown) => string } }
  poseidon: (inputs: unknown[]) => unknown
  eddsa: {
    prv2pub: (sk: Uint8Array) => [unknown, unknown]
    signPoseidon: (sk: Uint8Array, msg: unknown) => { R8: [unknown, unknown]; S: bigint | string }
    verifyPoseidon: (msg: unknown, sig: { R8: [unknown, unknown]; S: bigint | string }, pub: [unknown, unknown]) => boolean
  }
}

let _cl: CircomlibSurface | null = null
async function loadCircomlibjs(): Promise<CircomlibSurface> {
  if (_cl !== null) return _cl
  // circomlibjs ships ESM; require() works in Node ≥ 22 + CJS shim builds.
  // The lazy load keeps the import out of the eager SDK boot path, so callers
  // who never touch Mode B don't take the ~300 ms init cost.
  // The runtime exports `buildBabyjub`, `buildPoseidon`, `buildEddsa` but the
  // circomlibjs @types declaration is incomplete. Cast to a structural type
  // we know matches; the helper functions defensively coerce return shapes.
  const mod = (await import('circomlibjs')) as unknown as {
    buildBabyjub: () => Promise<unknown>
    buildPoseidon: () => Promise<(inputs: unknown[]) => unknown>
    buildEddsa: () => Promise<CircomlibSurface['eddsa']>
  }
  const [babyJub, poseidon, eddsa] = await Promise.all([
    mod.buildBabyjub(),
    mod.buildPoseidon(),
    mod.buildEddsa(),
  ])
  _cl = {
    babyJub: babyJub as CircomlibSurface['babyJub'],
    poseidon,
    eddsa,
  }
  return _cl
}

// ─── helpers ──────────────────────────────────────────────────────────────

function randomScalarBytes(): Uint8Array {
  const out = new Uint8Array(32)
  const cryptoObj = (globalThis as { crypto?: { getRandomValues: (b: Uint8Array) => void } }).crypto
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
    throw new Error(
      'kanon-zk: globalThis.crypto.getRandomValues unavailable — use Node ≥ 19, ' +
        'a modern browser, or polyfill globalThis.crypto.'
    )
  }
  cryptoObj.getRandomValues(out)
  return out
}

function bufferToHex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

function hexToBuffer(hex: string): Uint8Array {
  const s = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  if (s.length % 2 !== 0) throw new Error('hex string must have even length')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function feltFromBuffer(F: CircomlibSurface['babyJub']['F'], v: unknown): bigint {
  // circomlibjs returns Uint8Array or BigInt-ish; F.toString gives a decimal
  // representation. Round-trip through bigint for a stable type.
  return BigInt(F.toString(v))
}

function base64FromFelts(felts: bigint[]): string {
  // Pack each felt as 32 BE bytes; 3 felts → 96 bytes → ~128 base64 chars.
  const buf = new Uint8Array(felts.length * 32)
  for (let i = 0; i < felts.length; i++) {
    const f = felts[i]!
    let v = f
    for (let j = 31; j >= 0; j--) {
      buf[i * 32 + j] = Number(v & 0xffn)
      v >>= 8n
    }
  }
  // Browser-safe base64: btoa-like via Buffer where available.
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buf).toString('base64')
  }
  let s = ''
  for (const x of buf) s += String.fromCharCode(x)
  return btoa(s)
}

function feltsFromBase64(value: string, count: number): bigint[] {
  const buf =
    typeof Buffer !== 'undefined'
      ? new Uint8Array(Buffer.from(value, 'base64'))
      : (() => {
          const bin = atob(value)
          const arr = new Uint8Array(bin.length)
          for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i)
          return arr
        })()
  if (buf.length !== count * 32) {
    throw new Error(
      `kanon-zk: expected ${count * 32} bytes (${count} felts) but got ${buf.length}`
    )
  }
  const out: bigint[] = []
  for (let i = 0; i < count; i++) {
    let v = 0n
    for (let j = 0; j < 32; j++) v = (v << 8n) | BigInt(buf[i * 32 + j]!)
    out.push(v)
  }
  return out
}
