import { buildEddsa } from "circomlibjs";
import { poseidonHash } from "./poseidonTree";

let _eddsa: any;

/** Initialize the shared EdDSA-BabyJubjub instance. */
export async function initEddsa(): Promise<void> {
  if (!_eddsa) _eddsa = await buildEddsa();
}

export interface IssuerKeys {
  sk: Uint8Array;
  /** BabyJubjub public key (Ax, Ay) as field elements. Published on chain via
   *  `CredentialDefinitionRegistry.setIssuerZkPubKey(ax, ay)`. */
  Ax: bigint;
  Ay: bigint;
}

/** Derive an issuer key from a 32-byte secret. */
export function issuerFromSecret(sk: Uint8Array): IssuerKeys {
  if (!_eddsa) throw new Error("call initEddsa() first");
  const pub = _eddsa.prv2pub(sk);
  return { sk, Ax: _eddsa.F.toObject(pub[0]), Ay: _eddsa.F.toObject(pub[1]) };
}

export interface IssuedCredential {
  credId: bigint;
  attributes: bigint[];
  attributesHash: bigint;
  /**
   * Public Poseidon leaf = `Poseidon(LEAF_TAG=1, credDefId, credId, attributesHash)`
   * — the value that goes into the off-chain `PoseidonTree`, that the circuit
   * recomputes from `(credDefId, credId, attributes)`, and that the issuer's
   * EdDSA-BabyJubjub signature was computed over.
   */
  leaf: bigint;
  sigR8x: bigint;
  sigR8y: bigint;
  sigS: bigint;
}

/**
 * Issue a credential: compute the tagged leaf and EdDSA-sign it. The leaf is
 *   `Poseidon(LEAF_TAG=1, credDefId, credId, Poseidon(attributes))`
 * which exactly matches `non_revocation.circom` step 2 and the SDK's
 * `computeZkLeaf` — sigs produced here verify both in the circuit and via
 * `verifyZkSignature`.
 *
 * `credDefId` must be the *felt* form (`uint256(bytes32(credDefId)) mod p`) so
 * the binding aligns with what the on-chain MerkleStateRegistry expects in
 * `publicSignals[1]`.
 */
export function issueCredential(
  issuer: IssuerKeys,
  credDefId: bigint,
  credId: bigint,
  attributes: bigint[]
): IssuedCredential {
  if (!_eddsa) throw new Error("call initEddsa() first");
  const F = _eddsa.F;
  const attributesHash = poseidonHash(attributes);
  // Tag = 1 — `var LEAF_TAG = 1;` in non_revocation.circom. Pure number to
  // keep the dep graph flat (no circular import from ./eddsa). Both sites must
  // stay in sync; that invariant is also checked by the SDK ZkEddsa tests.
  const LEAF_TAG = 1n;
  const leaf = poseidonHash([LEAF_TAG, credDefId, credId, attributesHash]);
  const sig = _eddsa.signPoseidon(issuer.sk, F.e(leaf));
  return {
    credId,
    attributes,
    attributesHash,
    leaf,
    sigR8x: F.toObject(sig.R8[0]),
    sigR8y: F.toObject(sig.R8[1]),
    sigS: BigInt(sig.S),
  };
}
