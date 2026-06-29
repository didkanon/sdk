/**
 * Mode B attribute conventions over standard AnonCreds.
 *
 * Mode B is designed to fit inside an unmodified AnonCreds presentation: no
 * new DIDComm message types, no new format URIs, no plugin-side protocol
 * tweaks. The trick is two reserved attribute names that ride as regular
 * credential / self-attested attributes:
 *
 *   `kanonZkSig`    — issuer's BabyJubjub EdDSA signature over the credential
 *                     leaf, base64-encoded. Set as a *credential* attribute at
 *                     issuance time so the AnonCreds CL signature covers it,
 *                     preserving the "the CL signature signs over everything"
 *                     property. Holder reveals it during Mode B presentations.
 *
 *   `kanonZkProof`  — holder's Groth16 non-revocation proof + public signals,
 *                     base64-encoded. Set as a *self-attested* attribute on the
 *                     presentation. Verifier extracts it and submits to
 *                     `MerkleStateRegistry.verifyZKMembership` on chain.
 *
 * Keeping the names + encodings here lets issuer, holder and verifier agree
 * without coordinating elsewhere.
 */

import { AbiCoder, keccak256, toUtf8Bytes } from "ethers";

/** Reserved credential attribute carrying the issuer's BabyJubjub signature. */
export const KANON_ZK_SIG_ATTRIBUTE = "kanonZkSig";

/** Reserved self-attested attribute carrying the holder's Groth16 proof. */
export const KANON_ZK_PROOF_ATTRIBUTE = "kanonZkProof";

/** BN254 scalar field prime. Same field the circuit operates over. */
export const BN254_SCALAR_FIELD: bigint =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Canonical felt encoding of an AnonCreds attribute value.
 *
 * AnonCreds attributes are arbitrary strings (or numbers stringified). The
 * circuit needs every attribute as a BN254 felt. Doing a 1:1 mapping is hard
 * — many attribute values exceed 254 bits. So we hash:
 *
 *   `felt = uint256(keccak256(utf8(value))) mod BN254_SCALAR_FIELD`
 *
 * This preserves collision resistance (keccak is the source) at the cost of
 * losing the ability to do range comparisons on attribute values inside the
 * circuit. Range comparisons over numeric attributes are a follow-on; for the
 * current presentation policy ("non-revocation + selective disclosure") this
 * encoding is sufficient. Issuer, holder and verifier MUST use this exact
 * function so the in-circuit attribute hash matches.
 */
export function attrValueToFelt(value: string): bigint {
  // Empty string maps to the keccak of empty input, which is a valid felt.
  // We do not special-case it — only refuse non-string inputs at the boundary.
  if (typeof value !== "string") {
    throw new Error(
      `kanon-zk: attribute value must be a string, got ${typeof value}`
    );
  }
  return BigInt(keccak256(toUtf8Bytes(value))) % BN254_SCALAR_FIELD;
}

/**
 * Convenience: encode an ordered list of attribute names → felts, given a
 * `name → value` map. Used at issuance time by the SDK / plugin to build the
 * 16-element `attributes` array the circuit consumes.
 *
 * Throws if a name is missing — the schema's order MUST be the order used
 * everywhere (circuit input position, in-circuit `disclosedIndex`, etc.).
 */
export function encodeAttributesByName(
  schemaAttrNames: string[],
  values: Record<string, string>
): bigint[] {
  const out: bigint[] = [];
  for (const name of schemaAttrNames) {
    if (!(name in values)) {
      throw new Error(`kanon-zk: missing value for schema attribute '${name}'`);
    }
    out.push(attrValueToFelt(values[name]!));
  }
  return out;
}

/**
 * SDK-reserved attribute names. Excluded from the canonical Mode B leaf
 * encoding so the SNARK doesn't double-bind values the circuit already
 * binds (`kanonCredId` is a separate circuit input, `kanonZkSig` IS the
 * BJJ signature over the leaf — including it as a leaf input would be
 * circular).
 */
export const KANON_ZK_RESERVED_ATTRIBUTE_NAMES: readonly string[] = [
  "kanonCredId",
  KANON_ZK_SIG_ATTRIBUTE,
  KANON_ZK_PROOF_ATTRIBUTE,
];

/**
 * Canonical felt encoding of an attribute map for Mode B.
 *
 * Three sides need to agree on the leaf attributes — the issuance prep
 * step that signs the leaf, the issuance tracker that publishes it, and
 * the holder hook that proves against it. None of those sites have
 * reliable access to the schema's `attrNames` order at runtime (the
 * tracker reads from `record.credentialAttributes` which is an array but
 * the order can shift through anoncreds-rs serialization layers). So we
 * adopt a CANONICAL ORDER all three can reproduce from the attribute map
 * alone: **lexicographic byte sort of the attribute names**, excluding
 * the SDK-reserved names.
 *
 * Properties:
 *   - Schema authors can declare `attrNames` in any order; the leaf
 *     ordering is independent.
 *   - Issuer prep, tracker, and holder produce the same leaf so long as
 *     the value map is the same.
 *   - Adding a new attribute changes the leaf layout (new slot inserted
 *     in alphabetical position). This is unavoidable for any deterministic
 *     ordering and matches AnonCreds' own treatment of attrs as a set.
 */
export function encodeAttributesCanonical(
  values: Record<string, string>,
  excludeNames: ReadonlyArray<string> = KANON_ZK_RESERVED_ATTRIBUTE_NAMES
): bigint[] {
  const exclude = new Set(excludeNames);
  const sortedNames = Object.keys(values)
    .filter((n) => !exclude.has(n))
    .sort();
  return sortedNames.map((name) => attrValueToFelt(values[name]!));
}

/**
 * Wire-form payload for the `kanonZkProof` self-attested attribute. The
 * verifier abi-decodes this to recover the SNARK calldata layout that
 * `Groth16NonRevocationVerifier.verify` expects.
 *
 *   - `proofBytes`     = abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c)
 *   - `publicSignals`  = 7 × 0x-padded bytes32, in circuit order
 *                        [root, credDefId, challenge, Ax, Ay, idx, val]
 *
 * Carrying both lets the verifier call `verifyZKMembership(credDefId,
 * proofBytes, publicSignals)` directly with no extra reshaping.
 */
export interface KanonZkProofWire {
  proofBytes: string;
  publicSignals: string[];
}

/** Base64-encode the wire payload for transit as an AnonCreds attribute value. */
export function encodeKanonZkProofAttr(p: KanonZkProofWire): string {
  if (p.publicSignals.length !== 7) {
    throw new Error(
      `kanon-zk: expected 7 publicSignals, got ${p.publicSignals.length}`
    );
  }
  const blob = AbiCoder.defaultAbiCoder().encode(
    ["bytes", "bytes32[]"],
    [p.proofBytes, p.publicSignals]
  );
  // Hex string → base64 to fit AnonCreds string-valued attributes cleanly.
  const bytes = hexToBytes(blob);
  return typeof Buffer !== "undefined"
    ? Buffer.from(bytes).toString("base64")
    : btoa(String.fromCharCode(...bytes));
}

/** Inverse — used verifier-side to recover the on-chain calldata. */
export function decodeKanonZkProofAttr(value: string): KanonZkProofWire {
  const bytes =
    typeof Buffer !== "undefined"
      ? new Uint8Array(Buffer.from(value, "base64"))
      : Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  const blob = "0x" + bytesToHex(bytes);
  const [proofBytes, publicSignals] = AbiCoder.defaultAbiCoder().decode(
    ["bytes", "bytes32[]"],
    blob
  );
  if (publicSignals.length !== 7) {
    throw new Error(
      `kanon-zk: decoded publicSignals length ${publicSignals.length} (expected 7)`
    );
  }
  return { proofBytes, publicSignals: Array.from(publicSignals) };
}

function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
