import { bls12_381 } from "@noble/curves/bls12-381.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hexlify, randomBytes } from "ethers";
import { sha256 } from "@noble/hashes/sha2.js";

/**
 * Issuer key generation and signature operations.
 *
 * Using `bls12_381.shortSignatures`:
 *   - Public key: 96 bytes (G2 compressed) — matches what we record on-chain
 *   - Signature: 48 bytes (G1 compressed)
 *   - Message: bytes; the API hashes to G1 internally before signing
 *
 * For Phase 1 the on-chain registry just stores `issuerPubKey` bytes; verification
 * happens off-chain (here) and, in Phase 2, inside the Halo2 SNARK circuit.
 *
 * Backed by @noble/curves v2, multi-audit reviewed.
 */

export interface IssuerKeyPair {
  /** 32-byte private key (secret scalar, big-endian) */
  privateKey: Uint8Array;
  /** 96-byte BLS12-381 G2 compressed public key */
  publicKey: Uint8Array;
}

/** Generate a fresh BLS12-381 G2 issuer key pair. */
export function generateIssuerKeyPair(): IssuerKeyPair {
  const privateKey = bls12_381.utils.randomSecretKey();
  const publicKey = bls12_381.shortSignatures.getPublicKey(privateKey).toBytes(true);
  return { privateKey, publicKey };
}

/**
 * Sign a credential commitment with the issuer's BLS key.
 * The message is `Poseidon(credentialId || attributesHash)` (or a SHA-256 stand-in
 * pre-Phase-2); we hash to G1 before signing.
 */
export function signCredential(issuer: IssuerKeyPair, message: Uint8Array): Uint8Array {
  const hashed = bls12_381.shortSignatures.hash(message);
  return bls12_381.shortSignatures.sign(hashed, issuer.privateKey).toBytes(true);
}

/** Verify a credential signature off-chain. */
export function verifyCredentialSignature(
  pubKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    const hashed = bls12_381.shortSignatures.hash(message);
    const pkPoint = bls12_381.G2.Point.fromBytes(pubKey);
    const sigPoint = bls12_381.G1.Point.fromBytes(signature);
    return bls12_381.shortSignatures.verify(sigPoint, hashed, pkPoint);
  } catch {
    return false;
  }
}

/** Generate a random 32-byte credential ID. Cryptographically secure entropy. */
export function generateCredentialId(): string {
  return hexlify(randomBytes(32));
}

/**
 * Derive a holder binding key (Ed25519) used in the Tier 2 SNARK to prove
 * holder authority. Optional; only required if the credDef supports Tier 2.
 */
export function generateHolderBindingKey(): { secretKey: Uint8Array; publicKey: Uint8Array } {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey, publicKey };
}

/**
 * Compute a Poseidon-placeholder for the attribute hash (Phase 1).
 * In Phase 2 the issuer SDK upgrades this to true Poseidon-over-BLS12-381-Fr.
 */
export function hashAttributesPlaceholder(attributes: Record<string, string>): Uint8Array {
  const canonical = canonicalizeJSON(attributes);
  return sha256(new TextEncoder().encode(canonical));
}

function canonicalizeJSON(obj: unknown): string {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalizeJSON).join(",") + "]";
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  return (
    "{" +
    keys
      .map((k) => `${JSON.stringify(k)}:${canonicalizeJSON((obj as Record<string, unknown>)[k])}`)
      .join(",") +
    "}"
  );
}
