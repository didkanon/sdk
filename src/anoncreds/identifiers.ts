import { keccak256, toUtf8Bytes } from "ethers";

/**
 * did:kanon identifier helpers for the kanon registries. kanon binds the
 * DID to its subject, so there are exactly two shapes (no free-form network
 * segment): `did:kanon:org:0x<64 hex>` and `did:kanon:user:0x<64 hex>`.
 *
 * AnonCreds resource IDs are DID URLs under the issuer DID, e.g.
 * `did:kanon:org:0x<64 hex>/anoncreds/v0/SCHEMA/<name>/<version>`. The on-chain bytes32
 * id is `keccak256(utf8(resourceId))`. These MUST match the Python plugin
 * (`did_kanon`) so the two implementations resolve each other's objects.
 */

const ANONCREDS_PREFIX = "/anoncreds/v0";

export type KanonDidScope = "org" | "user";

export interface ParsedKanonDid {
  did: string;
  scope: KanonDidScope;
  orgId?: string;
  userHex?: string;
  path?: string;
}

export function orgDid(orgId: string): string {
  return `did:kanon:org:${orgId}`;
}

export function userDid(hexHandle: string): string {
  const h = hexHandle.startsWith("0x") ? hexHandle : `0x${hexHandle}`;
  return `did:kanon:user:${h}`;
}

const ORG_RE = /^did:kanon:org:(0x[0-9a-fA-F]{64})(\/[^#?]*)?(?:[#?].*)?$/;
const USER_RE = /^did:kanon:user:(0x[0-9a-fA-F]{64})(\/[^#?]*)?(?:[#?].*)?$/;

export function parseKanonDid(didUrl: string): ParsedKanonDid | null {
  if (!didUrl) return null;
  const org = ORG_RE.exec(didUrl);
  if (org) {
    return { did: orgDid(org[1]), scope: "org", orgId: org[1], path: org[2] };
  }
  const user = USER_RE.exec(didUrl);
  if (user) {
    return { did: userDid(user[1]), scope: "user", userHex: user[1], path: user[2] };
  }
  return null;
}

/** Issuer DID prefix of an AnonCreds resource id, or null. */
export function issuerDidOf(resourceId: string): string | null {
  return parseKanonDid(resourceId)?.did ?? null;
}

export function schemaResourceId(issuerDid: string, name: string, version: string): string {
  return `${issuerDid}${ANONCREDS_PREFIX}/SCHEMA/${name}/${version}`;
}

export function credDefResourceId(issuerDid: string, schemaTag: string, tag: string): string {
  return `${issuerDid}${ANONCREDS_PREFIX}/CLAIM_DEF/${schemaTag}/${tag}`;
}

/** On-chain bytes32 key for an AnonCreds resource id. */
export function resourceIdToBytes32(resourceId: string): string {
  return keccak256(toUtf8Bytes(resourceId));
}
