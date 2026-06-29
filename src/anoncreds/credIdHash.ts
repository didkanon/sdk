import { keccak256, toUtf8Bytes } from "ethers";

/**
 * Stable, canonical hash of an AnonCreds credential id used as the lookup key in
 * `AnonCredsStatusRegistry`. Both issuer (at issuance time) and verifier (at status
 * lookup time) MUST use this exact function so the bytes32 lines up.
 *
 * The credId is the value placed in the `credId` attribute of an issued AnonCreds
 * credential. Whatever string the issuer chose (typically a UUIDv4) is what we hash.
 *
 * @param credId  The credential identifier string from the AnonCreds credential.
 * @returns       0x-prefixed 32-byte keccak256 digest of the utf-8 encoding.
 */
export function kanonCredIdHash(credId: string): string {
  if (typeof credId !== "string" || credId.length === 0) {
    throw new Error("kanonCredIdHash: credId must be a non-empty string");
  }
  return keccak256(toUtf8Bytes(credId));
}

/**
 * Canonical name of the credential-id attribute that AnonCreds schemas under the
 * Kanon VDR MUST include. The verifier reads the disclosed attribute named exactly
 * this and calls `kanonCredIdHash` on the value before querying the status registry.
 *
 * Keeping this constant in the SDK so issuer, holder and verifier agree.
 */
export const KANON_CRED_ID_ATTRIBUTE = "kanonCredId";
