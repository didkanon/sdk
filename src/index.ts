/**
 * @ajna-inc/kanon-sdk
 *
 * Single-package TypeScript SDK for the kanon SSI protocol.
 *
 * Re-exports:
 *   ./core         — types, deployment loader, contract handles, Merkle tree
 *   ./issuer       — IssuerService + key/signature primitives
 *   ./holder       — HolderWallet + storage interface
 *   ./verifier     — VerifierService for relying parties
 *   ./orchestrator — KanonClient high-level facade
 *   ./zk           — Tier-2 Groth16 prover, Poseidon tree, EdDSA issuer
 *   ./anoncreds    — AnonCreds VDR helpers (canonical credId hashing)
 */
export * as core from "./core";
export * as issuer from "./issuer";
export * as holder from "./holder";
export * as verifier from "./verifier";
export * as orchestrator from "./orchestrator";
export * as zk from "./zk";
export * as anoncreds from "./anoncreds";

// Convenience top-level re-exports
export { KanonClient } from "./orchestrator/KanonClient";
export { IssuerService, type IssuerSyncCheckpoint } from "./issuer/IssuerService";
// Mode B (BabyJubjub EdDSA) primitives — what the non_revocation.circom
// circuit verifies. Plugins consume these to sign leaves at issuance and to
// pack signatures into the AnonCreds `kanonZkSig` attribute.
export {
  type Felt,
  type KanonZkIssuerKey,
  type KanonZkSignature,
  KANON_ZK_LEAF_TAG,
  generateZkIssuerKey,
  restoreZkIssuerKey,
  computeZkLeaf,
  signZkLeaf,
  verifyZkSignature,
  encodeZkSignature,
  decodeZkSignature,
} from "./zk/eddsa";
export { HolderWallet, InMemoryHolderStorage } from "./holder/HolderWallet";
export { VerifierService } from "./verifier/VerifierService";
export {
  loadDeployment,
  connectKanon,
  connectKanonFromAddressBook,
  connectKanonReadonly,
  StandardMerkleTree,
  deriveLeaf,
  TIER_ONE_TIME,
  TIER_ZK_SNARK,
  TIER_ALL,
  DIDScope,
  VerificationMethodType,
} from "./core";
export {
  kanonCredIdHash,
  KANON_CRED_ID_ATTRIBUTE,
  KANON_ZK_SIG_ATTRIBUTE,
  KANON_ZK_PROOF_ATTRIBUTE,
  KANON_ZK_RESERVED_ATTRIBUTE_NAMES,
  BN254_SCALAR_FIELD,
  attrValueToFelt,
  encodeAttributesByName,
  encodeAttributesCanonical,
  encodeKanonZkProofAttr,
  decodeKanonZkProofAttr,
  type KanonZkProofWire,
} from "./anoncreds";
