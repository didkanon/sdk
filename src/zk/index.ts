export * from "./poseidonTree";
export * from "./issuer";
export * from "./prover";
// BabyJubjub EdDSA primitives that the non_revocation.circom circuit verifies.
// Both plugins consume these via `@ajna-inc/kanon-sdk/zk` so the SDK is the
// single source of truth for sig encoding / leaf hashing.
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
} from "./eddsa";
