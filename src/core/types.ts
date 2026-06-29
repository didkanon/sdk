/**
 * Shared SDK types and constants.
 */

export const KANON_DID_METHOD = "did:kanon";
// Must match the compiled circuit `NonRevocation(26, ...)`.
export const DEFAULT_TREE_DEPTH = 26;
export const RECENT_ROOTS_WINDOW = 16;

export enum DIDScope {
  User = 0,
  Org = 1,
}

export enum VerificationMethodType {
  Ed25519VerificationKey2020 = 0,
  EcdsaSecp256k1VerificationKey2019 = 1,
  Bls12381G2Key2020 = 2,
  JsonWebKey2020 = 3,
}

export const TIER_ONE_TIME = 0b01;
export const TIER_ZK_SNARK = 0b10;
export const TIER_ALL = TIER_ONE_TIME | TIER_ZK_SNARK;

export interface KanonDeploymentAddresses {
  OrganizationRegistry: string;
  DIDRegistry: string;
  SchemaRegistry: string;
  CredentialDefinitionRegistry: string;
  MerkleStateRegistry: string;
  Halo2VerifierRegistry: string;
}

export interface KanonDeployment {
  chainId: number;
  network: string;
  deployedAt: string;
  deployer: string;
  rootAdmin: string;
  addresses: KanonDeploymentAddresses;
  implementations?: KanonDeploymentAddresses;
}

export interface Credential {
  credDefId: string;
  // SECRET. Presented to consumeOneTime; never published on-chain.
  credentialId: string;
  holderAddress: string;
  attributes: Record<string, string>;
  attributesHash: string;
  issuerSignature: string;
  issuedAt: number;
  // PUBLIC Tier-1 leaf = deriveLeaf(credentialId); this is what appears in events / the tree.
  leafKeccak: string;
  // Tier 2: Poseidon leaf used inside the SNARK circuit.
  leafPoseidon: string;
}

export interface CredentialPool {
  credDefId: string;
  holderAddress: string;
  credentials: Credential[];
  spent: Set<string>; // credentialIds that have been consumed
  refreshAfter: number; // unix timestamp when pool needs refresh
}

export interface Tier1Presentation {
  credDefId: string;
  credId: string; // the holder's SECRET; the contract derives the leaf
  merkleProof: string[];
}
