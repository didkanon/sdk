import { keccak256, concat, getBytes } from "ethers";
import { KanonContracts, Tier1Presentation } from "../core";
import { verifyCredentialSignature } from "../issuer/keys";

/**
 * Off-chain verifier for relying parties. The authoritative gate is the on-chain
 * `MerkleStateRegistry.consumeOneTime`; this class is a pre-check only.
 */
export class VerifierService {
  constructor(private readonly contracts: KanonContracts) {}

  /// All three reads are pinned to one block to eliminate TOCTOU between them.
  async verifyTier1Presentation(p: Tier1Presentation): Promise<boolean> {
    const ms = this.contracts.merkleStateRegistry;
    const cd = this.contracts.credDefRegistry;
    const provider = ms.runner?.provider;
    if (!provider) throw new Error("VerifierService: contracts must be connected to a provider");
    const blockTag = await provider.getBlockNumber();
    if (!(await cd.supportsTier(p.credDefId, 1, { blockTag }))) return false;
    if (await ms.isNullifierUsed(p.credDefId, p.credId, { blockTag })) return false;
    return ms.verifyKeccakMembership(p.credDefId, p.credId, p.merkleProof, { blockTag });
  }

  /**
   * Verify a credential's issuer signature off-chain. The signing message is
   * keccak256(credentialId || attributesHash).
   */
  async verifyCredentialIssuance(
    credDefId: string,
    credentialId: string,
    attributesHash: string,
    signature: string
  ): Promise<boolean> {
    const cd = await this.contracts.credDefRegistry.getCredentialDefinition(credDefId);
    const message = keccak256(concat([getBytes(credentialId), getBytes(attributesHash)]));
    return verifyCredentialSignature(
      getBytes(cd.issuerPubKey),
      getBytes(message),
      getBytes(signature)
    );
  }

  /**
   * Confirm an off-chain canonical JSON Schema matches the on-chain `schemaHash`.
   * The verifier computes keccak256 of the JSON bytes (after canonicalization)
   * and compares to the schema's on-chain hash.
   */
  async validateSchemaJson(schemaId: string, canonicalJsonBytes: Uint8Array): Promise<boolean> {
    const schema = await this.contracts.schemaRegistry.getSchema(schemaId);
    const computed = keccak256(canonicalJsonBytes);
    return computed.toLowerCase() === schema.schemaHash.toLowerCase();
  }

  /**
   * Get the current Merkle roots for a credDef (useful for cache invalidation).
   */
  async getCurrentRoots(credDefId: string): Promise<{ keccak: string; poseidon: string; epoch: bigint }> {
    const state = await this.contracts.merkleStateRegistry.getState(credDefId);
    return {
      keccak: state.rootKeccak,
      poseidon: state.rootPoseidon,
      epoch: state.epoch,
    };
  }
}
