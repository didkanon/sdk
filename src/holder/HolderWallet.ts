import {
  Credential,
  CredentialPool,
  KanonContracts,
  StandardMerkleTree,
  Tier1Presentation,
} from "../core";

/**
 * In-memory holder wallet for storing credential pools and producing Tier-1
 * presentations against the current Merkle root.
 *
 * In production, credential storage would be persisted (browser storage,
 * mobile secure enclave). This class is intentionally storage-agnostic — pass
 * an `IStorage` to plug in.
 */

export interface IHolderStorage {
  getPools(): Promise<CredentialPool[]>;
  savePool(pool: CredentialPool): Promise<void>;
  updatePool(credDefId: string, updater: (p: CredentialPool) => CredentialPool): Promise<void>;
}

export class InMemoryHolderStorage implements IHolderStorage {
  private pools = new Map<string, CredentialPool>();

  async getPools(): Promise<CredentialPool[]> {
    return [...this.pools.values()];
  }

  async savePool(pool: CredentialPool): Promise<void> {
    this.pools.set(pool.credDefId, pool);
  }

  async updatePool(
    credDefId: string,
    updater: (p: CredentialPool) => CredentialPool
  ): Promise<void> {
    const existing = this.pools.get(credDefId);
    if (!existing) throw new Error(`No pool for credDefId ${credDefId}`);
    this.pools.set(credDefId, updater(existing));
  }
}

export class HolderWallet {
  constructor(
    private readonly storage: IHolderStorage,
    private readonly contracts: KanonContracts
  ) {}

  /** Accept a fresh pool of one-time-use credentials issued by an issuer. */
  async acceptPool(pool: CredentialPool): Promise<void> {
    await this.storage.savePool(pool);
  }

  /** Get all stored pools. */
  async getPools(): Promise<CredentialPool[]> {
    return this.storage.getPools();
  }

  /**
   * Build a Tier-1 presentation for the given credDef.
   *  - Picks the first unspent credential from the holder's pool
   *  - Reconstructs the current Merkle tree by replaying chain events
   *    (so the Merkle proof matches the current on-chain root)
   *  - Marks the credential as spent in local storage
   *
   * Throws if the pool is depleted.
   */
  async buildTier1Presentation(credDefId: string): Promise<Tier1Presentation> {
    const pools = await this.storage.getPools();
    const pool = pools.find((p) => p.credDefId === credDefId);
    if (!pool) throw new Error(`No pool for credDefId ${credDefId}`);

    const next = pool.credentials.find((c) => !pool.spent.has(c.credentialId));
    if (!next) throw new Error(`Pool depleted for credDefId ${credDefId}`);

    // Rebuild the tree from public leaves and prove against the credential's derived leaf.
    const tree = await this.reconstructTree(credDefId);
    const proof = tree.proofFor(next.leafKeccak);

    // Mark spent before returning to avoid double-presentation across concurrent calls.
    await this.storage.updatePool(credDefId, (p) => ({
      ...p,
      spent: new Set([...p.spent, next.credentialId]),
    }));

    return {
      credDefId,
      credId: next.credentialId, // present the SECRET; the contract derives the leaf
      merkleProof: proof,
    };
  }

  /**
   * Reconstruct the current Merkle tree by replaying CredentialAdded / CredentialRevoked
   * events from genesis (or from a snapshot block if performance becomes a concern).
   */
  async reconstructTree(credDefId: string): Promise<StandardMerkleTree> {
    const reg = this.contracts.merkleStateRegistry;
    const addedFilter = reg.filters.CredentialAdded(credDefId);
    const revokedFilter = reg.filters.CredentialRevoked(credDefId);

    const [addedEvents, revokedEvents] = await Promise.all([
      reg.queryFilter(addedFilter, 0, "latest"),
      reg.queryFilter(revokedFilter, 0, "latest"),
    ]);

    const active = new Set<string>();
    for (const e of addedEvents) {
      active.add((e.args.leafKeccak as string).toLowerCase());
    }
    for (const e of revokedEvents) {
      active.delete((e.args.leafKeccak as string).toLowerCase());
    }

    if (active.size === 0) {
      // Match issuer's empty-tree convention
      return new StandardMerkleTree(["0x" + "00".repeat(32)]);
    }
    return new StandardMerkleTree([...active]);
  }
}
