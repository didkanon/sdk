import { Signer, keccak256, hexlify, getBytes, concat } from "ethers";
import {
  Credential,
  CredentialPool,
  KanonContracts,
  StandardMerkleTree,
  deriveLeaf,
  poseidonPlaceholderLeaf,
} from "../core";
import {
  IssuerKeyPair,
  generateCredentialId,
  hashAttributesPlaceholder,
  signCredential,
} from "./keys";

/**
 * IssuerService — high-level driver for issuer operations on a single credDef.
 *
 * Responsibilities:
 *  - Issue Tier-1 one-time-use credential pools to holders
 *  - Maintain the on-chain Merkle state (initialize, batchUpdate)
 *  - Track issued and revoked leaves locally so the next batch produces a correct new root
 */
export interface IssuerSyncCheckpoint {
  /** Last fully-replayed block. Next reconstruct call resumes from `lastSyncedBlock + 1`. */
  lastSyncedBlock: number;
  /**
   * Active leaves as parallel arrays. `keccak[i]` and `poseidon[i]` describe the
   * same credential. Persist this as-is to recover state without re-scanning
   * the chain from genesis.
   */
  active: { keccak: string[]; poseidon: string[] };
}

export class IssuerService {
  // keccak leaves currently in the active set; tree.root is built from these
  private leaves = new Set<string>();
  // keccak → poseidon companion, populated either at issuance time or by
  // reconstructFromChain. Used by `revoke()` to feed `batchUpdate`'s
  // `revokedLeavesPoseidon` argument without recomputing poseidon (which
  // would require attribute material the SDK no longer has on hand).
  private poseidonByKeccak = new Map<string, string>();
  // Highest block whose events have been folded into local state. Persist
  // alongside `leaves` to enable incremental rescans across restart.
  private lastSyncedBlock = 0;

  constructor(
    private readonly contracts: KanonContracts,
    private readonly signer: Signer,
    private readonly credDefId: string,
    private readonly issuerKeys: IssuerKeyPair
  ) {}

  /** Initialize the credDef's Merkle state on-chain (one-time setup). */
  async initialize(initialPoseidonRoot: string = "0x" + "00".repeat(32)): Promise<void> {
    const tx = await this.contracts.merkleStateRegistry
      .connect(this.signer)
      .initializeCredDefState(this.credDefId, "0x" + "00".repeat(32), initialPoseidonRoot);
    await tx.wait();
  }

  /**
   * Issue a pool of `count` one-time-use credentials to a holder.
   * Returns the pool (containing every credential + the signatures) for delivery
   * to the holder, and updates the on-chain Merkle root.
   */
  async issueOneTimePool(
    holderAddress: string,
    attributes: Record<string, string>,
    count: number,
    refreshAfterMs: number = 30 * 24 * 60 * 60 * 1000 // 30 days
  ): Promise<CredentialPool> {
    if (count <= 0) throw new Error("count must be > 0");
    const credentials: Credential[] = [];
    const newLeaves: string[] = [];

    const attributesHash = hashAttributesPlaceholder(attributes);
    const attributesHashHex = hexlify(attributesHash);

    for (let i = 0; i < count; i++) {
      const credentialId = generateCredentialId();
      const signingMessage = keccak256(concat([getBytes(credentialId), attributesHash]));
      const signature = signCredential(this.issuerKeys, getBytes(signingMessage));

      const leafKeccak = deriveLeaf(credentialId);
      const leafPoseidon = poseidonPlaceholderLeaf(leafKeccak);

      credentials.push({
        credDefId: this.credDefId,
        credentialId,
        holderAddress,
        attributes,
        attributesHash: attributesHashHex,
        issuerSignature: hexlify(signature),
        issuedAt: Math.floor(Date.now() / 1000),
        leafKeccak,
        leafPoseidon,
      });
      newLeaves.push(leafKeccak);
    }

    // Add to our local active set, rebuild tree, push update on-chain.
    const poseidonLeaves = newLeaves.map((l) => poseidonPlaceholderLeaf(l));
    for (let i = 0; i < newLeaves.length; i++) {
      this.leaves.add(newLeaves[i]!);
      this.poseidonByKeccak.set(newLeaves[i]!, poseidonLeaves[i]!);
    }
    const tree = this.buildTree();

    const tx = await this.contracts.merkleStateRegistry
      .connect(this.signer)
      .batchUpdate(
        this.credDefId,
        newLeaves,
        poseidonLeaves,
        [],
        [],
        tree.root,
        poseidonPlaceholderLeaf(tree.root)
      );
    await tx.wait();

    return {
      credDefId: this.credDefId,
      holderAddress,
      credentials,
      spent: new Set(),
      refreshAfter: Math.floor((Date.now() + refreshAfterMs) / 1000),
    };
  }

  /**
   * Revoke credentials by their **keccak leaves** (legacy entry point — prefer
   * `revokeByCredId` when you have the credIds since `revoke` requires you to
   * have already derived the leaves yourself).
   *
   * Uses the local `poseidonByKeccak` map to look up each revoked leaf's
   * poseidon companion (populated by `issueOneTimePool` at issuance time, or
   * by `reconstructFromChain` after restart). Falls back to the placeholder
   * mapping only if the companion is missing — which is a recoverable error,
   * since a missed companion means the leaf was never issued by this service
   * instance and the chain will reject the revoke anyway.
   */
  async revoke(leavesToRevoke: string[]): Promise<void> {
    if (leavesToRevoke.length === 0) return;
    const poseidonRevoked: string[] = [];
    for (const l of leavesToRevoke) {
      if (!this.leaves.has(l)) throw new Error(`Leaf ${l} not in active set`);
      poseidonRevoked.push(this.poseidonByKeccak.get(l) ?? poseidonPlaceholderLeaf(l));
    }
    for (const l of leavesToRevoke) {
      this.leaves.delete(l);
      this.poseidonByKeccak.delete(l);
    }

    const tree = this.buildTreeOrEmpty();

    const tx = await this.contracts.merkleStateRegistry
      .connect(this.signer)
      .batchUpdate(
        this.credDefId,
        [],
        [],
        leavesToRevoke,
        poseidonRevoked,
        tree.root,
        poseidonPlaceholderLeaf(tree.root)
      );
    await tx.wait();
  }

  /**
   * Revoke credentials by `credentialId` (the secret the holder presents) —
   * derives the keccak leaf via `deriveLeaf(credId)` and looks the poseidon
   * companion up from local state. The caller does not have to know either
   * leaf form, just the credId. This is the recommended entry point for
   * plugins.
   */
  async revokeByCredId(credIds: string[]): Promise<void> {
    if (credIds.length === 0) return;
    const leavesToRevoke = credIds.map((id) => deriveLeaf(id));
    return this.revoke(leavesToRevoke);
  }

  /**
   * Replay `CredentialAdded` / `CredentialRevoked` events from the
   * MerkleStateRegistry to rebuild the active leaf set. Both leaf forms
   * (keccak + poseidon) are emitted in each event, so the active set is
   * recovered without recomputing anything.
   *
   * Pass `fromBlock` to resume an incremental scan after a checkpoint;
   * otherwise scans from block 0. Returns the last block scanned so the caller
   * can persist it.
   *
   * Idempotent. Safe to call on a partially-hydrated service — events are
   * folded into the existing local state in chain order (block, logIndex).
   */
  async reconstructFromChain(fromBlock?: number): Promise<number> {
    const reg = this.contracts.merkleStateRegistry;
    const start = fromBlock ?? this.lastSyncedBlock;
    const latest = await this.signer.provider!.getBlockNumber();

    const addedFilter = reg.filters.CredentialAdded(this.credDefId);
    const revokedFilter = reg.filters.CredentialRevoked(this.credDefId);

    const [addedEvents, revokedEvents] = await Promise.all([
      reg.queryFilter(addedFilter, start, latest),
      reg.queryFilter(revokedFilter, start, latest),
    ]);

    type LeafEvent = {
      block: number;
      logIndex: number;
      kind: 'add' | 'revoke';
      keccak: string;
      poseidon: string;
    };
    const events: LeafEvent[] = [];
    for (const e of addedEvents) {
      events.push({
        block: e.blockNumber,
        logIndex: e.index,
        kind: 'add',
        keccak: (e.args.leafKeccak as string).toLowerCase(),
        poseidon: (e.args.leafPoseidon as string).toLowerCase(),
      });
    }
    for (const e of revokedEvents) {
      events.push({
        block: e.blockNumber,
        logIndex: e.index,
        kind: 'revoke',
        keccak: (e.args.leafKeccak as string).toLowerCase(),
        poseidon: (e.args.leafPoseidon as string).toLowerCase(),
      });
    }
    events.sort((a, b) =>
      a.block === b.block ? a.logIndex - b.logIndex : a.block - b.block
    );

    for (const ev of events) {
      if (ev.kind === 'add') {
        this.leaves.add(ev.keccak);
        this.poseidonByKeccak.set(ev.keccak, ev.poseidon);
      } else {
        this.leaves.delete(ev.keccak);
        this.poseidonByKeccak.delete(ev.keccak);
      }
    }

    this.lastSyncedBlock = latest;
    return latest;
  }

  /** Snapshot the active set + sync watermark for cold-start recovery. */
  getCheckpoint(): IssuerSyncCheckpoint {
    const keccak: string[] = [];
    const poseidon: string[] = [];
    for (const k of this.leaves) {
      keccak.push(k);
      poseidon.push(this.poseidonByKeccak.get(k) ?? poseidonPlaceholderLeaf(k));
    }
    return { lastSyncedBlock: this.lastSyncedBlock, active: { keccak, poseidon } };
  }

  /** Restore a previously-persisted checkpoint. Overwrites local state. */
  loadCheckpoint(cp: IssuerSyncCheckpoint): void {
    this.leaves = new Set(cp.active.keccak);
    this.poseidonByKeccak = new Map();
    for (let i = 0; i < cp.active.keccak.length; i++) {
      this.poseidonByKeccak.set(cp.active.keccak[i]!, cp.active.poseidon[i]!);
    }
    this.lastSyncedBlock = cp.lastSyncedBlock;
  }

  /** Return the current Merkle tree built from local state, or null if empty. */
  getCurrentTree(): StandardMerkleTree | null {
    if (this.leaves.size === 0) return null;
    return this.buildTree();
  }

  /** Public Merkle root being managed off-chain. */
  getCurrentRoot(): string {
    return this.buildTreeOrEmpty().root;
  }

  /**
   * Hydrate the active leaf set from an off-chain snapshot. The keccak
   * companions repopulate the poseidon map with placeholder values — callers
   * who need exact poseidon parity should use `loadCheckpoint(cp)` or
   * `reconstructFromChain()` instead.
   */
  hydrate(activeLeaves: string[]): void {
    this.leaves = new Set(activeLeaves);
    this.poseidonByKeccak = new Map(
      activeLeaves.map((k) => [k, poseidonPlaceholderLeaf(k)])
    );
  }

  private buildTree(): StandardMerkleTree {
    return new StandardMerkleTree([...this.leaves]);
  }

  /** Returns the tree, falling back to a single-leaf zero-tree if empty so root is deterministic. */
  private buildTreeOrEmpty(): StandardMerkleTree {
    if (this.leaves.size === 0) {
      return new StandardMerkleTree(["0x" + "00".repeat(32)]);
    }
    return this.buildTree();
  }
}
