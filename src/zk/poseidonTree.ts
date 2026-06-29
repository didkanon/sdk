import { buildPoseidon } from "circomlibjs";

/** Tree depth — must match the compiled circuit (`NonRevocation(26, ...)`). */
export const DEPTH = 26;
/** Attribute count — must match the circuit. */
export const N_ATTR = 16;

let _poseidon: any;

/** Initialize the shared Poseidon instance (call once before tree/issuer/prover use). */
export async function initPoseidon(): Promise<void> {
  if (!_poseidon) _poseidon = await buildPoseidon();
}

export function poseidon(): any {
  if (!_poseidon) throw new Error("call initPoseidon() first");
  return _poseidon;
}

/** Poseidon over bigints -> bigint, matching circomlib's Poseidon (and the circuit). */
export function poseidonHash(inputs: bigint[]): bigint {
  const F = _poseidon.F;
  return F.toObject(_poseidon(inputs.map((x) => F.e(x))));
}

/**
 * Domain-separation tag for Merkle internal nodes. MUST stay equal to the
 * `var NODE_TAG = 2;` declared in `non_revocation.circom`'s `MerkleInclusion`
 * template. Tags prevent an internal node value from ever being structurally
 * interpretable as a leaf (`LEAF_TAG = 1` for leaves).
 */
export const NODE_TAG = 2n;

/** `Poseidon(NODE_TAG, left, right)` — the same parent hash the circuit uses. */
function hashNode(left: bigint, right: bigint): bigint {
  return poseidonHash([NODE_TAG, left, right]);
}

/**
 * Sparse fixed-depth binary Merkle tree. Parent = Poseidon(NODE_TAG, left, right)
 * ordered by the path-index bit (0 = node is the left child), identical to the
 * in-circuit MerkleInclusion ordering. Empty leaves are 0; empty subtrees use
 * precomputed zero hashes, so building a depth-26 tree over a handful of
 * credentials is O(leaves × depth), not O(2^depth).
 */
export class PoseidonTree {
  readonly depth: number;
  private readonly zeros: bigint[];
  private readonly nodes: Map<number, bigint>[];

  constructor(depth: number, leaves: bigint[]) {
    this.depth = depth;
    this.zeros = new Array<bigint>(depth + 1);
    this.zeros[0] = 0n;
    for (let d = 1; d <= depth; d++) this.zeros[d] = hashNode(this.zeros[d - 1], this.zeros[d - 1]);
    this.nodes = Array.from({ length: depth + 1 }, () => new Map<number, bigint>());
    for (let i = 0; i < leaves.length; i++) this.insert(i, leaves[i]);
  }

  private nodeAt(level: number, index: number): bigint {
    const v = this.nodes[level].get(index);
    return v !== undefined ? v : this.zeros[level];
  }

  private insert(leafIndex: number, value: bigint): void {
    this.nodes[0].set(leafIndex, value);
    let idx = leafIndex;
    for (let level = 0; level < this.depth; level++) {
      const isRight = idx % 2;
      const left = isRight ? this.nodeAt(level, idx - 1) : this.nodeAt(level, idx);
      const right = isRight ? this.nodeAt(level, idx) : this.nodeAt(level, idx + 1);
      idx = Math.floor(idx / 2);
      this.nodes[level + 1].set(idx, hashNode(left, right));
    }
  }

  get root(): bigint {
    return this.nodeAt(this.depth, 0);
  }

  proof(index: number): { pathElements: bigint[]; pathIndices: number[] } {
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = index;
    for (let d = 0; d < this.depth; d++) {
      const isRight = idx % 2;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      pathElements.push(this.nodeAt(d, siblingIdx));
      pathIndices.push(isRight);
      idx = Math.floor(idx / 2);
    }
    return { pathElements, pathIndices };
  }
}

/** bigint -> 0x-padded bytes32 (for the on-chain Poseidon root / public signals). */
export function toBytes32(v: bigint): string {
  return "0x" + v.toString(16).padStart(64, "0");
}
