import { keccak256, getBytes, concat } from "ethers";

/**
 * Standard sorted-pair keccak256 Merkle tree compatible with OpenZeppelin's
 * MerkleProof.verify on-chain.
 *
 * The tree:
 *  - Sorts leaves canonically before construction
 *  - At each level, pairs leaves; if odd, the last leaf is carried up unchanged
 *  - At each pair, hashes `keccak256(min(a,b) || max(a,b))`
 */
export class StandardMerkleTree {
  readonly leaves: string[];
  readonly layers: string[][];

  constructor(leaves: string[]) {
    if (leaves.length === 0) throw new Error("StandardMerkleTree: empty leaves");
    this.leaves = [...leaves].map((l) => l.toLowerCase()).sort();
    this.layers = [this.leaves.slice()];
    let current = this.layers[0];
    while (current.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(hashPair(current[i], current[i + 1]));
        } else {
          next.push(current[i]);
        }
      }
      this.layers.push(next);
      current = next;
    }
  }

  get root(): string {
    return this.layers[this.layers.length - 1][0];
  }

  proofFor(leaf: string): string[] {
    const normalized = leaf.toLowerCase();
    let idx = this.leaves.indexOf(normalized);
    if (idx === -1) throw new Error("StandardMerkleTree: leaf not found");
    const proof: string[] = [];
    for (let l = 0; l < this.layers.length - 1; l++) {
      const layer = this.layers[l];
      const siblingIdx = idx ^ 1;
      if (siblingIdx < layer.length) {
        proof.push(layer[siblingIdx]);
      }
      idx = Math.floor(idx / 2);
    }
    return proof;
  }
}

function hashPair(a: string, b: string): string {
  const ab = a.toLowerCase();
  const bb = b.toLowerCase();
  const [lo, hi] = ab < bb ? [ab, bb] : [bb, ab];
  return keccak256(concat([getBytes(lo), getBytes(hi)]));
}

/**
 * Derive the public Merkle leaf from a holder's SECRET credId, matching the on-chain
 * `MerkleStateRegistry.deriveLeaf`: double-keccak per the OZ StandardMerkleTree convention.
 * `abi.encode(bytes32)` is the 32 raw bytes, so this reduces to keccak256(keccak256(credId)).
 * The credId is never published; only this derived leaf appears in events / the tree.
 */
export function deriveLeaf(credId: string): string {
  return keccak256(keccak256(credId));
}

/**
 * Compute a Tier-2 leaf placeholder. The real Poseidon hash is computed by the holder
 * inside the SNARK circuit; on-chain we store only the leaf commitment hash for
 * indexer reconstruction. Until the Phase-2 circuit lands, this is keccak(leaf) — a
 * placeholder. Replace with Poseidon when the Halo2 circuit is online.
 */
export function poseidonPlaceholderLeaf(keccakLeaf: string): string {
  return keccak256(keccakLeaf);
}
