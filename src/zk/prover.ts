import * as path from "path";
import { AbiCoder } from "ethers";
import { groth16 } from "snarkjs";
import { PoseidonTree } from "./poseidonTree";
import { IssuerKeys, IssuedCredential } from "./issuer";

const DEFAULT_BUILD = path.resolve(__dirname, "..", "..", "..", "circom", "build");
export const DEFAULT_WASM = path.join(DEFAULT_BUILD, "non_revocation_js", "non_revocation.wasm");
export const DEFAULT_ZKEY = path.join(DEFAULT_BUILD, "nr_final.zkey");

export interface ProofForChain {
  /** abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c) for Groth16NonRevocationVerifier. */
  proofBytes: string;
  /** bytes32[7] in circuit public order: [root, credDefId, challenge, Ax, Ay, idx, val]. */
  publicSignals: string[];
  root: bigint;
}

/**
 * Generate a Groth16 non-revocation proof and format it for on-chain verification.
 * Holder-side: requires the secret credId (in `cred`), the issuer's public key, and the
 * current Poseidon tree (rebuilt from CredentialAdded events).
 */
export async function proveNonRevocation(params: {
  issuer: IssuerKeys;
  cred: IssuedCredential;
  tree: PoseidonTree;
  leafIndex: number;
  credDefId: bigint;
  challenge: bigint;
  disclosedIndex: number;
  wasmPath?: string;
  zkeyPath?: string;
}): Promise<ProofForChain> {
  const { issuer, cred, tree, leafIndex, credDefId, challenge, disclosedIndex } = params;
  const { pathElements, pathIndices } = tree.proof(leafIndex);

  const input = {
    root: tree.root.toString(),
    credDefId: credDefId.toString(),
    challenge: challenge.toString(),
    issuerAx: issuer.Ax.toString(),
    issuerAy: issuer.Ay.toString(),
    disclosedIndex: [disclosedIndex.toString()],
    disclosedValue: [cred.attributes[disclosedIndex].toString()],
    credId: cred.credId.toString(),
    attributes: cred.attributes.map((a) => a.toString()),
    pathElements: pathElements.map((p) => p.toString()),
    pathIndices: pathIndices.map((p) => p.toString()),
    sigS: cred.sigS.toString(),
    sigR8x: cred.sigR8x.toString(),
    sigR8y: cred.sigR8y.toString(),
  };

  const { proof, publicSignals } = await groth16.fullProve(
    input,
    params.wasmPath ?? DEFAULT_WASM,
    params.zkeyPath ?? DEFAULT_ZKEY
  );

  // exportSolidityCallData yields correctly-ordered a,b,c (G2 coords swapped) + inputs.
  const calldata = await groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, inputs] = JSON.parse("[" + calldata + "]");
  const proofBytes = AbiCoder.defaultAbiCoder().encode(
    ["uint256[2]", "uint256[2][2]", "uint256[2]"],
    [a, b, c]
  );
  const toBytes32 = (v: string) => "0x" + BigInt(v).toString(16).padStart(64, "0");
  return {
    proofBytes,
    publicSignals: (inputs as string[]).map(toBytes32),
    root: tree.root,
  };
}
