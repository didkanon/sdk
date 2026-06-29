// Minimal ambient declarations for the untyped ZK dependencies so the strict SDK
// build compiles. The surfaces used are small and exercised by tests.
declare module "circomlibjs" {
  export const buildPoseidon: () => Promise<any>;
  export const buildEddsa: () => Promise<any>;
}
declare module "snarkjs" {
  export const groth16: {
    fullProve: (input: any, wasmPath: string, zkeyPath: string) => Promise<{ proof: any; publicSignals: any }>;
    exportSolidityCallData: (proof: any, publicSignals: any) => Promise<string>;
    verify: (vk: any, publicSignals: any, proof: any) => Promise<boolean>;
  };
}
