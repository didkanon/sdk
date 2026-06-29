import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "core/index": "src/core/index.ts",
    "issuer/index": "src/issuer/index.ts",
    "holder/index": "src/holder/index.ts",
    "verifier/index": "src/verifier/index.ts",
    "orchestrator/index": "src/orchestrator/index.ts",
    "anoncreds/index": "src/anoncreds/index.ts",
    "zk/index": "src/zk/index.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  external: [
    "ethers",
    "circomlibjs",
    "snarkjs",
    "@noble/curves",
    "@noble/hashes",
    "@openzeppelin/merkle-tree",
  ],
  outDir: "dist",
});
