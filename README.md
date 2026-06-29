# @ajna-inc/kanon-sdk

TypeScript SDK for the **Kanon AnonCreds VDR** — a W3C-compliant decentralised identity protocol that runs on any EVM-compatible chain.

If you're building a Credo agent, install `@ajna-inc/kanon` instead — it depends on this SDK and wires it into Credo for you. The SDK alone is for back-end issuer services, custom verifiers, or low-level contract interactions.

```bash
npm install @ajna-inc/kanon-sdk ethers
```

`ethers` v6 is a peer dependency. `snarkjs` and `circomlibjs` are optional — only required if you use the Mode B (Kanon ZK) prover.

## What's in the box

| Subpath | Purpose |
|---|---|
| `@ajna-inc/kanon-sdk` | Convenience top-level re-exports (KanonClient, IssuerService, VerifierService, HolderWallet, kanonCredIdHash) |
| `kanon/core` | Types, deployment loader, contract handles, Merkle tree, tier constants |
| `kanon/issuer` | EdDSA-BabyJubjub keys, IssuerService (mint, revoke, batchUpdate) |
| `kanon/holder` | HolderWallet + IHolderStorage + InMemoryHolderStorage |
| `kanon/verifier` | VerifierService (Tier-1 + Tier-2 verification helpers) |
| `kanon/orchestrator` | KanonClient — high-level facade across the seven registries |
| `kanon/anoncreds` | `kanonCredIdHash`, `KANON_CRED_ID_ATTRIBUTE` — minimal helpers consumed by the Credo plugin |
| `kanon/zk` | Mode B Groth16 prover — needs `snarkjs` + `circomlibjs` |

## Mode A vs Mode B

- **Mode A (default).** Use the `anoncreds` subpath plus `core` ABIs. No SNARK math required. This is what `@ajna-inc/kanon` (Credo plugin) uses to add on-chain revocation status to standard AnonCreds.
- **Mode B (optional).** Use the `zk` subpath. Generates Groth16 proofs against the Poseidon Merkle tree for unlinkable presentations.

## Build

```bash
npm install
npm run build     # tsup → dist/{index,core/...,zk/...}.{js,cjs,d.ts}
npm test          # currently a no-op; the contracts tests cover the on-chain layer
```

## License

Apache-2.0. See `LICENSE`.
