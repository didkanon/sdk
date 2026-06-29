import { ContractRunner, JsonRpcProvider } from "ethers";
import {
  OrganizationRegistry,
  DIDRegistry,
  SchemaRegistry,
  CredentialDefinitionRegistry,
  MerkleStateRegistry,
  Halo2VerifierRegistry,
  OrganizationRegistry__factory,
  DIDRegistry__factory,
  SchemaRegistry__factory,
  CredentialDefinitionRegistry__factory,
  MerkleStateRegistry__factory,
  Halo2VerifierRegistry__factory,
  KanonAddressBook__factory,
} from "../../../typechain-types";
import { KanonDeployment } from "./types";
import { loadDeployment } from "./deployment";

export interface KanonContracts {
  orgRegistry: OrganizationRegistry;
  didRegistry: DIDRegistry;
  schemaRegistry: SchemaRegistry;
  credDefRegistry: CredentialDefinitionRegistry;
  merkleStateRegistry: MerkleStateRegistry;
  verifierRegistry: Halo2VerifierRegistry;
}

/** Connect all six registries using the provided runner (provider or signer). */
export function connectKanon(deployment: KanonDeployment, runner: ContractRunner): KanonContracts {
  const a = deployment.addresses;
  return {
    orgRegistry: OrganizationRegistry__factory.connect(a.OrganizationRegistry, runner),
    didRegistry: DIDRegistry__factory.connect(a.DIDRegistry, runner),
    schemaRegistry: SchemaRegistry__factory.connect(a.SchemaRegistry, runner),
    credDefRegistry: CredentialDefinitionRegistry__factory.connect(a.CredentialDefinitionRegistry, runner),
    merkleStateRegistry: MerkleStateRegistry__factory.connect(a.MerkleStateRegistry, runner),
    verifierRegistry: Halo2VerifierRegistry__factory.connect(a.Halo2VerifierRegistry, runner),
  };
}

/**
 * Resolve the seven registry addresses from an on-chain `KanonAddressBook`
 * directory contract, then connect all registries using the provided runner.
 */
export async function connectKanonFromAddressBook(
  addressBook: string,
  runner: ContractRunner
): Promise<KanonContracts> {
  const book = KanonAddressBook__factory.connect(addressBook, runner);
  const r = await book.registries();
  const deployment = {
    addresses: {
      OrganizationRegistry: r.organizationRegistry,
      DIDRegistry: r.didRegistry,
      SchemaRegistry: r.schemaRegistry,
      CredentialDefinitionRegistry: r.credentialDefinitionRegistry,
      MerkleStateRegistry: r.merkleStateRegistry,
      Halo2VerifierRegistry: r.halo2VerifierRegistry,
    },
  } as KanonDeployment;
  return connectKanon(deployment, runner);
}

/**
 * Convenience: create a JsonRpcProvider, load deployment, return readonly contracts.
 */
export async function connectKanonReadonly(
  rpcUrl: string,
  chainId?: number
): Promise<KanonContracts & { provider: JsonRpcProvider; deployment: KanonDeployment }> {
  const provider = new JsonRpcProvider(rpcUrl);
  const resolvedChainId = chainId ?? Number((await provider.getNetwork()).chainId);
  const deployment = loadDeployment(resolvedChainId);
  return {
    ...connectKanon(deployment, provider),
    provider,
    deployment,
  };
}

export type {
  OrganizationRegistry,
  DIDRegistry,
  SchemaRegistry,
  CredentialDefinitionRegistry,
  MerkleStateRegistry,
  Halo2VerifierRegistry,
};
