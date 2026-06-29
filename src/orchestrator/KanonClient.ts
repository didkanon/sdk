import { ContractRunner, Signer, keccak256, getBytes, solidityPacked, randomBytes, hexlify } from "ethers";
import {
  KanonContracts,
  KanonDeployment,
  connectKanon,
  connectKanonFromAddressBook,
  DIDScope,
  VerificationMethodType,
  TIER_ONE_TIME,
  TIER_ZK_SNARK,
  TIER_ALL,
} from "../core";

/** Decoded DID record from the registry (callers map to their DID-document type). */
export interface KanonDidRecord {
  controller: string;
  orgId: string;
  scope: number;
  verificationMethods: { id: string; vmType: number; publicKeyHex: string }[];
  authentication: string[];
  assertionMethod: string[];
  services: { id: string; serviceType: string; endpoint: string }[];
  deactivated: boolean;
}

/**
 * KanonClient — a single ergonomic facade for the six kanon registries.
 *
 * Replaces the legacy `Kanon.sol` facade with an off-chain TypeScript class.
 * Stateless; all state lives on-chain.
 */
export class KanonClient {
  public readonly contracts: KanonContracts;

  constructor(
    public readonly deployment: KanonDeployment,
    runner: ContractRunner,
    contracts?: KanonContracts
  ) {
    this.contracts = contracts ?? connectKanon(deployment, runner);
  }

  /**
   * Build a `KanonClient` by resolving the seven registry addresses from an
   * on-chain `KanonAddressBook` directory contract. Restores the single-address
   * ergonomics: callers only need the address-book address.
   */
  static async fromAddressBook(addressBook: string, runner: ContractRunner): Promise<KanonClient> {
    const contracts = await connectKanonFromAddressBook(addressBook, runner);
    const deployment: KanonDeployment = {
      chainId: 0,
      addresses: {
        OrganizationRegistry: await contracts.orgRegistry.getAddress(),
        DIDRegistry: await contracts.didRegistry.getAddress(),
        SchemaRegistry: await contracts.schemaRegistry.getAddress(),
        CredentialDefinitionRegistry: await contracts.credDefRegistry.getAddress(),
        MerkleStateRegistry: await contracts.merkleStateRegistry.getAddress(),
        Halo2VerifierRegistry: await contracts.verifierRegistry.getAddress(),
      },
    } as KanonDeployment;
    return new KanonClient(deployment, runner, contracts);
  }

  // ── Org operations ──────────────────────────────────────────────────

  async registerOrg(signer: Signer, did: string, admin: string): Promise<string> {
    const tx = await this.contracts.orgRegistry.connect(signer).registerOrg(did, admin);
    const receipt = await tx.wait();
    if (!receipt) throw new Error("no receipt for registerOrg");
    for (const log of receipt.logs) {
      try {
        const parsed = this.contracts.orgRegistry.interface.parseLog(log);
        if (parsed?.name === "OrgRegistered") return parsed.args.orgId as string;
      } catch {
        /* not from orgRegistry */
      }
    }
    throw new Error("OrgRegistered event not found in receipt");
  }

  async approveOrg(governanceSigner: Signer, orgId: string): Promise<void> {
    const tx = await this.contracts.orgRegistry.connect(governanceSigner).approveOrg(orgId);
    await tx.wait();
  }

  async addOrgMember(adminSigner: Signer, orgId: string, member: string): Promise<void> {
    const tx = await this.contracts.orgRegistry.connect(adminSigner).addMember(orgId, member);
    await tx.wait();
  }

  // ── DID operations ──────────────────────────────────────────────────

  /**
   * Compute the canonical user-DID for a given signer + salt.
   * If `salt` is omitted, a fresh random salt is generated.
   */
  computeUserDid(holderAddress: string, salt?: string): { did: string; salt: string } {
    const s = salt ?? hexlify(randomBytes(32));
    const handle = keccak256(solidityPacked(["string", "address", "bytes32"], ["did:kanon:user:", holderAddress, s]));
    return { did: `did:kanon:user:${handle}`, salt: s };
  }

  /** Register a User-scope DID, sender-bound to `signer`. */
  async registerUserDid(
    signer: Signer,
    salt: string,
    options?: { verificationMethods?: { id: string; vmType: VerificationMethodType; publicKey: string }[] }
  ): Promise<string> {
    const holderAddr = await signer.getAddress();
    const { did } = this.computeUserDid(holderAddr, salt);
    const vm = options?.verificationMethods ?? [];
    const refs = vm.map((v) => v.id);
    const doc = {
      controller: "0x0000000000000000000000000000000000000000",
      orgId: "0x" + "00".repeat(32),
      scope: DIDScope.User,
      verificationMethods: vm,
      authentication: refs,
      assertionMethod: refs,
      capabilityInvocation: [],
      capabilityDelegation: [],
      keyAgreement: [],
      services: [],
      docHash: "0x" + "00".repeat(32),
      createdAt: 0,
      updatedAt: 0,
      deactivated: false,
    };
    const tx = await this.contracts.didRegistry.connect(signer).registerDID(did, salt, doc);
    await tx.wait();
    return did;
  }

  /** Register an Org-scope DID `did:kanon:org:<orgId>`. The signer must be an
   * approved+active member of the org. */
  async registerOrgDid(
    signer: Signer,
    orgId: string,
    options?: {
      verificationMethods?: { id: string; vmType: VerificationMethodType; publicKey: string }[];
      services?: { id: string; serviceType: string; endpoint: string }[];
    }
  ): Promise<string> {
    const did = `did:kanon:org:${orgId}`;
    const controller = await signer.getAddress();
    const vm = options?.verificationMethods ?? [];
    const refs = vm.map((v) => v.id);
    const doc = {
      controller,
      orgId,
      scope: DIDScope.Org,
      verificationMethods: vm,
      authentication: refs,
      assertionMethod: refs,
      capabilityInvocation: [],
      capabilityDelegation: [],
      keyAgreement: [],
      services: options?.services ?? [],
      docHash: "0x" + "00".repeat(32),
      createdAt: 0,
      updatedAt: 0,
      deactivated: false,
    };
    const tx = await this.contracts.didRegistry.connect(signer).registerDID(did, "0x" + "00".repeat(32), doc);
    await tx.wait();
    return did;
  }

  /** Resolve a DID into a decoded record (null if absent/reverts). */
  async resolveDidRecord(did: string): Promise<KanonDidRecord | null> {
    let raw;
    try {
      raw = await this.contracts.didRegistry.resolveDID(did);
    } catch {
      return null;
    }
    return {
      controller: raw.controller,
      orgId: raw.orgId as string,
      scope: Number(raw.scope),
      verificationMethods: raw.verificationMethods.map(
        (vm: { id: string; vmType: bigint | number; publicKey: string }) => ({
          id: vm.id,
          vmType: Number(vm.vmType),
          publicKeyHex: vm.publicKey,
        })
      ),
      authentication: [...raw.authentication],
      assertionMethod: [...raw.assertionMethod],
      services: raw.services.map((s: { id: string; serviceType: string; endpoint: string }) => ({
        id: s.id,
        serviceType: s.serviceType,
        endpoint: s.endpoint,
      })),
      deactivated: raw.deactivated,
    };
  }

  // ── Schema operations ──────────────────────────────────────────────

  async registerSchema(
    memberSigner: Signer,
    orgId: string,
    schemaId: string,
    schemaHash: string,
    uri: string
  ): Promise<void> {
    const tx = await this.contracts.schemaRegistry
      .connect(memberSigner)
      .registerSchema(orgId, schemaId, schemaHash, uri);
    await tx.wait();
  }

  // ── CredDef operations ─────────────────────────────────────────────

  /**
   * Register a credential definition. For Mode B credDefs (`tiers & TIER_ZK_SNARK != 0`)
   * the BabyJubjub issuer public key MUST be supplied here — there is no
   * separate "set Tier 2 key" call. Mode A credDefs MUST pass `0n` for both
   * coordinates; the registry rejects a stray key with `UnexpectedIssuerZkPubKey`
   * to catch policyMask / key mismatches at the source.
   */
  async registerCredentialDefinition(
    memberSigner: Signer,
    credDefId: string,
    schemaId: string,
    issuerPubKey: Uint8Array,
    tiers: number = TIER_ALL,
    uri: string = "",
    issuerZkPubKey: { ax: bigint; ay: bigint } = { ax: 0n, ay: 0n }
  ): Promise<void> {
    const tx = await this.contracts.credDefRegistry
      .connect(memberSigner)
      .registerCredentialDefinition(
        credDefId,
        schemaId,
        hexlify(issuerPubKey),
        tiers,
        uri,
        issuerZkPubKey.ax,
        issuerZkPubKey.ay
      );
    await tx.wait();
  }

  /**
   * Read the policy mask the issuer chose when registering this credDef. The
   * mask is the union of TIER_ONE_TIME (0b01) and TIER_ZK_SNARK (0b10). Plugins
   * read it at issuance time to decide whether to also write a Mode B leaf to
   * MerkleStateRegistry.
   */
  async getCredDefPolicy(credDefId: string): Promise<number> {
    const cd = await this.contracts.credDefRegistry.getCredentialDefinition(credDefId);
    return Number(cd.policyMask);
  }

  /** True iff the credDef opted in to Tier-2 unlinkable presentations. */
  async credDefSupportsZk(credDefId: string): Promise<boolean> {
    return this.contracts.credDefRegistry.supportsTier(credDefId, TIER_ZK_SNARK);
  }

  /** True iff the credDef opted in to Tier-1 one-time-use credentials. */
  async credDefSupportsOneTime(credDefId: string): Promise<boolean> {
    return this.contracts.credDefRegistry.supportsTier(credDefId, TIER_ONE_TIME);
  }

  // ── Convenience constants ──────────────────────────────────────────

  static readonly TIER_ONE_TIME = TIER_ONE_TIME;
  static readonly TIER_ZK_SNARK = TIER_ZK_SNARK;
  static readonly TIER_ALL = TIER_ALL;
}
