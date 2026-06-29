import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { keccak256 } from "ethers";

import { deploySystem } from "../helpers/fixtures";
import {
  IssuerService,
  HolderWallet,
  InMemoryHolderStorage,
  VerifierService,
  KanonClient,
} from "../../sdk/src";
import { generateIssuerKeyPair, verifyCredentialSignature } from "../../sdk/src/issuer/keys";
import { TIER_ONE_TIME, deriveLeaf, StandardMerkleTree } from "../../sdk/src/core";

describe("SDK integration", () => {
  it("issuer + holder + verifier full lifecycle (Tier 1)", async () => {
    const sys = await loadFixture(deploySystem);

    // Pretend deployment object so sdk-core types are exercised
    const deployment = {
      chainId: 31337,
      network: "hardhat",
      deployedAt: new Date().toISOString(),
      deployer: await sys.rootAdmin.getAddress(),
      rootAdmin: await sys.rootAdmin.getAddress(),
      addresses: {
        OrganizationRegistry: await sys.orgRegistry.getAddress(),
        DIDRegistry: await sys.didRegistry.getAddress(),
        SchemaRegistry: await sys.schemaRegistry.getAddress(),
        CredentialDefinitionRegistry: await sys.credDefRegistry.getAddress(),
        MerkleStateRegistry: await sys.merkleStateRegistry.getAddress(),
        Halo2VerifierRegistry: await sys.verifierRegistry.getAddress(),
      },
    };

    // KanonClient orchestration: register an approved org
    const client = new KanonClient(deployment, sys.orgAdmin);
    const orgId = await client.registerOrg(sys.orgAdmin, "did:kanon:org:1", await sys.orgAdmin.getAddress());
    await client.approveOrg(sys.rootAdmin, orgId);
    await client.addOrgMember(sys.orgAdmin, orgId, await sys.member1.getAddress());

    // Register schema
    const schemaId = keccak256(ethers.toUtf8Bytes("SDK-test-schema"));
    const schemaHash = keccak256(ethers.toUtf8Bytes("schema-content"));
    await client.registerSchema(sys.member1, orgId, schemaId, schemaHash, "ipfs://Qm-test");

    // Generate BLS issuer key pair using SDK
    const issuerKeys = generateIssuerKeyPair();
    expect(issuerKeys.privateKey.length).to.equal(32);
    expect(issuerKeys.publicKey.length).to.equal(96);

    // Register credDef using SDK
    const credDefId = keccak256(ethers.toUtf8Bytes("SDK-test-credDef"));
    await client.registerCredentialDefinition(
      sys.member1,
      credDefId,
      schemaId,
      issuerKeys.publicKey,
      TIER_ONE_TIME
    );

    // Wire up the IssuerService
    const issuer = new IssuerService(
      {
        orgRegistry: sys.orgRegistry,
        didRegistry: sys.didRegistry,
        schemaRegistry: sys.schemaRegistry,
        credDefRegistry: sys.credDefRegistry,
        merkleStateRegistry: sys.merkleStateRegistry,
        verifierRegistry: sys.verifierRegistry,
      },
      sys.member1,
      credDefId,
      issuerKeys
    );
    await issuer.initialize();

    // Issue a pool of 3 Tier-1 credentials to the holder
    const holderAddr = await sys.holder.getAddress();
    const pool = await issuer.issueOneTimePool(holderAddr, { kyc_level: "verified" }, 3);
    expect(pool.credentials.length).to.equal(3);

    // HolderWallet holds the pool
    const storage = new InMemoryHolderStorage();
    const wallet = new HolderWallet(storage, {
      orgRegistry: sys.orgRegistry,
      didRegistry: sys.didRegistry,
      schemaRegistry: sys.schemaRegistry,
      credDefRegistry: sys.credDefRegistry,
      merkleStateRegistry: sys.merkleStateRegistry,
      verifierRegistry: sys.verifierRegistry,
    });
    await wallet.acceptPool(pool);

    // Holder builds a Tier-1 presentation
    const presentation = await wallet.buildTier1Presentation(credDefId);
    expect(presentation.credDefId).to.equal(credDefId);
    expect(presentation.merkleProof.length).to.be.greaterThan(0);

    // VerifierService validates the presentation
    const verifier = new VerifierService({
      orgRegistry: sys.orgRegistry,
      didRegistry: sys.didRegistry,
      schemaRegistry: sys.schemaRegistry,
      credDefRegistry: sys.credDefRegistry,
      merkleStateRegistry: sys.merkleStateRegistry,
      verifierRegistry: sys.verifierRegistry,
    });
    expect(await verifier.verifyTier1Presentation(presentation)).to.equal(true);

    // Consume the credential on-chain
    await sys.merkleStateRegistry
      .connect(sys.holder)
      .consumeOneTime(credDefId, presentation.credId, presentation.merkleProof);
    expect(
      await sys.merkleStateRegistry.isNullifierUsed(credDefId, presentation.credId)
    ).to.equal(true);

    // Verifier now rejects (nullifier used)
    expect(await verifier.verifyTier1Presentation(presentation)).to.equal(false);

    // Issuer signature verifies off-chain via VerifierService
    expect(
      await verifier.verifyCredentialIssuance(
        credDefId,
        pool.credentials[0].credentialId,
        pool.credentials[0].attributesHash,
        pool.credentials[0].issuerSignature
      )
    ).to.equal(true);
  });

  it("BLS signature round-trip via @noble/curves works", () => {
    const issuer = generateIssuerKeyPair();
    const message = new TextEncoder().encode("hello kanon");
    const { signCredential } = require("../../sdk/src/issuer/keys");
    const sig = signCredential(issuer, message);
    expect(sig.length).to.equal(48);
    expect(verifyCredentialSignature(issuer.publicKey, message, sig)).to.equal(true);

    // Wrong message rejects
    expect(
      verifyCredentialSignature(issuer.publicKey, new TextEncoder().encode("tampered"), sig)
    ).to.equal(false);
  });

  it("StandardMerkleTree generates valid proofs that pass on-chain verifier", async () => {
    const sys = await loadFixture(deploySystem);
    // Register a credDef with Tier 1 only, populate the tree, present from SDK
    await sys.orgRegistry.connect(sys.orgAdmin).registerOrg("did:kanon:org:1", await sys.orgAdmin.getAddress());
    await sys.orgRegistry.connect(sys.rootAdmin).approveOrg(1);
    const schemaId = keccak256(ethers.toUtf8Bytes("S"));
    await sys.schemaRegistry
      .connect(sys.orgAdmin)
      .registerSchema(1, schemaId, keccak256(ethers.toUtf8Bytes("h")), "u");
    const credDefId = keccak256(ethers.toUtf8Bytes("C"));
    await sys.credDefRegistry
      .connect(sys.orgAdmin)
      .registerCredentialDefinition(credDefId, schemaId, ethers.hexlify(ethers.randomBytes(96)), 1);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .initializeCredDefState(credDefId, ethers.ZeroHash, ethers.ZeroHash);

    const credIds: string[] = [];
    const leaves: string[] = [];
    for (let i = 0; i < 8; i++) {
      const credId = keccak256(ethers.toUtf8Bytes(`c${i}`));
      credIds.push(credId);
      leaves.push(deriveLeaf(credId));
    }
    const tree = new StandardMerkleTree(leaves);
    await sys.merkleStateRegistry
      .connect(sys.orgAdmin)
      .batchUpdate(
        credDefId,
        leaves,
        leaves.map(keccak256),
        [],
        [],
        tree.root,
        ethers.ZeroHash
      );
    for (let i = 0; i < credIds.length; i++) {
      const proof = tree.proofFor(leaves[i]);
      expect(
        await sys.merkleStateRegistry.verifyKeccakMembership(credDefId, credIds[i], proof)
      ).to.equal(true);
    }
  });
});
