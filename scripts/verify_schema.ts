// Exercise real SDK code against the live chain: read the schema the Python
// plugin registered and validate it through VerifierService.validateSchemaJson.
import { connectKanonReadonly } from "../src/core/contracts";
import { VerifierService } from "../src/verifier/VerifierService";

const SCHEMA_ID =
  "0x1720b87c00a667f18f850a9e193d30d73fc9b210f4253313185cfcafc9ccf4e3";
const RPC = "https://besu.essi.studio";

async function main() {
  const conn = await connectKanonReadonly(RPC, 1947);
  const verifier = new VerifierService(conn);
  const s = await conn.schemaRegistry.getSchema(SCHEMA_ID);
  const b64 = s.uri.split(",")[1];
  const canonical = new Uint8Array(Buffer.from(b64, "base64"));
  const valid = await verifier.validateSchemaJson(SCHEMA_ID, canonical);
  console.log("schemaHash :", s.schemaHash);
  console.log("uri        :", s.uri.slice(0, 48) + "...");
  console.log("validateSchemaJson:", valid);
  if (!valid) {
    console.error("SDK FAILED to validate Python-registered schema");
    process.exit(1);
  }
  console.log("SDK VALIDATED PYTHON-REGISTERED SCHEMA");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
