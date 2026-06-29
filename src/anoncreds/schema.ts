import { keccak256, toUtf8Bytes } from "ethers";
import { parseKanonDid, resourceIdToBytes32, schemaResourceId } from "./identifiers";

/**
 * Schema anchoring for the kanon SchemaRegistry.
 *
 * The registry is content-agnostic: it stores `(issuerOrg, schemaHash, uri, …)`
 * where `schemaHash = keccak256(canonical JSON)` and the full body rides inline
 * as a `data:` URI. The canonicalization (recursively sorted keys, no
 * whitespace) is byte-identical to the Python `did_kanon` plugin so the two
 * interoperate, and it is exactly what `VerifierService.validateSchemaJson`
 * checks.
 *
 * `anchorJson` / `decodeDataUri` are the generic core (any JSON body);
 * `encodeAnonCredsSchema` is a thin wrapper that supplies the AnonCreds shape
 * and the resource-id derivation.
 */

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = canonicalize((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

/** Canonical JSON bytes (recursively sorted keys, no whitespace). */
export function canonicalJsonBytes(obj: unknown): Uint8Array {
  return toUtf8Bytes(JSON.stringify(canonicalize(obj)));
}

function toBase64(bytes: Uint8Array): string {
  return typeof Buffer !== "undefined"
    ? Buffer.from(bytes).toString("base64")
    : btoa(String.fromCharCode(...bytes));
}

function fromBase64(b64: string): Uint8Array {
  return typeof Buffer !== "undefined"
    ? new Uint8Array(Buffer.from(b64, "base64"))
    : Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export interface AnchoredJson {
  /** keccak256 of the canonical JSON body. */
  hash: string;
  /** data:application/json;base64,… holding the canonical body. */
  uri: string;
  /** the exact canonical bytes that were hashed + base64'd. */
  canonical: Uint8Array;
}

/** Generic: anchor any JSON body → on-chain hash + inline `data:` URI. */
export function anchorJson(body: unknown): AnchoredJson {
  const canonical = canonicalJsonBytes(body);
  return {
    hash: keccak256(canonical),
    uri: "data:application/json;base64," + toBase64(canonical),
    canonical,
  };
}

/** Generic: decode an inline `data:` JSON URI back into an object (or null). */
export function decodeDataUri(uri: string): unknown | null {
  if (!uri || !uri.startsWith("data:")) return null;
  const comma = uri.indexOf(",");
  if (comma < 0) return null;
  const meta = uri.slice(0, comma);
  const payload = uri.slice(comma + 1);
  try {
    const raw = meta.includes("base64") ? fromBase64(payload) : toUtf8Bytes(payload);
    return JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return null;
  }
}

// ── AnonCreds wrapper ──────────────────────────────────────────────────

export interface KanonSchemaBody {
  name: string;
  version: string;
  attrNames: string[];
  issuerId: string;
}

export interface EncodedAnonCredsSchema {
  /** AnonCreds resource id (DID URL). */
  schemaId: string;
  /** On-chain bytes32 key. */
  schemaIdBytes32: string;
  /** keccak256 of the canonical body. */
  schemaHash: string;
  /** data: URI holding the canonical body. */
  uri: string;
  body: KanonSchemaBody;
}

/** Build the on-chain schemaId/hash/uri for an AnonCreds schema. */
export function encodeAnonCredsSchema(schema: {
  issuerId: string;
  name: string;
  version: string;
  attrNames: string[];
}): EncodedAnonCredsSchema {
  const body: KanonSchemaBody = {
    name: schema.name,
    version: schema.version,
    attrNames: [...schema.attrNames],
    issuerId: schema.issuerId,
  };
  const anchored = anchorJson(body);
  const schemaId = schemaResourceId(schema.issuerId, schema.name, schema.version);
  return {
    schemaId,
    schemaIdBytes32: resourceIdToBytes32(schemaId),
    schemaHash: anchored.hash,
    uri: anchored.uri,
    body,
  };
}

/** Org id (bytes32 hex) for an org-scoped issuer DID; throws for non-org issuers. */
export function issuerOrgId(issuerDid: string): string {
  const parsed = parseKanonDid(issuerDid);
  if (!parsed || parsed.scope !== "org" || parsed.orgId === undefined) {
    throw new Error(`kanon: issuer must be an org DID (did:kanon:org:0x<64hex>), got ${issuerDid}`);
  }
  return parsed.orgId;
}
