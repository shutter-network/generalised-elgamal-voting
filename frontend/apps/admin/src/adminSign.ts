/** Admin authorization: sign register/cancel requests with the admin wallet (MetaMask).
 *
 * The digests below are byte-exact mirrors of `geg.core.authz`:
 *   register → keccak256(canonical JSON of the config with electionId zeroed) == register_digest
 *   cancel   → keccak256("cancel" | "|" | eid(32) | "|")                       == request_digest("cancel", eid)
 * The wallet then EIP-191 personal-signs the raw digest (== Python encode_defunct(primitive=digest)),
 * so the service/data-layer `ecrecover` matches config.admin_key. Locked by adminSign.test.ts. */

import { concat, hexToBytes, keccak256, stringToBytes, type Hex } from "viem";

const ZERO_EID: Hex = ("0x" + "0".repeat(64)) as Hex;

/** Canonical JSON matching Python `json.dumps(obj, sort_keys=True, separators=(",",":"))`:
 * object keys sorted recursively, array order preserved, no whitespace. (Values here are
 * ASCII hex / ints / short strings, so JSON escaping is identical across Python and JS.) */
export function canonicalize(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(o[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

/** Lowercase every 0x-hex value in a config. The backend decodes each address/key to bytes
 * and re-encodes it **lowercase** before recomputing the digest, so we must sign the
 * lowercase form. Critically, wagmi returns the admin's address EIP-55 **checksummed**
 * (mixed case); signing that verbatim changes the digest and fails verification. Non-hex
 * strings (variant "A", mode, urls, protocolVersion) don't start with 0x, so are untouched. */
export function lowercaseHex<T>(v: T): T {
  if (typeof v === "string") return (v.startsWith("0x") ? v.toLowerCase() : v) as T;
  if (Array.isArray(v)) return v.map(lowercaseHex) as unknown as T;
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, lowercaseHex(val)])) as T;
  }
  return v;
}

/** register_digest: the config digest is taken with electionId zeroed (the backend assigns
 * the id, so it's not bound by the admin signature). */
export function registerDigest(config: Record<string, unknown>): Hex {
  return keccak256(stringToBytes(canonicalize({ ...config, electionId: ZERO_EID })));
}

/** request_digest("cancel", eid). `eid` is the canonical 0x-hex 32-byte election id
 * (accepts a plain string; @geg/shared's Hex is `string`). */
export function cancelDigest(eid: string): Hex {
  return keccak256(concat([stringToBytes("cancel|"), hexToBytes(eid as `0x${string}`), stringToBytes("|")]));
}

