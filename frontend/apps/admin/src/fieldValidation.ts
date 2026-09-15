/** Shape checks for the 0x-hex identity fields in the register form.
 *
 * These fields go straight into the **signed** config, so a malformed one is expensive:
 * the admin signs it, the registration either reverts on chain or lands a config whose
 * ballots can never verify. Catching the shape here turns a confusing downstream failure
 * (a contract revert, or every ballot failing attestation at ingestion) into a specific
 * message before the wallet is even asked to sign.
 *
 * Length is the meaningful check because each field has exactly one legal size:
 *   - eligibility public key → 48 bytes (compressed BLS12-381 G1)
 *   - result publisher       → 20 bytes (Ethereum address)
 *   - ballot sponsor         → 20 bytes (Ethereum address), optional
 * A 40-hex-char value pasted into the eligibility field, or a truncated address, is
 * otherwise indistinguishable from a valid one until much later.
 */

export const ELIGIBILITY_KEY_BYTES = 48; // compressed BLS12-381 G1 point
export const ADDRESS_BYTES = 20; // secp256k1 / Ethereum address

const ZERO_ADDRESS = "0x" + "0".repeat(2 * ADDRESS_BYTES);

/**
 * Validate a 0x-hex field of an exact byte length. Returns the lowercased value, or
 * throws with a message naming the field and what was wrong.
 *
 * Lowercasing matters beyond tidiness: the backend decodes each value to bytes and
 * re-encodes it lowercase before recomputing the register digest, so a checksummed
 * (mixed-case) address would be signed in one form and verified in another.
 */
export function requireHexBytes(value: string, byteLength: number, label: string): string {
  const v = value.trim();
  if (!v) throw new Error(`${label} is required.`);
  if (!v.startsWith("0x")) {
    throw new Error(`${label} must start with 0x (got "${truncate(v)}").`);
  }
  const body = v.slice(2);
  if (!/^[0-9a-fA-F]*$/.test(body)) {
    throw new Error(`${label} must be hexadecimal — it contains a non-hex character.`);
  }
  const expected = 2 * byteLength;
  if (body.length !== expected) {
    const gotBytes = body.length / 2;
    const detail = Number.isInteger(gotBytes)
      ? `${gotBytes} byte${gotBytes === 1 ? "" : "s"}`
      : `${body.length} hex characters (not a whole number of bytes)`;
    throw new Error(
      `${label} must be exactly ${byteLength} bytes (${expected} hex characters after 0x), ` +
      `but this is ${detail}.`,
    );
  }
  return v.toLowerCase();
}

/** An Ethereum address, rejecting the zero address (granting a role to 0x0 is never intended). */
export function requireAddress(value: string, label: string): string {
  const v = requireHexBytes(value, ADDRESS_BYTES, label);
  if (v === ZERO_ADDRESS) throw new Error(`${label} cannot be the zero address.`);
  return v;
}

/** The 48-byte compressed BLS12-381 G1 eligibility issuer key. */
export function requireEligibilityKey(value: string): string {
  return requireHexBytes(value, ELIGIBILITY_KEY_BYTES, "Eligibility public key");
}

/** An address that may be left blank; shape-checked only when one is supplied. */
export function optionalAddress(value: string, label: string): string | null {
  return value.trim() ? requireAddress(value, label) : null;
}

/**
 * The ballot sponsor (vote proxy), whose *necessity* depends on the backend:
 *
 *   - **blockchain** → required. `ElectionBase`'s constructor reverts with `InvalidConfig`
 *     on `voteProxy == address(0)`, so "no sponsor" is not expressible on chain. (It is not
 *     the only permitted writer — `ElectionVoting` lets anyone self-submit for
 *     `selfSubmitFee` — but the address must still be non-zero.)
 *   - **database / memory** → optional. Empty `gatewayKeys` means *open ballot writes*, the
 *     documented default for voter-direct deployments.
 *
 * When the backend is not yet known (the capability probe failed) we stay **lenient**:
 * blocking a legitimate database registration because a status fetch failed would be worse
 * than letting the chain adapter raise its own clear error a moment later.
 */
export function sponsorAddress(value: string, dataStore: "database" | "blockchain" | null): string | null {
  const label = "On-chain ballot sponsor (vote-proxy)";
  if (dataStore === "blockchain") return requireAddress(value, label);
  return optionalAddress(value, label);
}

function truncate(v: string): string {
  return v.length <= 24 ? v : `${v.slice(0, 21)}…`;
}
