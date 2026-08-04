/** `0x`-hex <-> bytes helpers (the SDK exports none). Matches geg's `enc_bytes`. */

export type Hex = string; // 0x-prefixed lowercase hex

export function bytesToHex(b: Uint8Array): Hex {
  let s = "0x";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(h: Hex): Uint8Array {
  const body = h.startsWith("0x") ? h.slice(2) : h;
  if (body.length % 2 !== 0) throw new Error(`odd-length hex: ${h}`);
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** A decimal election id (as the public API returns) -> canonical 32-byte 0x-hex. */
export function eidToHex(id: number | bigint): Hex {
  let n = BigInt(id).toString(16);
  if (n.length > 64) throw new Error(`election id too large: ${id}`);
  return "0x" + n.padStart(64, "0");
}

/** Bare 64-char hex (no 0x) for the gateway ballot path segment. */
export function eidToBareHex(id: number | bigint): string {
  return eidToHex(id).slice(2);
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
