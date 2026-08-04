import type { Hex } from "viem";
import { useAccount, useSignMessage } from "wagmi";

export interface WalletSigner {
  /** Connected account, or null when no wallet is connected. */
  account: Hex | null;
  /** EIP-191 personal-sign over a raw 32-byte digest (admin register/cancel). */
  signDigest: (digest: Hex) => Promise<Hex>;
  /** EIP-191 personal-sign over a human-readable message (voter eligibility challenge).
   * Chain-agnostic — proving address control needs no chain/network. */
  signMessage: (message: string) => Promise<Hex>;
}

/** Wallet signer over the connected wagmi account. Both apps use this instead of a
 * bespoke viem client, so RainbowKit owns connect/disconnect/switch. */
export function useWalletSigner(): WalletSigner {
  const { address } = useAccount();
  const { signMessageAsync } = useSignMessage();
  return {
    account: (address ?? null) as Hex | null,
    signDigest: (digest) => signMessageAsync({ message: { raw: digest } }),
    signMessage: (message) => signMessageAsync({ message }),
  };
}
