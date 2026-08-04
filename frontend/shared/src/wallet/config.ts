import { createConfig, http } from "wagmi";
import { mainnet } from "wagmi/chains";
import { injected } from "wagmi/connectors";

/** wagmi config for both apps. We only ever *sign* (admin: register/cancel digests;
 * voter: the eligibility challenge) via EIP-191 personal-sign — which is **chain-agnostic**
 * (no chainId in the signed payload). No transactions are ever sent from the browser, so
 * the configured chain is purely nominal: wagmi's API requires at least one, but the user
 * can be connected to any network and signing still works (we hide the chain UI). mainnet
 * is just a placeholder with a default transport we never call.
 *
 * Injected-only connector (MetaMask/Rabby browser extension) — no WalletConnect, so no
 * WalletConnect Cloud projectId is required. RainbowKit still provides the connect /
 * disconnect / account UI on top. */
export const wagmiConfig = createConfig({
  chains: [mainnet],
  connectors: [injected()],
  transports: { [mainnet.id]: http() },
});
