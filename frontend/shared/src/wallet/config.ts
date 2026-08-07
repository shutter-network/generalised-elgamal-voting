import { createConfig, http } from "wagmi";
import { mainnet, sepolia, holesky, hoodi, base, arbitrum, optimism, polygon, foundry, localhost } from "wagmi/chains";
import { injected } from "wagmi/connectors";

/** wagmi config for both apps. We only ever *sign* (admin: register/cancel digests;
 * voter: the eligibility challenge) via EIP-191 personal-sign — which is **chain-agnostic**
 * (no chainId in the signed payload). No transactions are ever sent from the browser, so
 * the configured chains are purely nominal and their transports are never called.
 *
 * We list the handful of chains this app is realistically used on so RainbowKit does NOT
 * flag "Wrong network" and its account modal works: mainnet + common testnets, the main
 * L2s, and the local dev chains (anvil/foundry = 31337, localhost = 1337). A wallet on some
 * other chain still signs fine, but RainbowKit would show "Wrong network" — add that
 * chainId here to fix it.
 *
 * Injected-only connector (MetaMask/Rabby browser extension) — no WalletConnect, so no
 * WalletConnect Cloud projectId is required. RainbowKit provides the connect / disconnect /
 * account UI on top. */
export const wagmiConfig = createConfig({
  chains: [mainnet, sepolia, holesky, hoodi, base, arbitrum, optimism, polygon, foundry, localhost],
  connectors: [injected()],
  transports: {
    [mainnet.id]: http(),
    [sepolia.id]: http(),
    [holesky.id]: http(),
    [hoodi.id]: http(),
    [base.id]: http(),
    [arbitrum.id]: http(),
    [optimism.id]: http(),
    [polygon.id]: http(),
    [foundry.id]: http(),
    [localhost.id]: http(),
  },
});
