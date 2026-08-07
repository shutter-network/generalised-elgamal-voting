import "@rainbow-me/rainbowkit/styles.css";
import { ConnectButton as RKConnectButton, RainbowKitProvider, lightTheme } from "@rainbow-me/rainbowkit";

// Match the app's shutter-blue so the ConnectButton is the same #0044a4 as every other button.
const rkTheme = lightTheme({ accentColor: "#0044a4", accentColorForeground: "#ffffff" });
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WagmiProvider } from "wagmi";
import { wagmiConfig } from "./config";

const queryClient = new QueryClient();

/** Wrap an app in the wagmi + react-query + RainbowKit providers. RainbowKit's
 * <ConnectButton/> then gives connect / disconnect / switch-account UI for free. */
export function Web3Providers({ children }: { children: React.ReactNode }) {
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={rkTheme}>{children}</RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

/** The wallet connect / account control. This is RainbowKit's own <ConnectButton>, so the
 * connected-account popup is RainbowKit's real account modal (ENS name/avatar, balance,
 * copy, explorer, disconnect) — not a hand-rolled replica.
 *
 * The app never sends a transaction (it only EIP-191 *signs*), so the network is cosmetic:
 * we hide the chain pill (`chainStatus="none"`) and the balance. RainbowKit only works /
 * avoids a "Wrong network" nag when the connected chain is in wagmi's `chains` — see
 * config.ts, which lists the chains this app is realistically used on. */
export function ConnectButton() {
  return <RKConnectButton chainStatus="none" showBalance={false} />;
}
