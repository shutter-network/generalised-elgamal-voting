import "@rainbow-me/rainbowkit/styles.css";
import { RainbowKitProvider, lightTheme } from "@rainbow-me/rainbowkit";

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

export { ConnectButton } from "@rainbow-me/rainbowkit";
