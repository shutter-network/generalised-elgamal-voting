// Wallet layer (wagmi + RainbowKit). Kept as a separate entrypoint (`@geg/shared/wallet`)
// so importing the dashboard/api barrel doesn't pull in the wallet stack.
export { wagmiConfig } from "./config";
export { Web3Providers, ConnectButton } from "./Web3Providers";
export { useWalletSigner, type WalletSigner } from "./useWalletSigner";
