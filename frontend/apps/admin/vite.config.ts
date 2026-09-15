import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// @geg/shared is consumed as TypeScript source via this alias (Vite transpiles it),
// so there's no separate build step for the shared package.
// The shared dashboard's in-browser verification pulls in the crypto SDK
// (@shutter-network/urban-verified-crypto), which expects `buffer` + a Node-ish
// global; polyfill them (mirrors the voter app). blst.js/blst.wasm live in public/.
export default defineConfig({
  plugins: [react()],
  define: { global: "globalThis" },
  resolve: {
    alias: {
      "@geg/shared": fileURLToPath(new URL("../../shared/src", import.meta.url)),
      buffer: "buffer/",
    },
  },
  optimizeDeps: {
    include: ["buffer"],
    esbuildOptions: { define: { global: "globalThis" } },
  },
  server: { port: 5173 },
});
