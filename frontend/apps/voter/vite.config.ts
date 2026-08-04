import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The crypto SDK (@shutter-network/urban-verified-crypto) pulls in `buffer` and expects
// a Node-ish global; polyfill it for the browser. blst.js/blst.wasm live in public/.
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
  server: { port: 5174 },
});
