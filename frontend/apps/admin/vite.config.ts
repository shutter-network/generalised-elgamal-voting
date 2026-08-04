import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// @geg/shared is consumed as TypeScript source via this alias (Vite transpiles it),
// so there's no separate build step for the shared package.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@geg/shared": fileURLToPath(new URL("../../shared/src", import.meta.url)),
    },
  },
  server: { port: 5173 },
});
