/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

export default defineConfig({
  // The dev server must never listen beyond loopback (plan section 1, rule 6).
  server: {
    host: "127.0.0.1",
    port: 9245,
    strictPort: true,
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  plugins: [svelte()],
  test: {
    include: ["src/**/*.test.ts"],
  },
});
