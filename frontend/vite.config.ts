/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// The development server injects CSS as inline <style> elements, which the
// page's CSP refuses. Only while serving on loopback for development, the
// policy also allows inline styles; a build never runs this plugin, and the
// bundle check refuses any CSP that allows inline content (S-33).
function devServerStyles(): Plugin {
  return {
    name: "soireehost-dev-styles",
    apply: "serve",
    transformIndexHtml(html) {
      return html.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'");
    },
  };
}

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
  plugins: [svelte(), devServerStyles()],
  // Component tests mount Svelte in a DOM, which needs its browser build.
  resolve: process.env.VITEST ? { conditions: ["browser"] } : undefined,
  test: {
    include: ["src/**/*.test.ts"],
  },
});
