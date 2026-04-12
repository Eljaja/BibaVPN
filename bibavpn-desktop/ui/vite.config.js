import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  publicDir: "public",
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
  },
});
