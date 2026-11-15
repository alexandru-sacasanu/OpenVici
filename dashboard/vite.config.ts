import { defineConfig } from "vite";

// The build lands inside the Python package, which serves it as static files.
export default defineConfig({
  base: "./",
  build: {
    outDir: "../src/openvici/dashboard/static",
    emptyOutDir: true,
    target: "es2022",
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8765" },
  },
});
