import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dashboard talks to the TriNetra FastAPI service.
const API_TARGET = process.env.TRINETRA_API_TARGET || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Sub-path deployments (e.g. GitHub Pages at /trinetra/) set VITE_BASE at
  // build time; the Docker image and local dev keep the default "/".
  base: process.env.VITE_BASE || "/",
  server: {
    port: 5173,
    proxy: {
      "/api": { target: API_TARGET, changeOrigin: true },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});