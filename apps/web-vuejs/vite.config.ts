import path from "node:path";
import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      "/api/spa": { target: "http://localhost:8000", changeOrigin: true },
      "/api/v1": { target: "http://localhost:8000", changeOrigin: true },
      "/oauth": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
