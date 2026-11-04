import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dev server proxies the API and WebSocket to the FastAPI backend.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    chunkSizeWarningLimit: 600, // recharts is ~550 kB on its own
    rollupOptions: {
      output: {
        manualChunks: { xterm: ["@xterm/xterm", "@xterm/addon-fit"], charts: ["recharts"] },
      },
    },
  },
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
});
