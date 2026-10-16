import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("@emoji-mart/data")) return "emoji-data"
          if (id.includes("@emoji-mart/react") || id.includes("emoji-mart")) return "emoji-picker"
          if (id.includes("radix-ui") || id.includes("@radix-ui")) return "radix-ui"
          if (id.includes("react-dom") || id.includes("react-router")) return "react-vendor"
          if (id.includes("socket.io-client")) return "socket-client"
        },
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
})
