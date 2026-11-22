import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig, loadEnv, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import { buildRobotsTxt, buildSeoHeadTags, buildSitemapXml, normalizeSiteUrl } from './src/lib/seo'

// Adds the tags that need the site address to index.html and writes robots.txt and
// sitemap.xml. The address comes from VITE_SITE_URL; without it only robots.txt is written.
const seoPlugin = (siteUrl: string | null, googleVerification?: string): Plugin => ({
  name: 'chatchit-seo',
  transformIndexHtml(html) {
    const tags = buildSeoHeadTags(siteUrl, googleVerification)
    return tags ? html.replace('</head>', `    ${tags}\n  </head>`) : html
  },
  generateBundle() {
    this.emitFile({ type: 'asset', fileName: 'robots.txt', source: buildRobotsTxt(siteUrl) })
    if (siteUrl) this.emitFile({ type: 'asset', fileName: 'sitemap.xml', source: buildSitemapXml(siteUrl) })
  },
})

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const siteUrl = normalizeSiteUrl(env.VITE_SITE_URL)

  return {
    plugins: [react(), tailwindcss(), seoPlugin(siteUrl, env.VITE_GOOGLE_SITE_VERIFICATION)],
    build: {
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes("@emoji-mart/data")) return "emoji-data"
            if (id.includes("@emoji-mart/react") || id.includes("emoji-mart")) return "emoji-picker"
            if (id.includes("radix-ui") || id.includes("@radix-ui")) return "radix-ui"
            if (id.includes("react-dom") || id.includes("react-router")) return "react-vendor"
            if (id.includes("socket.io-client")) return "socket-client"
            // only loaded by the sign-in page, on wide screens
            if (id.includes("node_modules/three")) return "three"
          },
        },
      },
    },
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
  }
})
