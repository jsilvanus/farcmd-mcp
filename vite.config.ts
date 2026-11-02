import { defineConfig } from 'vite';
export default defineConfig({
  root: 'web',
  base: './', // relative asset URLs, so the UI also works under a sub-path of MCP_PUBLIC_URL
  build: { outDir: '../dist/web', emptyOutDir: true },
  server: { port: 5173, proxy: { '/api': 'http://localhost:5999' } },
});
