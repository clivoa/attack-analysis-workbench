import { defineConfig } from 'vite'

export default defineConfig({
  root: 'src',
  base: '/attack-analysis-workbench/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    minify: 'terser',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'd3': ['d3']
        }
      }
    }
  },
  server: {
    port: 5173,
    open: true
  }
})
