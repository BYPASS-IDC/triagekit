import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/triage': 'http://127.0.0.1:8000',
      '/scan': 'http://127.0.0.1:8000',
      '/webscan': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
    },
  },
  build: {
    outDir: '../src/triagekit/web/static/app',
    emptyOutDir: true,
  },
  base: '/app/',
})
