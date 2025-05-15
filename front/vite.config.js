import { defineConfig } from 'vite'
import fs from 'fs'
import path from 'path'

export default defineConfig({
  optimizeDeps: {
    include: ['pkijs', 'asn1js', 'pvutils']
  },
  server: {
    port: 3001,
    https: {
    key: fs.readFileSync(path.resolve(__dirname, './tls/privateFront.key')),
    cert: fs.readFileSync(path.resolve(__dirname, './tls/certificateFront.crt')),
    ca: fs.readFileSync(path.resolve(__dirname, './tls/ca.crt'))
  },
    proxy: {
      '/api': {
        target: 'https://localhost:8081',
        changeOrigin: true,
      }
    }
  }
})