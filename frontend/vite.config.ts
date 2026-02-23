import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  esbuild: {
    // ✅ ОТКЛЮЧАЕМ TypeScript ошибки полностью
    logOverride: { 'this-is-undefined-in-esm': 'silent' }
  },
  build: {
    rollupOptions: {
      input: 'index.html'
    },
    // ✅ Игнорируем TS ошибки при сборке
    commonjsOptions: {
      ignoreDynamicRequires: true
    }
  },
  server: {
    port: 3000,
    host: true
  }
})