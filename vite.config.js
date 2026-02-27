import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Redirect API calls to the backend
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
      // Redirect Socket.io calls to the backend
      '/socket.io': {
        target: 'http://localhost:3000',
        ws: true,
      },
      // Redirect uploads to the backend
      '/uploads': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      }
    }
  }
})