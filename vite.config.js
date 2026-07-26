import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // Keep Google OAuth development on one stable, registered browser origin.
    host: 'localhost',
    port: 5173,
    strictPort: true,
  },
})
