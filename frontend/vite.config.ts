import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import federation from '@originjs/vite-plugin-federation';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [
    react(),
    federation({
      name: 'gateway_shell',
      filename: 'remoteEntry.js',
      exposes: {
        './Devices': './src/features/devices/DevicesRemote.tsx',
        './DockerWorkspaces': './src/features/docker/DockerWorkspacesRemote.tsx',
        './ThinClients': './src/features/thin-clients/ThinClientsRemote.tsx',
        './ChatGPTAccess': './src/features/access/AccessRemote.tsx',
        './Audit': './src/features/audit/AuditRemote.tsx'
      },
      shared: ['react', 'react-dom', '@tanstack/react-query']
    })
  ],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/auth': 'http://127.0.0.1:8000',
      '/oauth': 'http://127.0.0.1:8000',
      '/mcp': 'http://127.0.0.1:8000'
    }
  },
  resolve: {
    alias: {
      '@gateway/ui': fileURLToPath(new URL('./libs/ui/src', import.meta.url)),
      '@gateway/components': fileURLToPath(new URL('./libs/components/src', import.meta.url)),
      '@gateway/pages': fileURLToPath(new URL('./libs/pages/src', import.meta.url)),
      '@gateway/generated': fileURLToPath(new URL('./src/generated', import.meta.url)),
      '@gateway/shared': fileURLToPath(new URL('./src/shared', import.meta.url))
    }
  },
  build: {
    target: 'esnext'
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts']
  }
});
