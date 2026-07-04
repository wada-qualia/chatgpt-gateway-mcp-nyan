import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import federation from '@originjs/vite-plugin-federation';

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
  build: {
    target: 'esnext'
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test-setup.ts']
  }
});
