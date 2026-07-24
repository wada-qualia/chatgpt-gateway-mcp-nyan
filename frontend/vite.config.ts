import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import federation from '@originjs/vite-plugin-federation';
import { fileURLToPath, URL } from 'node:url';

const gatewayApi = process.env.VITE_GATEWAY_API ?? 'http://127.0.0.1:8000';

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
        './Monitoring': './src/features/monitoring/MonitoringRemote.tsx',
        './ActivityRegistry': './src/features/activity/ActivityRegistryRemote.tsx',
        './CollaborationRegistry': './src/features/collaboration/CollaborationRegistryRemote.tsx',
        './CoordinationRegistry': './src/features/coordination/CoordinationRegistryRemote.tsx',
        './AutonomyRegistry': './src/features/autonomy/AutonomyRegistryRemote.tsx',
        './OperationsRegistry': './src/features/operations/OperationsRegistryRemote.tsx',
        './AdministrationRegistry': './src/features/administration/AdministrationRegistryRemote.tsx',
        './ChatGPTAccess': './src/features/access/AccessRemote.tsx',
        './Audit': './src/features/audit/AuditRemote.tsx'
      },
      shared: ['react', 'react-dom', 'react-router', '@tanstack/react-query']
    })
  ],
  server: {
    port: 5173,
    host: '127.0.0.1',
    proxy: {
      '/api': gatewayApi,
      '/auth': gatewayApi,
      '/oauth': gatewayApi,
      '/mcp': gatewayApi
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
    setupFiles: ['./src/test-setup.ts'],
    exclude: ['e2e/**', 'tests/e2e/**', 'node_modules/**', 'dist/**']
  }
});
