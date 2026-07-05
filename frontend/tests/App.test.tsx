import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test } from 'vitest';
import { App } from '../src/App';
import AccessRemote from '../src/features/access/AccessRemote';
import AuditRemote from '../src/features/audit/AuditRemote';
import DevicesRemote from '../src/features/devices/DevicesRemote';
import DockerWorkspacesRemote from '../src/features/docker/DockerWorkspacesRemote';
import ThinClientsRemote from '../src/features/thin-clients/ThinClientsRemote';

afterEach(() => cleanup());

function renderWithQuery(ui: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  render(
    <QueryClientProvider client={queryClient}>
      {ui}
    </QueryClientProvider>
  );
}

test('renders operational gateway dashboard shell', async () => {
  renderWithQuery(<App />);
  expect(screen.getByText('ChatGPT MCP SSH Gateway')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /add ssh device/i })).toBeInTheDocument();
  expect(screen.getByText('New SSH device')).toBeInTheDocument();
});

test('devices remote renders only the devices page surface', async () => {
  renderWithQuery(<DevicesRemote />);
  expect(screen.getByRole('heading', { name: 'Devices' })).toBeInTheDocument();
  expect(screen.getByText('New SSH device')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('docker workspaces remote renders only the workspaces page surface', async () => {
  renderWithQuery(<DockerWorkspacesRemote />);
  expect(screen.getByRole('heading', { name: 'Docker Workspaces' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /create ubuntu/i })).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('thin clients remote renders only the thin clients page surface', async () => {
  renderWithQuery(<ThinClientsRemote />);
  expect(screen.getByRole('heading', { name: 'Thin Clients' })).toBeInTheDocument();
  expect(screen.getByText(/gateway_cli login/)).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('access and audit remotes render independent page surfaces', async () => {
  renderWithQuery(<AccessRemote />);
  expect(screen.getByRole('heading', { name: 'ChatGPT Access' })).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();

  cleanup();
  renderWithQuery(<AuditRemote />);
  expect(screen.getByRole('heading', { name: 'Audit' })).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});
