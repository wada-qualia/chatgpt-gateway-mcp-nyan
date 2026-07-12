import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, expect, test, vi } from 'vitest';
import { App } from '../src/App';
import AccessRemote from '../src/features/access/AccessRemote';
import AuditRemote from '../src/features/audit/AuditRemote';
import DevicesRemote from '../src/features/devices/DevicesRemote';
import DockerWorkspacesRemote from '../src/features/docker/DockerWorkspacesRemote';
import MonitoringRemote from '../src/features/monitoring/MonitoringRemote';
import ThinClientsRemote from '../src/features/thin-clients/ThinClientsRemote';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function jsonResponse(data: unknown) {
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data))
  } as Response);
}

function mockEmptyGatewayApi() {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: [], provider: 'keycloak' });
    }
    if (url === '/api/docker/images') {
      return jsonResponse({ images: ['ubuntu:24.04'] });
    }
    if (url === '/api/thin-clients/device-code') {
      return jsonResponse({
        device_code: 'device-preissued',
        user_code: 'ABC123',
        verification_uri: 'http://localhost:8000/thin-clients/activate',
        interval: 3
      });
    }
    if (
      url === '/api/devices' ||
      url === '/api/docker/workspaces' ||
      url === '/api/thin-clients' ||
      url === '/api/command-sessions' ||
      url === '/api/access/grants' ||
      url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) {
      return jsonResponse([]);
    }
    return jsonResponse({});
  }));
}

function mockGatewayApiWithDevices(initialDevices: Array<Record<string, unknown>>) {
  let devices = initialDevices;
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: [], provider: 'keycloak' });
    }
    if (url === '/api/docker/images') {
      return jsonResponse({ images: ['ubuntu:24.04'] });
    }
    if (url === '/api/devices') {
      return jsonResponse(devices);
    }
    const deviceMatch = url.match(new RegExp('^/api/devices/([^/]+)(?:/(test))?$'));
    if (deviceMatch) {
      const [, deviceId, action] = deviceMatch;
      const device = devices.find((item) => item.id === deviceId);
      if (!device) return jsonResponse({ detail: 'Device not found' });
      if (action === 'test' && init?.method === 'POST') {
        Object.assign(device, { status: 'reachable' });
        return jsonResponse(device);
      }
      if (init?.method === 'PATCH') {
        const payload = JSON.parse(String(init.body ?? '{}')) as { name?: string; target?: string };
        if (payload.name) device.name = payload.name;
        if (payload.target) {
          const [username = '', rest = ''] = payload.target.split('@');
          const [host = '', port = '22'] = rest.split(':');
          Object.assign(device, { username, host, port: Number(port) });
        }
        return jsonResponse(device);
      }
      if (init?.method === 'DELETE') {
        devices = devices.filter((item) => item.id !== deviceId);
        return jsonResponse({ ok: true });
      }
    }
    if (
      url === '/api/docker/workspaces' ||
      url === '/api/thin-clients' ||
      url === '/api/command-sessions' ||
      url === '/api/access/grants' ||
      url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) {
      return jsonResponse([]);
    }
    return jsonResponse({});
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function mockGatewayApiWithWorkspace() {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: [], provider: 'keycloak' });
    }
    if (url === '/api/docker/images') {
      return jsonResponse({ images: ['ubuntu:24.04'] });
    }
    if (url === '/api/docker/workspaces') {
      return jsonResponse([
        {
          id: 'workspace-1',
          owner_subject: 'dev:local',
          name: 'ubuntu-lab',
          description: 'Editable lab',
          image: 'ubuntu:24.04',
          container_name: 'gw-darius-ubuntu-lab',
          container_id: '1234567890abcdef',
          status: 'running',
          source_workspace_id: null,
          created_at: '2026-07-05T00:00:00Z',
          updated_at: '2026-07-05T00:00:00Z'
        }
      ]);
    }
    if (
      url === '/api/devices' ||
      url === '/api/thin-clients' ||
      url === '/api/command-sessions' ||
      url === '/api/access/grants' ||
      url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) {
      return jsonResponse([]);
    }
    return jsonResponse({});
  }));
}

function mockGatewayApiWithThinClient() {
  let deleted = false;
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: [], provider: 'keycloak' });
    }
    if (url === '/api/docker/images') {
      return jsonResponse({ images: ['ubuntu:24.04'] });
    }
    if (url === '/api/thin-clients/thin-1' && init?.method === 'DELETE') {
      deleted = true;
      return jsonResponse({ ok: true });
    }
    if (url === '/api/thin-clients') {
      return jsonResponse(
        deleted
          ? []
          : [
              {
                id: 'thin-1',
                owner_subject: 'dev:local',
                hostname: 'MacBook-Pro-darius.local',
                directory: '/Users/darius/project',
                status: 'online',
                meta: { labels: { version: '0.2.0' } },
                created_at: '2026-07-05T00:00:00Z',
                last_seen_at: '2026-07-05T00:00:00Z'
              }
            ]
      );
    }
    if (
      url === '/api/devices' ||
      url === '/api/docker/workspaces' ||
      url === '/api/command-sessions' ||
      url === '/api/access/grants' ||
      url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) {
      return jsonResponse([]);
    }
    return jsonResponse({});
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function mockGatewayApiWithMonitoring() {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: [], provider: 'keycloak' });
    }
    if (url === '/api/docker/images') {
      return jsonResponse({ images: ['ubuntu:24.04'] });
    }
    if (url === '/api/devices') {
      return jsonResponse([
        {
          id: 'device-leak-guard',
          owner_subject: 'dev:local',
          name: 'ssh-device-detail-leak',
          kind: 'ssh',
          host: '10.0.1.66',
          port: 22,
          username: 'robot',
          auth_type: 'password',
          status: 'verified',
          created_at: '2026-07-09T00:00:00Z',
          updated_at: '2026-07-09T00:00:00Z'
        }
      ]);
    }
    if (url === '/api/command-sessions') {
      return jsonResponse([
        {
          id: 'session-1',
          owner_subject: 'dev:local',
          origin: 'thin_client',
          resource_id: 'thin-1',
          name: 'brew install',
          command: 'brew install php',
          cwd: '/Users/darius/project',
          status: 'running',
          pid: '12345',
          exit_code: null,
          line_count: 3,
          truncated: false,
          meta: {},
          created_at: '2026-07-06T00:00:00Z',
          started_at: '2026-07-06T00:00:00Z',
          completed_at: null,
          updated_at: '2026-07-06T00:00:03Z'
        },
        {
          id: 'session-ssh-1',
          owner_subject: 'dev:local',
          origin: 'ssh',
          resource_id: 'device-1',
          name: 'whoami on robot',
          command: 'whoami',
          cwd: '~',
          status: 'completed',
          pid: null,
          exit_code: 0,
          line_count: 1,
          truncated: false,
          meta: { host: '10.0.1.65', username: 'robot', action: 'whoami' },
          created_at: '2026-07-06T00:00:05Z',
          started_at: '2026-07-06T00:00:05Z',
          completed_at: '2026-07-06T00:00:06Z',
          updated_at: '2026-07-06T00:00:06Z'
        },
        ...Array.from({ length: 10 }, (_, index) => ({
          id: `session-extra-${index}`,
          owner_subject: 'dev:local',
          origin: 'thin_client',
          resource_id: 'thin-1',
          name: `extra command ${index}`,
          command: `echo ${index}`,
          cwd: '/Users/darius/project',
          status: 'completed',
          pid: null,
          exit_code: 0,
          line_count: 1,
          truncated: false,
          meta: {},
          created_at: '2026-07-06T00:00:07Z',
          started_at: '2026-07-06T00:00:07Z',
          completed_at: '2026-07-06T00:00:08Z',
          updated_at: '2026-07-06T00:00:08Z'
        }))
      ]);
    }
    if (url === '/api/command-sessions/session-1/output?tail=200') {
      return jsonResponse({
        session_id: 'session-1',
        start_line: 1,
        end_line: 3,
        total_lines: 3,
        lines: [
          { line: 1, stream: 'stdout', text: '==> Fetching php', timestamp: '2026-07-06T00:00:01Z', auto_sent: true, agent_requested: false },
          { line: 2, stream: 'stdout', text: '==> Installing dependencies', timestamp: '2026-07-06T00:00:02Z', auto_sent: false, agent_requested: true },
          { line: 3, stream: 'stderr', text: 'Warning: already installed', timestamp: '2026-07-06T00:00:03Z', auto_sent: false, agent_requested: false }
        ]
      });
    }
    if (url === '/api/command-sessions/session-1/tool-calls') {
      return jsonResponse([
        {
          id: 'tool-call-1',
          tool_name: 'thin_client_run_command',
          arguments: { command: 'brew install php' },
          status: 'success',
          session_id: 'session-1',
          error: null,
          created_at: '2026-07-06T00:00:00Z',
          completed_at: '2026-07-06T00:00:01Z'
        }
      ]);
    }
    if (url === '/api/file-changes?limit=50') {
      return jsonResponse([
        {
          id: 'change-1',
          owner_subject: 'dev:local',
          origin: 'thin_client',
          resource_id: 'thin-1',
          tool_call_id: 'tool-call-2',
          path: 'docs/policy.md',
          operation: 'replace',
          added_lines: 1,
          removed_lines: 1,
          bytes_before: 11,
          bytes_after: 15,
          replacements: 1,
          truncated: false,
          suppressed: false,
          created_at: '2026-07-06T00:00:04Z',
          diff_json: {
            format: 'unified',
            suppressed: false,
            truncated: false,
            added_lines: 1,
            removed_lines: 1,
            hunks: [
              {
                old_start: 1,
                old_count: 1,
                new_start: 1,
                new_count: 1,
                lines: [
                  { kind: 'delete', text: 'old policy' },
                  { kind: 'insert', text: 'updated policy' }
                ]
              }
            ]
          }
        }
      ]);
    }
    if (
      url === '/api/devices' ||
      url === '/api/docker/workspaces' ||
      url === '/api/thin-clients' ||
      url === '/api/access/grants' ||
      url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) {
      return jsonResponse([]);
    }
    return jsonResponse({});
  }));
}

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location-probe" hidden>{location.pathname}</span>;
}

function renderWithQuery(ui: ReactElement, route = '/devices') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  render(
    <MemoryRouter
      future={{ v7_relativeSplatPath: true, v7_startTransition: true }}
      initialEntries={[route]}
    >
      <QueryClientProvider client={queryClient}>
        {ui}
        <LocationProbe />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

test('renders operational gateway dashboard shell', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<App />);
  expect(screen.getByText('ChatGPT MCP SSH Gateway')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /^add device$/i })).toBeInTheDocument();
  expect(screen.getByText('New SSH device')).toBeInTheDocument();
  expect(await screen.findByText('No devices registered yet.')).toBeInTheDocument();
  expect(screen.queryByText('No device selected')).not.toBeInTheDocument();
});

test('dashboard root redirects to devices route', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<App />, '/');
  expect(await screen.findByRole('heading', { name: 'Devices' })).toBeInTheDocument();
  expect(screen.getByTestId('location-probe')).toHaveTextContent('/devices');
});

test('dashboard sidebar navigation updates the route', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<App />, '/devices');
  fireEvent.click(screen.getByRole('button', { name: 'Docker Workspaces' }));
  expect(screen.getByTestId('location-probe')).toHaveTextContent('/workspaces');
  expect(await screen.findByRole('heading', { name: 'Docker Workspaces' })).toBeInTheDocument();
});

test('devices remote renders only the devices page surface', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<DevicesRemote />);
  expect(screen.getByRole('heading', { name: 'Devices' })).toBeInTheDocument();
  expect(screen.getByText('New SSH device')).toBeInTheDocument();
  expect(await screen.findByText('No devices registered yet.')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('devices pagination renders only available pages', async () => {
  mockGatewayApiWithDevices([
    {
      id: 'device-1',
      owner_subject: 'dev:local',
      name: '10.0.1.65',
      kind: 'ssh',
      host: '10.0.1.65',
      port: 22,
      username: 'robot',
      auth_type: 'password',
      status: 'registered',
      created_at: '2026-07-09T00:00:00Z',
      updated_at: '2026-07-09T00:00:00Z'
    }
  ]);
  renderWithQuery(<DevicesRemote />);

  expect(await screen.findAllByText('10.0.1.65')).toHaveLength(2);
  expect(screen.getAllByText('Needs test').length).toBeGreaterThan(0);
  expect(screen.getByText('1 devices')).toBeInTheDocument();
  expect(screen.getByText('1-1 of 1')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '1' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '2' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '3' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
});

test('device detail tabs and actions are interactive', async () => {
  const fetchMock = mockGatewayApiWithDevices([
    {
      id: 'device-1',
      owner_subject: 'dev:local',
      name: '10.0.1.65',
      kind: 'ssh',
      host: '10.0.1.65',
      port: 22,
      username: 'robot',
      auth_type: 'password',
      status: 'registered',
      created_at: '2026-07-09T00:00:00Z',
      updated_at: '2026-07-09T00:00:00Z'
    }
  ]);
  renderWithQuery(<App />, '/devices');

  expect(await screen.findByRole('heading', { name: '10.0.1.65' })).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: /Workspaces/ }));
  expect(screen.getByText('No workspaces attached')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: /Thin Clients/ }));
  expect(screen.getByText('No thin clients linked')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: 'Audit' }));
  expect(screen.getByText('Device Audit')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /Test Connection/i }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/devices/device-1/test',
      expect.objectContaining({ method: 'POST' })
    );
  });

  fireEvent.click(screen.getByRole('button', { name: /Edit/i }));
  fireEvent.change(screen.getByLabelText('Device name'), { target: { value: 'renamed-box' } });
  fireEvent.change(screen.getByLabelText('SSH target'), { target: { value: 'robot@10.0.1.66:2222' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/devices/device-1',
      expect.objectContaining({ method: 'PATCH' })
    );
  });

  fireEvent.click(screen.getByRole('button', { name: /^Delete$/ }));
  const firstDialog = screen.getByRole('dialog', { name: 'Delete SSH device?' });
  expect(firstDialog).toBeInTheDocument();
  fireEvent.click(within(firstDialog).getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('dialog', { name: 'Delete SSH device?' })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /^Delete$/ }));
  const secondDialog = screen.getByRole('dialog', { name: 'Delete SSH device?' });
  fireEvent.click(within(secondDialog).getByRole('button', { name: 'Delete device' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/devices/device-1',
      expect.objectContaining({ method: 'DELETE' })
    );
  });
  await waitFor(() => {
    expect(screen.queryByText('Delete SSH device?')).not.toBeInTheDocument();
  });
  expect(screen.queryByText('No device selected')).not.toBeInTheDocument();
  expect(document.querySelector('.detail-panel')).toBeNull();
});

test('docker workspaces remote renders only the workspaces page surface', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<DockerWorkspacesRemote />);
  expect(screen.getByRole('heading', { name: 'Docker Workspaces' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /create ubuntu/i })).toBeInTheDocument();
  expect(await screen.findByText('No Docker workspaces yet.')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('monitoring remote renders paginated sessions and selected terminal output', async () => {
  mockGatewayApiWithMonitoring();
  renderWithQuery(<MonitoringRemote />);
  expect(screen.getByRole('heading', { name: 'Monitoring' })).toBeInTheDocument();
  expect(await screen.findByText('brew install')).toBeInTheDocument();
  expect(screen.getByText('12 sessions')).toBeInTheDocument();
  expect(screen.getByText('1-10 of 12')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '2' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Previous command sessions page' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Next command sessions page' })).toBeEnabled();
  expect(document.querySelector('.terminal-output-panel')).toBeNull();
  expect(screen.queryByText('==> Fetching php')).not.toBeInTheDocument();
  expect(screen.getAllByText('Thin client').length).toBeGreaterThan(0);
  expect(screen.getAllByText('SSH host').length).toBeGreaterThan(0);
  expect(screen.getByText('robot@10.0.1.65')).toBeInTheDocument();

  fireEvent.click(screen.getByText('brew install'));

  expect(await screen.findByText('==> Fetching php')).toBeInTheDocument();
  expect(document.querySelector('.terminal-output-panel')).toBeInTheDocument();
  expect(screen.getByText('auto')).toBeInTheDocument();
  expect(screen.getByText('agent')).toBeInTheDocument();
  expect(screen.getByText('thin_client_run_command')).toBeInTheDocument();
  expect(await screen.findByText('Recent file changes')).toBeInTheDocument();
  expect(screen.getByText('docs/policy.md')).toBeInTheDocument();
  expect(screen.getByText('old policy')).toBeInTheDocument();
  expect(screen.getByText('updated policy')).toBeInTheDocument();
  expect(screen.getByText('+1')).toBeInTheDocument();
  expect(screen.getByText('-1')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
  expect(screen.queryByRole('heading', { name: 'ssh-device-detail-leak' })).not.toBeInTheDocument();
  expect(document.querySelector('.detail-panel')).toBeNull();
});

test('docker workspaces surface exposes lifecycle actions', async () => {
  mockGatewayApiWithWorkspace();
  renderWithQuery(<DockerWorkspacesRemote />);
  expect(await screen.findByText('ubuntu-lab')).toBeInTheDocument();
  expect(screen.getByText('Editable lab')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /edit/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /clone/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /freeze/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
});

test('docker workspaces surface edits name and description inline', async () => {
  mockGatewayApiWithWorkspace();
  renderWithQuery(<DockerWorkspacesRemote />);
  fireEvent.click(await screen.findByRole('button', { name: /edit/i }));
  expect(document.querySelector('.workspace-edit-form')).toBeNull();
  expect(document.querySelector('.workspace-title-input')).toBeInTheDocument();
  expect(document.querySelector('.workspace-description-input')).toBeInTheDocument();
  expect(screen.queryByText('ubuntu-lab')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Workspace name')).toHaveValue('ubuntu-lab');
  expect(screen.getByLabelText('Workspace description')).toHaveValue('Editable lab');
  expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
});

test('thin clients remote renders only the thin clients page surface', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<ThinClientsRemote />);
  expect(screen.getByRole('heading', { name: 'Thin Clients' })).toBeInTheDocument();
  expect(screen.getByText(/gateway-thin-client\.sh install/)).toBeInTheDocument();
  expect(await screen.findByText('No thin clients registered yet.')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('thin clients install command is selectable and copyable', async () => {
  mockEmptyGatewayApi();
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText }
  });
  renderWithQuery(<ThinClientsRemote />);
  const command = screen.getByText(/gateway-thin-client\.sh install/);
  expect(command.closest('pre')).toHaveClass('selectable');

  fireEvent.click(screen.getByRole('button', { name: /copy thin client install command/i }));

  expect(await screen.findByRole('button', { name: /copied thin client install command/i })).toBeInTheDocument();
  expect(writeText).toHaveBeenCalledWith(expect.stringContaining('gateway-thin-client.sh install'));
});

test('thin clients surface deletes a registered client', async () => {
  const fetchMock = mockGatewayApiWithThinClient();
  renderWithQuery(<ThinClientsRemote />);

  expect(await screen.findByText('MacBook-Pro-darius.local')).toBeInTheDocument();
  expect(screen.getByText('/Users/darius/project')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /delete/i }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/thin-clients/thin-1',
      expect.objectContaining({ method: 'DELETE' })
    );
  });
  expect(await screen.findByText('No thin clients registered yet.')).toBeInTheDocument();
});

test('thin clients issue device code writes shell-safe login command', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<App />, '/thin-clients');

  fireEvent.click(screen.getByRole('button', { name: /issue device code/i }));

  const command = await screen.findByText(/--device-code 'device-preissued'/);
  expect(command).toHaveTextContent("--user-code 'ABC123'");
  expect(command).toHaveTextContent("--verification-uri 'http://localhost:8000/thin-clients/activate'");
  expect(command.textContent).not.toContain("# code");
});

test('thin clients copy command falls back when Clipboard API is denied', async () => {
  mockEmptyGatewayApi();
  const writeText = vi.fn().mockRejectedValue(new Error('denied'));
  const execCommand = vi.fn().mockReturnValue(true);
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText }
  });
  Object.defineProperty(document, 'execCommand', {
    configurable: true,
    value: execCommand
  });
  renderWithQuery(<ThinClientsRemote />);

  fireEvent.click(screen.getByRole('button', { name: /copy thin client install command/i }));

  expect(await screen.findByRole('button', { name: /copied thin client install command/i })).toBeInTheDocument();
  expect(writeText).toHaveBeenCalledWith(expect.stringContaining('gateway-thin-client.sh install'));
  expect(execCommand).toHaveBeenCalledWith('copy');
});

test('access and audit remotes render independent page surfaces', async () => {
  mockEmptyGatewayApi();
  renderWithQuery(<AccessRemote />);
  expect(screen.getByRole('heading', { name: 'ChatGPT Access' })).toBeInTheDocument();
  expect(await screen.findByText('No ChatGPT access grants yet.')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();

  cleanup();
  mockEmptyGatewayApi();
  renderWithQuery(<AuditRemote />);
  expect(screen.getByRole('heading', { name: 'Audit' })).toBeInTheDocument();
  expect(await screen.findByText('No audit events recorded yet.')).toBeInTheDocument();
  expect(screen.queryByText('ChatGPT MCP SSH Gateway')).not.toBeInTheDocument();
});

test('devices remote shows a loader while API data is pending', () => {
  vi.stubGlobal('fetch', vi.fn(() => new Promise(() => undefined)));
  renderWithQuery(<DevicesRemote />);
  expect(screen.getByText('Loading devices...')).toBeInTheDocument();
});
