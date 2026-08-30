import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter, useLocation } from 'react-router';
import { afterEach, expect, test, vi } from 'vitest';
import { App } from '../src/App';
import AccessRemote from '../src/features/access/AccessRemote';
import AuditRemote from '../src/features/audit/AuditRemote';
import DevicesRemote from '../src/features/devices/DevicesRemote';
import DockerWorkspacesRemote from '../src/features/docker/DockerWorkspacesRemote';
import MonitoringRemote from '../src/features/monitoring/MonitoringRemote';
import ThinClientsRemote from '../src/features/thin-clients/ThinClientsRemote';
import { GatewayTopbar } from '@gateway/components';
import i18n from '../src/shared/i18n';

afterEach(async () => {
  cleanup();
  vi.unstubAllGlobals();
  await i18n.changeLanguage('en');
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
        verification_uri: 'http://gateway.example:8000/thin-clients/activate',
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
      initialEntries={[route]}
    >
      <QueryClientProvider client={queryClient}>
        {ui}
        <LocationProbe />
      </QueryClientProvider>
    </MemoryRouter>
  );
}

test('unauthenticated topbar exposes Keycloak login action', () => {
  render(<GatewayTopbar errorMessage="Authentication required" />);
  expect(screen.getByRole('link', { name: 'Sign in with Keycloak' })).toHaveAttribute(
    'href',
    '/auth/login?next=%2F'
  );
});

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

  fireEvent.click(screen.getByRole('button', { name: 'Operations' }));
  expect(screen.getByTestId('location-probe')).toHaveTextContent('/operations');
  expect(await screen.findByRole('heading', { name: 'Operations & Reliability' })).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'User Administration' }));
  expect(screen.getByTestId('location-probe')).toHaveTextContent('/user-administration');
  expect(await screen.findByRole('heading', { name: 'User Administration' })).toBeInTheDocument();
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
  expect(screen.getByText('1 device')).toBeInTheDocument();
  expect(screen.getByText('1-1 of 1')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: '1' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '2' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: '3' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Previous page' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Next page' })).toBeDisabled();
});

test('device row action menu opens and invokes connection test and delete', async () => {
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
  vi.stubGlobal('confirm', vi.fn(() => true));
  renderWithQuery(<App />, '/devices');

  const actionsButton = await screen.findByRole('button', { name: 'Actions for 10.0.1.65' });
  fireEvent.click(actionsButton);
  let menu = screen.getByRole('menu');
  expect(within(menu).getByRole('menuitem', { name: 'View details' })).toBeInTheDocument();
  fireEvent.click(within(menu).getByRole('menuitem', { name: 'Test Connection' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/devices/device-1/test',
      expect.objectContaining({ method: 'POST' })
    );
  });

  fireEvent.click(screen.getByRole('button', { name: 'Actions for 10.0.1.65' }));
  menu = screen.getByRole('menu');
  fireEvent.click(within(menu).getByRole('menuitem', { name: 'Delete' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/devices/device-1',
      expect.objectContaining({ method: 'DELETE' })
    );
  });
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
  expect(command).toHaveTextContent("--gateway 'http://gateway.example:8000'");
  expect(command).toHaveTextContent("--user-code 'ABC123'");
  expect(command).toHaveTextContent("--verification-uri 'http://gateway.example:8000/thin-clients/activate'");
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


test('settings language dropdown switches and persists Russian UI', async () => {
  let settings = {
    ui_language: 'en',
    ssh_command_profile: 'unrestricted',
    ssh_command_profile_override: null,
    ssh_command_profile_default: 'unrestricted',
    raw_commands_enabled: true,
    deny_patterns_enabled: false
  };
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: [], provider: 'keycloak' });
    }
    if (url === '/api/account/settings') {
      if (init?.method === 'PATCH') {
        settings = { ...settings, ...JSON.parse(String(init.body ?? '{}')) };
      }
      return jsonResponse(settings);
    }
    if (url === '/api/docker/images') return jsonResponse({ images: ['ubuntu:24.04'] });
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
  });
  vi.stubGlobal('fetch', fetchMock);

  renderWithQuery(<App />, '/settings');
  const language = await screen.findByRole('combobox', { name: 'Language' });
  fireEvent.change(language, { target: { value: 'ru' } });

  expect(await screen.findByRole('heading', { name: 'Настройки' })).toBeInTheDocument();
  expect(screen.getByText('Устройства')).toBeInTheDocument();
  expect(document.documentElement.lang).toBe('ru');
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/account/settings',
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({ ui_language: 'ru' })
      })
    );
  });
});

test('MCP connections page creates a service-account backed remote server', async () => {
  let servers: Array<Record<string, unknown>> = [];
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/auth/me') {
      return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: ['gateway-admin'], provider: 'keycloak' });
    }
    if (url === '/api/docker/images') return jsonResponse({ images: ['ubuntu:24.04'] });
    if (url === '/api/mcp/servers' && init?.method === 'POST') {
      const payload = JSON.parse(String(init.body ?? '{}')) as Record<string, unknown>;
      const server = {
        id: 'mcp-server-1',
        owner_subject: 'dev:local',
        stable_slug: 'remote-build-mcp',
        display_name: payload.display_name,
        origin: 'gateway',
        transport: 'streamable_http',
        endpoint_url: payload.endpoint_url,
        credential_binding_id: payload.credential_binding_id,
        status: 'draft',
        trust_level: 'unreviewed',
        negotiated_protocol_version: null,
        capabilities: {},
        catalog_generation: 0,
        last_connected_at: null,
        last_catalog_refreshed_at: null,
        version: 1,
        created_at: '2026-07-24T00:00:00Z',
        updated_at: '2026-07-24T00:00:00Z'
      };
      servers = [server];
      return jsonResponse(server);
    }
    if (url === '/api/mcp/credential-bindings/material' && init?.method === 'POST') {
      return jsonResponse({
        id: 'binding-1', owner_subject: 'dev:local', binding_type: 'service_account',
        provider: null, secret_blob_id: 'opaque-backend-reference', audience: null, scopes: [],
        status: 'active', version: 1, meta: { mode: 'header', backend_reference: true },
        rotated_at: null, revoked_at: null, created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:00:00Z'
      });
    }
    if (url === '/api/mcp/servers') return jsonResponse(servers);
    if (
      url === '/api/devices' || url === '/api/docker/workspaces' || url === '/api/thin-clients' ||
      url === '/api/command-sessions' || url === '/api/access/grants' || url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) return jsonResponse([]);
    return jsonResponse({});
  });
  vi.stubGlobal('fetch', fetchMock);

  renderWithQuery(<App />, '/mcp-connections');
  expect(await screen.findByRole('heading', { name: 'MCP Connections' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /add MCP server/i }));
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Remote Build MCP' } });
  fireEvent.change(screen.getByLabelText('MCP endpoint'), { target: { value: 'https://mcp.example.test/mcp' } });
  fireEvent.change(screen.getByLabelText('Authorization'), { target: { value: 'header' } });
  fireEvent.change(screen.getByLabelText('Header value'), { target: { value: 'test-secret-value' } });
  fireEvent.click(screen.getByRole('button', { name: /create connection/i }));

  expect(await screen.findByText('Remote Build MCP')).toBeInTheDocument();
  expect(screen.queryByText('test-secret-value')).not.toBeInTheDocument();
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/mcp/credential-bindings/material',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('test-secret-value')
      })
    );
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/mcp/servers',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('binding-1')
      })
    );
  });
});

test('MCP connections page updates chat context mode for a URL-based OAuth client', async () => {
  const clientId = 'https://chatgpt.com/oauth/NGZjo_yePO24/client.json';
  let presentation = {
    client_id: clientId,
    client_name: 'Auto-registered MCP client',
    presentation_profile: 'chatgpt-stable',
    presentation_policy_generation: 1,
    presentation_mode: 'native_projected',
    selected_mode: 'native_projected',
    selection_reason: 'policy',
    presentation_capabilities: ['native_tools'],
    chat_context_mode: 'off',
    workspace_plan: 'none',
    allowed_tool_names: [],
    updated_at: '2026-08-30T00:00:00Z'
  };
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/auth/me') return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: ['gateway-admin'], provider: 'keycloak' });
    if (url === '/api/docker/images') return jsonResponse({ images: ['ubuntu:24.04'] });
    if (url === '/api/mcp/servers') return jsonResponse([]);
    if (url === '/api/mcp/presentation-profiles') return jsonResponse([{ id: 'chatgpt-stable', label: 'ChatGPT stable', description: 'Stable ChatGPT profile.' }]);
    if (url.startsWith('/api/mcp/projection-generations')) return jsonResponse([]);
    if (url === '/api/mcp/oauth-clients/presentation') return jsonResponse([presentation]);
    if (url === `/api/mcp/oauth-clients/${encodeURIComponent(clientId)}/presentation` && init?.method === 'PATCH') {
      const payload = JSON.parse(String(init.body ?? '{}')) as Record<string, unknown>;
      presentation = {
        ...presentation,
        ...payload,
        presentation_policy_generation: 2,
        updated_at: '2026-08-30T00:01:00Z'
      };
      return jsonResponse(presentation);
    }
    if (
      url === '/api/devices' || url === '/api/docker/workspaces' || url === '/api/thin-clients' ||
      url === '/api/command-sessions' || url === '/api/access/grants' || url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) return jsonResponse([]);
    return jsonResponse({});
  });
  vi.stubGlobal('fetch', fetchMock);

  renderWithQuery(<App />, '/mcp-connections');
  const chatContextMode = await screen.findByRole('combobox', { name: 'Chat context mode for Auto-registered MCP client' });
  expect(chatContextMode).toHaveValue('off');
  fireEvent.change(chatContextMode, { target: { value: 'optional' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save profile' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/mcp/oauth-clients/${encodeURIComponent(clientId)}/presentation`,
      expect.objectContaining({
        method: 'PATCH',
        body: JSON.stringify({
          profile_id: 'chatgpt-stable',
          presentation_mode: 'native_projected',
          presentation_capabilities: ['native_tools'],
          chat_context_mode: 'optional',
          workspace_plan: 'none',
          allowed_tool_names: []
        })
      })
    );
  });
  expect(await screen.findByText(new RegExp(`${clientId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} · policy generation 2`))).toBeInTheDocument();
  expect(screen.getByRole('combobox', { name: 'Chat context mode for Auto-registered MCP client' })).toHaveValue('optional');
});

test('MCP connections page inspects revisions and soft-removes with optimistic headers', async () => {
  const server = {
    id: 'server-1', owner_subject: 'dev:local', normalized_slug: 'remote-mcp',
    display_name: 'Remote MCP', origin: 'gateway', transport: 'streamable_http',
    endpoint_url: 'https://mcp.example.test/mcp', credential_binding_id: null,
    status: 'online', trust_level: 'unreviewed', quarantine_reason: null,
    negotiated_protocol_version: '2025-11-25', capabilities: {}, catalog_generation: 1,
    policy_generation: 1, version: 4, last_connected_at: '2026-07-24T00:00:00Z',
    last_catalog_refreshed_at: '2026-07-24T00:00:00Z', disabled_at: null,
    created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:00:00Z'
  };
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/auth/me') return jsonResponse({ subject: 'dev:local', username: 'darius', email: 'dev@k-lab.local', roles: ['gateway-admin'], provider: 'keycloak' });
    if (url === '/api/docker/images') return jsonResponse({ images: ['ubuntu:24.04'] });
    if (url === '/api/mcp/servers') return jsonResponse([server]);
    if (url === '/api/mcp/servers/server-1/tools') return jsonResponse([{
      id: 'tool-1', owner_subject: 'dev:local', server_id: 'server-1', upstream_name: 'get_build_log',
      normalized_name: 'get_build_log', lifecycle_state: 'active', current_revision_id: 'revision-1', version: 1,
      first_observed_at: '2026-07-24T00:00:00Z', last_observed_at: '2026-07-24T00:00:00Z',
      created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:00:00Z'
    }]);
    if (url === '/api/mcp/tools/tool-1/revisions') return jsonResponse([{
      id: 'revision-1', owner_subject: 'dev:local', server_id: 'server-1', tool_id: 'tool-1', revision_number: 1,
      input_schema: { type: 'object', properties: { build: { type: 'integer' } } }, output_schema: null,
      sanitized_title: 'Get build log', sanitized_description: 'Reads a bounded build log.', annotations: {},
      schema_hash: 'a'.repeat(64), protocol_version: '2025-11-25', catalog_generation: 1,
      action_class: 'read', read_only_status: 'verified', risk_evidence: {}, version: 1,
      classified_by_subject: 'dev:local', classified_at: '2026-07-24T00:00:00Z', superseded_by_revision_id: null,
      discovered_at: '2026-07-24T00:00:00Z', created_at: '2026-07-24T00:00:00Z'
    }]);
    if (url === '/api/mcp/tools/tool-1/exposure') return jsonResponse({
      id: 'exposure-1', owner_subject: 'dev:local', server_id: 'server-1', tool_id: 'tool-1', revision_id: 'revision-1',
      mode: 'catalog_only', projected_name: null, enabled: true, required_role: null, required_scope: null,
      approval_class: 'none', projection_generation: 0, policy_generation: 1, version: 1,
      reviewed_by_subject: 'dev:local', reviewed_at: '2026-07-24T00:00:00Z',
      created_at: '2026-07-24T00:00:00Z', updated_at: '2026-07-24T00:00:00Z'
    });
    if (url === '/api/mcp/servers/server-1' && init?.method === 'DELETE') return jsonResponse({ ...server, status: 'disabled', version: 5, disabled_at: '2026-07-24T00:01:00Z' });
    if (
      url === '/api/devices' || url === '/api/docker/workspaces' || url === '/api/thin-clients' ||
      url === '/api/command-sessions' || url === '/api/access/grants' || url === '/api/audit/events' ||
      url.startsWith('/api/file-changes')
    ) return jsonResponse([]);
    return jsonResponse({});
  });
  vi.stubGlobal('fetch', fetchMock);

  renderWithQuery(<App />, '/mcp-connections');
  expect(await screen.findByText('Remote MCP')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /inspect catalog/i }));
  fireEvent.click(await screen.findByRole('button', { name: /get_build_log/i }));
  expect(await screen.findByText('catalog_only / enabled')).toBeInTheDocument();
  expect(screen.getByText('verified')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /^remove$/i }));
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith('/api/mcp/servers/server-1', expect.objectContaining({
      method: 'DELETE',
      headers: expect.objectContaining({ 'If-Match': '4' })
    }));
  });
});
