import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactElement } from 'react';
import { afterEach, expect, test, vi } from 'vitest';
import {
  ActivityRegistryPage,
  AdministrationRegistryPage,
  AutonomyRegistryPage,
  CollaborationRegistryPage,
  CoordinationRegistryPage,
  OperationsRegistryPage
} from '../libs/pages/src/registryPages';

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

function renderRegistry(element: ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 }
    }
  });
  return render(
    <QueryClientProvider client={queryClient}>
      {element}
    </QueryClientProvider>
  );
}

test('renders all registry surfaces', async () => {
  vi.stubGlobal('fetch', vi.fn(() => jsonResponse({ items: [], next_cursor: null, has_more: false })));

  const views = [
    [<ActivityRegistryPage key="activity" />, 'Activity & Execution History'],
    [<CollaborationRegistryPage key="collaboration" />, 'Agent Collaboration'],
    [<CoordinationRegistryPage key="coordination" />, 'Agent Coordination'],
    [<AutonomyRegistryPage key="autonomy" />, 'Safety & Autonomy'],
    [<OperationsRegistryPage key="operations" />, 'Operations & Reliability'],
    [<AdministrationRegistryPage key="administration" />, 'User Administration']
  ] as const;

  for (const [view, heading] of views) {
    const rendered = renderRegistry(view);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    rendered.unmount();
  }
});

test('uses opaque server cursors without duplicating activity rows', async () => {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('cursor=cursor-page-2')) {
      return jsonResponse({
        items: [
          {
            id: 'session-2',
            status: 'completed',
            origin: 'ssh',
            resource_id: 'server-2',
            name: 'second page command',
            command: 'whoami',
            line_count: 1,
            updated_at: '2026-07-22T11:00:00Z'
          }
        ],
        next_cursor: null,
        has_more: false
      });
    }
    return jsonResponse({
      items: [
        {
          id: 'session-1',
          status: 'running',
          origin: 'thin_client',
          resource_id: 'client-1',
          name: 'first page command',
          command: 'npm test',
          line_count: 120,
          updated_at: '2026-07-22T12:00:00Z'
        }
      ],
      next_cursor: 'cursor-page-2',
      has_more: true
    });
  });
  vi.stubGlobal('fetch', fetchMock);

  renderRegistry(<ActivityRegistryPage />);

  expect(await screen.findByText('first page command')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /next/i }));

  expect(await screen.findByText('second page command')).toBeInTheDocument();
  expect(screen.queryByText('first page command')).not.toBeInTheDocument();
  expect(screen.getByText(/Page 2/)).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledWith(
    expect.stringContaining('cursor=cursor-page-2'),
    expect.any(Object)
  );

  fireEvent.click(screen.getByRole('button', { name: /previous/i }));
  await waitFor(() => expect(screen.getByText('first page command')).toBeInTheDocument());
});

test('switches registry tabs, sends filters and opens immutable record details', async () => {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('/collaboration/commands')) {
      return jsonResponse({
        items: [
          {
            id: 'command-1',
            status: 'pending',
            kind: 'instruction',
            issuer_agent_id: 'agent-a',
            target_agent_id: 'agent-b',
            instruction: 'Run validation',
            created_at: '2026-07-22T12:00:00Z'
          }
        ],
        next_cursor: null,
        has_more: false
      });
    }
    return jsonResponse({ items: [], next_cursor: null, has_more: false });
  });
  vi.stubGlobal('fetch', fetchMock);

  renderRegistry(<CollaborationRegistryPage />);
  fireEvent.click(screen.getByRole('tab', { name: 'Commands' }));
  expect(await screen.findByText('Run validation')).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Search Commands'), {
    target: { value: 'validation' }
  });
  fireEvent.change(screen.getByLabelText('Filter Commands by status'), {
    target: { value: 'pending' }
  });
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('search=validation'),
      expect.any(Object)
    );
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('status=pending'),
      expect.any(Object)
    );
  });

  fireEvent.click(await screen.findByText('Run validation'));
  expect(screen.getByText('Registry record')).toBeInTheDocument();
  expect(screen.getByText(/"id": "command-1"/)).toBeInTheDocument();
});

test('renders P1 operations data, delivery history and aggregate broker diagnostics', async () => {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('/operations/outbox-attempts')) {
      return jsonResponse({
        items: [
          {
            id: 'attempt-1',
            status: 'published',
            outbox_event_id: 'outbox-1',
            attempt_number: 1,
            replica_id: 'gateway-a',
            broker_sequence: 42,
            started_at: '2026-07-22T15:00:00Z'
          }
        ],
        next_cursor: null,
        has_more: false
      });
    }
    if (url.includes('/operations/broker-diagnostics')) {
      return jsonResponse({
        items: [
          {
            id: 'GATEWAY_EVENTS:gateway-a',
            stream: 'GATEWAY_EVENTS',
            consumer: 'gateway-a',
            message_count: 12,
            mode: 'aggregate-only',
            last_processed_at: '2026-07-22T15:01:00Z'
          }
        ],
        next_cursor: null,
        has_more: false
      });
    }
    return jsonResponse({
      items: [
        {
          id: 'outbox-1',
          status: 'retry',
          event_type: 'gateway.test.v1',
          owner_subject: 'dev:local',
          attempt_count: 1,
          max_attempts: 10,
          attempts: [{ id: 'attempt-1' }],
          payload: { credential: '[REDACTED]' },
          updated_at: '2026-07-22T15:00:00Z'
        }
      ],
      next_cursor: null,
      has_more: false
    });
  });
  vi.stubGlobal('fetch', fetchMock);

  renderRegistry(<OperationsRegistryPage />);
  expect(await screen.findByText('gateway.test.v1')).toBeInTheDocument();
  fireEvent.click(screen.getByText('gateway.test.v1'));
  expect(screen.getByText(/\[REDACTED\]/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: 'Delivery attempts' }));
  expect(await screen.findByText('gateway-a')).toBeInTheDocument();
  expect(screen.getByText('42')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: 'Broker diagnostics' }));
  expect(await screen.findByText('aggregate-only')).toBeInTheDocument();
  expect(screen.getByText('12')).toBeInTheDocument();
});

test('renders safe administration metadata and provider filtering', async () => {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('/administration/oauth-clients')) {
      return jsonResponse({
        items: [
          {
            id: 'client-1',
            client_id: 'client-1',
            client_name: 'ChatGPT Connector',
            redirect_uris: ['https://chat.openai.com/aip/callback'],
            scopes: ['workspace:read'],
            created_at: '2026-07-22T16:00:00Z'
          }
        ],
        next_cursor: null,
        has_more: false
      });
    }
    return jsonResponse({
      items: [
        {
          id: 'keycloak:operator',
          username: 'operator',
          subject: 'keycloak:operator',
          email: 'operator@example.test',
          provider: 'keycloak',
          roles: ['gateway-user', 'gateway-auditor'],
          last_seen_at: '2026-07-22T16:00:00Z'
        }
      ],
      next_cursor: null,
      has_more: false
    });
  });
  vi.stubGlobal('fetch', fetchMock);

  renderRegistry(<AdministrationRegistryPage />);
  expect(await screen.findByText('operator@example.test')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Filter Users by provider'), {
    target: { value: 'keycloak' }
  });
  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('provider=keycloak'),
      expect.any(Object)
    );
  });

  fireEvent.click(screen.getByRole('tab', { name: 'OAuth clients' }));
  expect(await screen.findByText('ChatGPT Connector')).toBeInTheDocument();
  expect(screen.getByText('workspace:read')).toBeInTheDocument();
});
