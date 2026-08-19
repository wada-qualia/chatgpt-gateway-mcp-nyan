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


test('renders semantic approval review and submits a canonical vote only after confirmation', async () => {
  let voted = false;
  const baseApproval = {
    id: 'approval-1',
    status: 'pending',
    action_kind: 'deploy',
    action_class: 'production',
    tool: 'ssh_device_run_command',
    command_profile: 'deploy',
    created_by_subject: 'keycloak:operator',
    proposer_agent_id: 'agent-proposer',
    executor_agent_id: 'agent-executor',
    policy_id: 'policy-1',
    policy_generation: 9,
    command_id: 'command-1',
    work_item_id: 'work-1',
    integration_id: null,
    payload_summary: { target: 'service-a' },
    quorum_required: 2,
    require_admin_approval: true,
    expires_at: '2026-08-19T12:00:00Z',
    created_at: '2026-08-18T12:00:00Z',
    updated_at: '2026-08-18T12:00:00Z',
    votes: [],
    review: {
      surface: 'gateway',
      authorized: true,
      can_vote: true,
      reason: null,
      current_voter_decision: null,
      approve_count: 0,
      reject_count: 0,
      quorum_required: 2,
      quorum_met: false,
      admin_required: true,
      admin_approve_count: 0,
      expired: false,
      target: { kind: 'gateway', review_surface: 'gateway' }
    }
  };
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('/api/agent-autonomy/approvals/approval-1/votes')) {
      expect(init?.method).toBe('POST');
      expect(init?.body).toBe(JSON.stringify({ decision: 'approve', reason: 'Reviewed by operator' }));
      voted = true;
      return jsonResponse({
        ...baseApproval,
        votes: [
          {
            id: 'vote-1',
            voter_subject: 'keycloak:reviewer',
            decision: 'approve',
            reason: 'Reviewed by operator',
            created_at: '2026-08-18T12:05:00Z'
          }
        ],
        review: {
          ...baseApproval.review,
          can_vote: false,
          reason: 'Current reviewer already voted',
          current_voter_decision: 'approve',
          approve_count: 1
        }
      });
    }
    if (url.includes('/api/registry/autonomy/approvals')) {
      return jsonResponse({
        items: [
          voted
            ? {
                ...baseApproval,
                votes: [
                  {
                    id: 'vote-1',
                    voter_subject: 'keycloak:reviewer',
                    decision: 'approve',
                    reason: 'Reviewed by operator',
                    created_at: '2026-08-18T12:05:00Z'
                  }
                ],
                review: {
                  ...baseApproval.review,
                  can_vote: false,
                  reason: 'Current reviewer already voted',
                  current_voter_decision: 'approve',
                  approve_count: 1
                }
              }
            : baseApproval
        ],
        next_cursor: null,
        has_more: false
      });
    }
    return jsonResponse({ items: [], next_cursor: null, has_more: false });
  });
  vi.stubGlobal('fetch', fetchMock);

  renderRegistry(<AutonomyRegistryPage />);
  fireEvent.click(await screen.findByText('deploy'));

  expect(screen.getByText('Record details')).toBeInTheDocument();
  expect(screen.getByText('Review state')).toBeInTheDocument();
  expect(screen.getByText('Immutable target')).toBeInTheDocument();
  expect(screen.getByText('Raw record')).toBeInTheDocument();
  expect(screen.getByText('Required quorum')).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('Decision reason (optional)'), {
    target: { value: 'Reviewed by operator' }
  });
  fireEvent.click(screen.getByRole('button', { name: 'Approve' }));

  expect(fetchMock).not.toHaveBeenCalledWith(
    '/api/agent-autonomy/approvals/approval-1/votes',
    expect.any(Object)
  );
  expect(screen.getByRole('alertdialog', { name: 'Confirm approve' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Confirm approve' }));

  await waitFor(() => {
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/agent-autonomy/approvals/approval-1/votes',
      expect.objectContaining({ method: 'POST' })
    );
  });
  expect((await screen.findAllByText('Current reviewer already voted')).length).toBeGreaterThan(0);
});

test('routes AFFiNE approvals to native notifications without gateway decision controls', async () => {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('/api/registry/autonomy/approvals')) {
      return jsonResponse({
        items: [
          {
            id: 'approval-affine-1',
            status: 'pending',
            action_kind: 'update_document',
            action_class: 'write',
            tool: 'research_update_document',
            command_profile: null,
            quorum_required: 1,
            require_admin_approval: false,
            expires_at: '2026-08-19T12:00:00Z',
            created_at: '2026-08-18T12:00:00Z',
            updated_at: '2026-08-18T12:00:00Z',
            votes: [],
            review: {
              surface: 'affine',
              authorized: true,
              can_vote: false,
              reason: 'AFFiNE-targeted approvals are reviewed in AFFiNE Notifications',
              current_voter_decision: null,
              approve_count: 0,
              reject_count: 0,
              quorum_required: 1,
              quorum_met: false,
              admin_required: false,
              admin_approve_count: 0,
              expired: false,
              target: {
                kind: 'mcp_federation',
                provider: 'affine',
                review_surface: 'affine',
                preparation_id: 'prep-1',
                server_id: 'server-1',
                tool_id: 'tool-1',
                revision_id: 'revision-1',
                server_name: 'AFFiNE Research Knowledge Provider',
                tool_name: 'research_update_document'
              }
            }
          }
        ],
        next_cursor: null,
        has_more: false
      });
    }
    return jsonResponse({ items: [], next_cursor: null, has_more: false });
  });
  vi.stubGlobal('fetch', fetchMock);

  renderRegistry(<AutonomyRegistryPage />);
  fireEvent.click(await screen.findByText('update_document'));

  expect(screen.getAllByText(/reviewed in AFFiNE Notifications/).length).toBeGreaterThan(0);
  expect(screen.getByText('prep-1')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument();
});
