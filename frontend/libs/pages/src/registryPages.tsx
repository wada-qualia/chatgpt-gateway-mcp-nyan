import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ChevronLeft, ChevronRight, RefreshCw, Search } from 'lucide-react';
import { Button, SearchField, StatusPill, TableFrame } from '@gateway/ui';
import {
  registryApi,
  type CursorPage,
  type RegistryQuery,
  type RegistryRecord
} from '@gateway/generated/registry-client';

export type RegistrySurfaceId = 'activity' | 'collaboration' | 'coordination' | 'autonomy' | 'operations' | 'administration';

type RegistryColumn = {
  key: string;
  label: string;
  render: (record: RegistryRecord) => ReactNode;
};

type RegistryTab = {
  id: string;
  label: string;
  path: string;
  emptyMessage: string;
  columns: RegistryColumn[];
  searchParam?: string;
  statusParam?: string;
};

type RegistrySurface = {
  title: string;
  description: string;
  tabs: RegistryTab[];
};

const activityTabs: RegistryTab[] = [
  {
    id: 'sessions',
    label: 'Command sessions',
    path: 'activity/sessions',
    emptyMessage: 'No command sessions recorded.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('origin', 'Origin'),
      textColumn('resource_id', 'Resource'),
      primaryColumn('name', 'command', 'Command'),
      numberColumn('line_count', 'Lines'),
      dateColumn('updated_at', 'Updated')
    ]
  },
  {
    id: 'tool-calls',
    label: 'Tool calls',
    path: 'activity/tool-calls',
    emptyMessage: 'No agent tool calls recorded.',
    searchParam: 'tool_name',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('tool_name', 'Tool'),
      textColumn('session_id', 'Session'),
      textColumn('error', 'Error'),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'deliveries',
    label: 'Output deliveries',
    path: 'activity/deliveries',
    emptyMessage: 'No output delivery records.',
    statusParam: 'reason',
    columns: [
      textColumn('reason', 'Reason'),
      textColumn('session_id', 'Session'),
      rangeColumn(),
      textColumn('tool_call_id', 'Tool call'),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'file-changes',
    label: 'File changes',
    path: 'activity/file-changes',
    emptyMessage: 'No file changes recorded.',
    statusParam: 'operation',
    columns: [
      textColumn('operation', 'Operation'),
      textColumn('path', 'Path'),
      textColumn('origin', 'Origin'),
      diffColumn(),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'audit',
    label: 'Audit events',
    path: 'activity/audit-events',
    emptyMessage: 'No audit events recorded.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('event_type', 'Event'),
      textColumn('actor_subject', 'Actor'),
      resourceColumn(),
      dateColumn('created_at', 'Created')
    ]
  }
];

const collaborationTabs: RegistryTab[] = [
  {
    id: 'rooms',
    label: 'Rooms',
    path: 'collaboration/rooms',
    emptyMessage: 'No collaboration rooms.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('title', 'Room'),
      textColumn('repository_identity', 'Repository'),
      textColumn('project_path', 'Project path'),
      dateColumn('updated_at', 'Updated')
    ]
  },
  {
    id: 'agents',
    label: 'Agents',
    path: 'collaboration/agents',
    emptyMessage: 'No registered agents.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('display_name', 'Agent'),
      textColumn('logical_agent_id', 'Logical ID'),
      textColumn('current_room_id', 'Room'),
      dateColumn('last_heartbeat_at', 'Heartbeat')
    ]
  },
  {
    id: 'messages',
    label: 'Messages',
    path: 'collaboration/messages',
    emptyMessage: 'No agent messages.',
    searchParam: 'search',
    statusParam: 'kind',
    columns: [
      textColumn('kind', 'Kind'),
      textColumn('sender_agent_id', 'Sender'),
      textColumn('recipient_agent_id', 'Recipient'),
      primaryColumn('body', 'id', 'Message'),
      countColumn('deliveries', 'Deliveries'),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'commands',
    label: 'Commands',
    path: 'collaboration/commands',
    emptyMessage: 'No agent commands.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('kind', 'Kind'),
      textColumn('issuer_agent_id', 'Issuer'),
      textColumn('target_agent_id', 'Target'),
      primaryColumn('instruction', 'id', 'Instruction'),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'work-items',
    label: 'Work items',
    path: 'collaboration/work-items',
    emptyMessage: 'No work items.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('title', 'Work item'),
      textColumn('assigned_agent_id', 'Assigned agent'),
      numberColumn('priority', 'Priority'),
      numberColumn('version', 'Version'),
      dateColumn('updated_at', 'Updated')
    ]
  }
];

const coordinationTabs: RegistryTab[] = [
  {
    id: 'leases',
    label: 'Resource leases',
    path: 'coordination/leases',
    emptyMessage: 'No resource leases.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('holder_agent_id', 'Holder'),
      textColumn('resource_id', 'Resource'),
      countColumn('reservations', 'Reservations'),
      numberColumn('fencing_token', 'Fence'),
      dateColumn('expires_at', 'Expires')
    ]
  },
  {
    id: 'handoffs',
    label: 'Handoffs',
    path: 'coordination/handoffs',
    emptyMessage: 'No handoff barriers.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('source_agent_id', 'Source'),
      textColumn('target_agent_id', 'Target'),
      textColumn('lease_id', 'Lease'),
      textColumn('summary', 'Summary'),
      dateColumn('updated_at', 'Updated')
    ]
  },
  {
    id: 'integrations',
    label: 'Integrations',
    path: 'coordination/integrations',
    emptyMessage: 'No integration records.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('target_branch', 'Target branch'),
      textColumn('coordinator_agent_id', 'Coordinator'),
      countColumn('candidate_change_ids', 'Candidates'),
      numberColumn('version', 'Version'),
      dateColumn('updated_at', 'Updated')
    ]
  }
];

const autonomyTabs: RegistryTab[] = [
  {
    id: 'approvals',
    label: 'Approvals',
    path: 'autonomy/approvals',
    emptyMessage: 'No approval requests.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('action_kind', 'Action'),
      textColumn('tool', 'Tool'),
      textColumn('executor_agent_id', 'Executor'),
      quorumColumn(),
      dateColumn('expires_at', 'Expires')
    ]
  },
  {
    id: 'permits',
    label: 'Execution permits',
    path: 'autonomy/permits',
    emptyMessage: 'No execution permits.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('tool', 'Tool'),
      textColumn('executor_agent_id', 'Executor'),
      usageColumn(),
      numberColumn('fencing_token', 'Fence'),
      dateColumn('expires_at', 'Expires')
    ]
  },
  {
    id: 'receipts',
    label: 'Action receipts',
    path: 'autonomy/receipts',
    emptyMessage: 'No action receipts.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('tool', 'Tool'),
      textColumn('executor_agent_id', 'Executor'),
      textColumn('command_id', 'Command'),
      textColumn('error', 'Error'),
      dateColumn('completed_at', 'Completed')
    ]
  },
  {
    id: 'policies',
    label: 'Policies',
    path: 'autonomy/policies',
    emptyMessage: 'No autonomy policies.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('name', 'Policy'),
      textColumn('assignment_mode', 'Assignment'),
      numberColumn('max_parallel_assignments', 'Parallel'),
      numberColumn('generation', 'Generation'),
      dateColumn('updated_at', 'Updated')
    ]
  },
  {
    id: 'controls',
    label: 'Controls',
    path: 'autonomy/controls',
    emptyMessage: 'No autonomy controls.',
    statusParam: 'state',
    columns: [
      stateColumn(),
      textColumn('scope_type', 'Scope type'),
      textColumn('scope_id', 'Scope'),
      numberColumn('generation', 'Generation'),
      textColumn('reason', 'Reason'),
      dateColumn('updated_at', 'Updated')
    ]
  },
  {
    id: 'assignments',
    label: 'Assignments',
    path: 'autonomy/assignments',
    emptyMessage: 'No autonomy assignments.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('work_item_id', 'Work item'),
      textColumn('selected_agent_id', 'Agent'),
      numberColumn('score', 'Score'),
      numberColumn('policy_generation', 'Policy generation'),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'recoveries',
    label: 'Recovery loops',
    path: 'autonomy/recoveries',
    emptyMessage: 'No recovery loops.',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('source_type', 'Source'),
      textColumn('target_agent_id', 'Target'),
      attemptsColumn(),
      textColumn('last_error', 'Last error'),
      dateColumn('next_attempt_at', 'Next attempt')
    ]
  },
  {
    id: 'overrides',
    label: 'Overrides',
    path: 'autonomy/overrides',
    emptyMessage: 'No operator overrides.',
    statusParam: 'action',
    columns: [
      textColumn('action', 'Action'),
      textColumn('scope_type', 'Scope type'),
      textColumn('scope_id', 'Scope'),
      textColumn('actor_subject', 'Actor'),
      textColumn('reason', 'Reason'),
      dateColumn('created_at', 'Created')
    ]
  }
];


const operationsTabs: RegistryTab[] = [
  {
    id: 'outbox',
    label: 'Outbox events',
    path: 'operations/outbox',
    emptyMessage: 'No outbox events.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('event_type', 'Event'),
      textColumn('owner_subject', 'Owner'),
      deliveryBudgetColumn(),
      countColumn('attempts', 'Delivery history'),
      dateColumn('updated_at', 'Updated')
    ]
  },
  {
    id: 'outbox-attempts',
    label: 'Delivery attempts',
    path: 'operations/outbox-attempts',
    emptyMessage: 'No outbox delivery attempts.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('outbox_event_id', 'Outbox event'),
      numberColumn('attempt_number', 'Attempt'),
      textColumn('replica_id', 'Replica'),
      numberColumn('broker_sequence', 'Broker sequence'),
      textColumn('error', 'Error'),
      dateColumn('started_at', 'Started')
    ]
  },
  {
    id: 'replicas',
    label: 'Gateway replicas',
    path: 'operations/replicas',
    emptyMessage: 'No gateway replicas registered.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('id', 'Replica'),
      textColumn('hostname', 'Host'),
      numberColumn('process_id', 'PID'),
      dateColumn('last_heartbeat_at', 'Heartbeat'),
      dateColumn('expires_at', 'Expires')
    ]
  },
  {
    id: 'routes',
    label: 'Realtime routes',
    path: 'operations/realtime-routes',
    emptyMessage: 'No realtime routes.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('target_kind', 'Target kind'),
      textColumn('target_id', 'Target'),
      textColumn('replica_id', 'Replica'),
      textColumn('connection_id', 'Connection'),
      dateColumn('last_seen_at', 'Last seen')
    ]
  },
  {
    id: 'notifications',
    label: 'Notifications',
    path: 'operations/notifications',
    emptyMessage: 'No realtime notifications.',
    searchParam: 'search',
    statusParam: 'status',
    columns: [
      statusColumn(),
      textColumn('event_type', 'Event'),
      textColumn('target_id', 'Target'),
      textColumn('replica_id', 'Replica'),
      numberColumn('attempt_count', 'Attempts'),
      dateColumn('created_at', 'Created')
    ]
  },
  {
    id: 'broker-diagnostics',
    label: 'Broker diagnostics',
    path: 'operations/broker-diagnostics',
    emptyMessage: 'No broker deduplication diagnostics.',
    searchParam: 'search',
    columns: [
      textColumn('stream', 'Stream'),
      textColumn('consumer', 'Consumer'),
      numberColumn('message_count', 'Processed messages'),
      textColumn('mode', 'Exposure'),
      dateColumn('last_processed_at', 'Last processed')
    ]
  }
];

const administrationTabs: RegistryTab[] = [
  {
    id: 'users',
    label: 'Users',
    path: 'administration/users',
    emptyMessage: 'No gateway users.',
    searchParam: 'search',
    statusParam: 'provider',
    columns: [
      textColumn('username', 'User'),
      textColumn('subject', 'Subject'),
      textColumn('email', 'Email'),
      textColumn('provider', 'Provider'),
      textColumn('roles', 'Roles'),
      dateColumn('last_seen_at', 'Last seen')
    ]
  },
  {
    id: 'oauth-clients',
    label: 'OAuth clients',
    path: 'administration/oauth-clients',
    emptyMessage: 'No OAuth clients.',
    searchParam: 'search',
    columns: [
      textColumn('client_name', 'Client'),
      textColumn('client_id', 'Client ID'),
      countColumn('redirect_uris', 'Redirect URIs'),
      textColumn('scopes', 'Scopes'),
      dateColumn('created_at', 'Created')
    ]
  }
];

const surfaces: Record<RegistrySurfaceId, RegistrySurface> = {
  activity: {
    title: 'Activity & Execution History',
    description: 'Paginated execution, delivery, file-change and audit evidence across gateway resources.',
    tabs: activityTabs
  },
  collaboration: {
    title: 'Agent Collaboration',
    description: 'Durable rooms, agents, messages, commands and work items.',
    tabs: collaborationTabs
  },
  coordination: {
    title: 'Agent Coordination',
    description: 'Resource ownership, fencing, handoff barriers and integration decisions.',
    tabs: coordinationTabs
  },
  autonomy: {
    title: 'Safety & Autonomy',
    description: 'Policies, approvals, permits, receipts, recovery and operator control evidence.',
    tabs: autonomyTabs
  },
  operations: {
    title: 'Operations & Reliability',
    description: 'Outbox delivery, broker deduplication, gateway replicas and realtime routing evidence.',
    tabs: operationsTabs
  },
  administration: {
    title: 'User Administration',
    description: 'Administrator-only gateway identities, roles, providers and safe OAuth client metadata.',
    tabs: administrationTabs
  }
};

export function ActivityRegistryPage() {
  return <RegistryPage surfaceId="activity" />;
}

export function CollaborationRegistryPage() {
  return <RegistryPage surfaceId="collaboration" />;
}

export function CoordinationRegistryPage() {
  return <RegistryPage surfaceId="coordination" />;
}

export function AutonomyRegistryPage() {
  return <RegistryPage surfaceId="autonomy" />;
}

export function OperationsRegistryPage() {
  return <RegistryPage surfaceId="operations" />;
}

export function AdministrationRegistryPage() {
  return <RegistryPage surfaceId="administration" />;
}

function RegistryPage({ surfaceId }: { surfaceId: RegistrySurfaceId }) {
  const surface = surfaces[surfaceId];
  const [activeTabId, setActiveTabId] = useState(surface.tabs[0].id);
  const [draftSearch, setDraftSearch] = useState('');
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [cursorStack, setCursorStack] = useState<Array<string | null>>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [selectedId, setSelectedId] = useState('');
  const activeTab = surface.tabs.find((tab) => tab.id === activeTabId) ?? surface.tabs[0];
  const currentCursor = cursorStack[pageIndex] ?? null;
  const params = useMemo<RegistryQuery>(() => {
    const result: RegistryQuery = { limit: 25, cursor: currentCursor };
    if (activeTab.searchParam && search) result[activeTab.searchParam] = search;
    if (activeTab.statusParam && status) result[activeTab.statusParam] = status;
    return result;
  }, [activeTab, currentCursor, search, status]);
  const query = useQuery({
    queryKey: ['registry', surfaceId, activeTab.path, params],
    queryFn: () => registryApi.list(activeTab.path, params),
    refetchInterval: surfaceId === 'activity' ? 5000 : false
  });
  const page = query.data ?? emptyPage;
  const selected = page.items.find((item) => item.id === selectedId) ?? null;

  useEffect(() => {
    setDraftSearch('');
    setSearch('');
    setStatus('');
  }, [activeTabId]);

  useEffect(() => {
    setCursorStack([null]);
    setPageIndex(0);
    setSelectedId('');
  }, [activeTabId, search, status]);

  useEffect(() => {
    if (selectedId && !page.items.some((item) => item.id === selectedId)) {
      setSelectedId('');
    }
  }, [page.items, selectedId]);

  function nextPage() {
    if (!page.next_cursor) return;
    const nextStack = cursorStack.slice(0, pageIndex + 1);
    nextStack.push(page.next_cursor);
    setCursorStack(nextStack);
    setPageIndex(pageIndex + 1);
    setSelectedId('');
  }

  return (
    <div className="subview registry-page">
      <div className="section-title registry-heading">
        <div>
          <h1>{surface.title}</h1>
          <p>{surface.description}</p>
        </div>
        <Button onClick={() => query.refetch()} type="button">
          <RefreshCw size={16} /> Refresh
        </Button>
      </div>
      <div className="registry-tabs" role="tablist" aria-label={`${surface.title} registries`}>
        {surface.tabs.map((tab) => (
          <Button
            aria-selected={activeTab.id === tab.id}
            className={activeTab.id === tab.id ? 'active' : ''}
            key={tab.id}
            onClick={() => setActiveTabId(tab.id)}
            role="tab"
            type="button"
          >
            {tab.label}
          </Button>
        ))}
      </div>
      <form
        className="registry-filters"
        onSubmit={(event) => {
          event.preventDefault();
          setSearch(draftSearch.trim());
        }}
      >
        <SearchField
          aria-label={`Search ${activeTab.label}`}
          disabled={!activeTab.searchParam}
          icon={<Search size={18} />}
          onChange={setDraftSearch}
          placeholder={activeTab.searchParam ? `Search ${activeTab.label.toLowerCase()}` : 'Search unavailable for this registry'}
          value={draftSearch}
        />
        <input
          aria-label={`Filter ${activeTab.label} by ${activeTab.statusParam ?? 'status'}`}
          disabled={!activeTab.statusParam}
          onChange={(event) => setStatus(event.target.value.trim())}
          placeholder={activeTab.statusParam ? `Filter by ${activeTab.statusParam.replace('_', ' ')}` : 'Status filter unavailable'}
          value={status}
        />
        <Button disabled={!activeTab.searchParam} type="submit">Apply</Button>
        <Button
          onClick={() => {
            setDraftSearch('');
            setSearch('');
            setStatus('');
          }}
          type="button"
        >
          Clear
        </Button>
      </form>
      <div className={`registry-content ${selected ? 'has-detail' : ''}`}>
        <div className="registry-table-panel">
          <RegistryTable
            columns={activeTab.columns}
            emptyMessage={activeTab.emptyMessage}
            error={query.error}
            isLoading={query.isPending}
            items={page.items}
            onSelect={setSelectedId}
            selectedId={selectedId}
          />
          <div className="registry-pager">
            <span>Page {pageIndex + 1} · {page.items.length} records</span>
            <div>
              <Button disabled={pageIndex === 0} onClick={() => setPageIndex(pageIndex - 1)} type="button">
                <ChevronLeft size={16} /> Previous
              </Button>
              <Button disabled={!page.has_more || !page.next_cursor} onClick={nextPage} type="button">
                Next <ChevronRight size={16} />
              </Button>
            </div>
          </div>
        </div>
        {selected ? (
          <RegistryDetail
            activeTabId={activeTab.id}
            onClose={() => setSelectedId('')}
            onRefresh={async () => {
              await query.refetch();
            }}
            record={selected}
            surfaceId={surfaceId}
          />
        ) : null}
      </div>
    </div>
  );
}

function RegistryTable({
  columns,
  emptyMessage,
  error,
  isLoading,
  items,
  onSelect,
  selectedId
}: {
  columns: RegistryColumn[];
  emptyMessage: string;
  error: unknown;
  isLoading: boolean;
  items: RegistryRecord[];
  onSelect: (id: string) => void;
  selectedId: string;
}) {
  return (
    <TableFrame compact>
      <table className="registry-table">
        <thead>
          <tr>{columns.map((column) => <th key={column.key}>{column.label}</th>)}</tr>
        </thead>
        <tbody>
          {isLoading ? (
            <RegistryNotice colSpan={columns.length} text="Loading registry..." />
          ) : error ? (
            <RegistryNotice colSpan={columns.length} text={errorMessage(error)} />
          ) : items.length === 0 ? (
            <RegistryNotice colSpan={columns.length} text={emptyMessage} />
          ) : (
            items.map((item) => (
              <tr
                className={selectedId === item.id ? 'selected-row' : ''}
                key={item.id}
                onClick={() => onSelect(item.id)}
              >
                {columns.map((column) => <td key={column.key}>{column.render(item)}</td>)}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </TableFrame>
  );
}

function RegistryNotice({ colSpan, text }: { colSpan: number; text: string }) {
  return <tr><td className="registry-notice" colSpan={colSpan}>{text}</td></tr>;
}

function RegistryDetail({
  activeTabId,
  onClose,
  onRefresh,
  record,
  surfaceId
}: {
  activeTabId: string;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  record: RegistryRecord;
  surfaceId: RegistrySurfaceId;
}) {
  if (surfaceId === 'autonomy') {
    return (
      <AutonomyRegistryDetail
        activeTabId={activeTabId}
        onClose={onClose}
        onRefresh={onRefresh}
        record={record}
      />
    );
  }
  return (
    <aside className="registry-detail">
      <RegistryDetailHeader onClose={onClose} record={record} title="Registry record" />
      <pre className="selectable"><code>{JSON.stringify(record, null, 2)}</code></pre>
    </aside>
  );
}

function RegistryDetailHeader({
  onClose,
  record,
  title
}: {
  onClose: () => void;
  record: RegistryRecord;
  title: string;
}) {
  return (
    <header>
      <div>
        <strong>{title}</strong>
        <span>{record.id}</span>
      </div>
      <Button onClick={onClose} type="button">Close</Button>
    </header>
  );
}

type SemanticField = {
  key: string;
  label: string;
};

const autonomySemanticFields: Record<string, SemanticField[]> = {
  approvals: [
    { key: 'status', label: 'Status' },
    { key: 'action_kind', label: 'Action' },
    { key: 'action_class', label: 'Risk class' },
    { key: 'tool', label: 'Tool' },
    { key: 'command_profile', label: 'Command profile' },
    { key: 'created_by_subject', label: 'Initiator subject' },
    { key: 'proposer_agent_id', label: 'Proposer agent' },
    { key: 'executor_agent_id', label: 'Executor agent' },
    { key: 'policy_id', label: 'Policy' },
    { key: 'policy_generation', label: 'Policy generation' },
    { key: 'command_id', label: 'Command' },
    { key: 'work_item_id', label: 'Work item' },
    { key: 'integration_id', label: 'Integration' },
    { key: 'payload_summary', label: 'Bounded summary' },
    { key: 'expires_at', label: 'Expires' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' }
  ],
  permits: [
    { key: 'status', label: 'Status' },
    { key: 'action_class', label: 'Risk class' },
    { key: 'tool', label: 'Tool' },
    { key: 'command_profile', label: 'Command profile' },
    { key: 'approval_request_id', label: 'Approval request' },
    { key: 'policy_id', label: 'Policy' },
    { key: 'policy_generation', label: 'Policy generation' },
    { key: 'command_id', label: 'Command' },
    { key: 'executor_agent_id', label: 'Executor agent' },
    { key: 'fencing_token', label: 'Fencing token' },
    { key: 'max_uses', label: 'Maximum uses' },
    { key: 'use_count', label: 'Current uses' },
    { key: 'issued_by_subject', label: 'Issued by' },
    { key: 'issued_at', label: 'Issued' },
    { key: 'expires_at', label: 'Expires' },
    { key: 'claimed_at', label: 'Claimed' },
    { key: 'consumed_at', label: 'Consumed' },
    { key: 'revoked_at', label: 'Revoked' },
    { key: 'revocation_reason', label: 'Revocation reason' },
    { key: 'control_snapshot', label: 'Control snapshot' }
  ],
  receipts: [
    { key: 'status', label: 'Status' },
    { key: 'action_class', label: 'Risk class' },
    { key: 'tool', label: 'Tool' },
    { key: 'command_profile', label: 'Command profile' },
    { key: 'approval_request_id', label: 'Approval request' },
    { key: 'permit_id', label: 'Permit' },
    { key: 'command_id', label: 'Command' },
    { key: 'executor_agent_id', label: 'Executor agent' },
    { key: 'result_summary', label: 'Result summary' },
    { key: 'error', label: 'Error' },
    { key: 'external_references', label: 'External references' },
    { key: 'started_at', label: 'Started' },
    { key: 'completed_at', label: 'Completed' }
  ],
  policies: [
    { key: 'name', label: 'Policy' },
    { key: 'status', label: 'Status' },
    { key: 'room_id', label: 'Room' },
    { key: 'assignment_mode', label: 'Assignment mode' },
    { key: 'coordinator_agent_id', label: 'Coordinator agent' },
    { key: 'allowed_action_classes', label: 'Allowed action classes' },
    { key: 'allowed_tools', label: 'Allowed tools' },
    { key: 'allowed_command_profiles', label: 'Allowed command profiles' },
    { key: 'max_parallel_assignments', label: 'Maximum parallel assignments' },
    { key: 'approval_rules', label: 'Approval rules' },
    { key: 'recovery_policy', label: 'Recovery policy' },
    { key: 'generation', label: 'Generation' },
    { key: 'version', label: 'Version' },
    { key: 'created_by_subject', label: 'Created by' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' }
  ],
  controls: [
    { key: 'state', label: 'State' },
    { key: 'scope_type', label: 'Scope type' },
    { key: 'scope_id', label: 'Scope' },
    { key: 'owner_subject', label: 'Owner' },
    { key: 'generation', label: 'Generation' },
    { key: 'reason', label: 'Reason' },
    { key: 'changed_by_subject', label: 'Changed by' },
    { key: 'expires_at', label: 'Expires' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' }
  ],
  assignments: [
    { key: 'status', label: 'Status' },
    { key: 'room_id', label: 'Room' },
    { key: 'policy_id', label: 'Policy' },
    { key: 'work_item_id', label: 'Work item' },
    { key: 'selected_agent_id', label: 'Selected agent' },
    { key: 'score', label: 'Score' },
    { key: 'rationale', label: 'Rationale' },
    { key: 'policy_generation', label: 'Policy generation' },
    { key: 'work_item_version', label: 'Work item version' },
    { key: 'created_by_subject', label: 'Created by' },
    { key: 'applied_at', label: 'Applied' },
    { key: 'revoked_at', label: 'Revoked' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' }
  ],
  recoveries: [
    { key: 'status', label: 'Status' },
    { key: 'room_id', label: 'Room' },
    { key: 'policy_id', label: 'Policy' },
    { key: 'source_type', label: 'Source type' },
    { key: 'source_id', label: 'Source' },
    { key: 'target_agent_id', label: 'Target agent' },
    { key: 'strategy', label: 'Strategy' },
    { key: 'attempt_count', label: 'Attempts' },
    { key: 'max_attempts', label: 'Maximum attempts' },
    { key: 'base_backoff_seconds', label: 'Base backoff seconds' },
    { key: 'next_attempt_at', label: 'Next attempt' },
    { key: 'last_command_id', label: 'Last command' },
    { key: 'last_error', label: 'Last error' },
    { key: 'policy_generation', label: 'Policy generation' },
    { key: 'generation', label: 'Generation' },
    { key: 'created_by_subject', label: 'Created by' },
    { key: 'completed_at', label: 'Completed' },
    { key: 'created_at', label: 'Created' },
    { key: 'updated_at', label: 'Updated' }
  ],
  overrides: [
    { key: 'action', label: 'Action' },
    { key: 'scope_type', label: 'Scope type' },
    { key: 'scope_id', label: 'Scope' },
    { key: 'previous_state', label: 'Previous state' },
    { key: 'new_state', label: 'New state' },
    { key: 'reason', label: 'Reason' },
    { key: 'actor_subject', label: 'Actor' },
    { key: 'evidence', label: 'Evidence' },
    { key: 'created_at', label: 'Created' }
  ]
};

function AutonomyRegistryDetail({
  activeTabId,
  onClose,
  onRefresh,
  record
}: {
  activeTabId: string;
  onClose: () => void;
  onRefresh: () => Promise<void>;
  record: RegistryRecord;
}) {
  const fields = autonomySemanticFields[activeTabId] ?? [];
  const title = autonomyTabs.find((tab) => tab.id === activeTabId)?.label ?? 'Safety & Autonomy';
  return (
    <aside className="registry-detail registry-detail-semantic">
      <RegistryDetailHeader onClose={onClose} record={record} title={title} />
      <div className="registry-detail-body">
        <section className="registry-detail-section">
          <h3>Record details</h3>
          <div className="registry-detail-grid">
            {fields.map((field) => (
              <SemanticDetailField
                key={field.key}
                label={field.label}
                value={record[field.key]}
                valueKey={field.key}
              />
            ))}
          </div>
        </section>
        {activeTabId === 'approvals' ? (
          <ApprovalReviewDetail onRefresh={onRefresh} record={record} />
        ) : null}
        <details className="registry-raw">
          <summary>Raw record</summary>
          <pre className="selectable"><code>{JSON.stringify(record, null, 2)}</code></pre>
        </details>
      </div>
    </aside>
  );
}

function SemanticDetailField({
  label,
  value,
  valueKey
}: {
  label: string;
  value: unknown;
  valueKey: string;
}) {
  return (
    <div className="registry-detail-field">
      <span>{label}</span>
      <strong className="selectable">{semanticValue(valueKey, value)}</strong>
    </div>
  );
}

function ApprovalReviewDetail({
  onRefresh,
  record
}: {
  onRefresh: () => Promise<void>;
  record: RegistryRecord;
}) {
  const review = objectValue(record.review);
  const target = objectValue(review.target);
  const votes = Array.isArray(record.votes) ? record.votes : [];
  const [reason, setReason] = useState('');
  const [pendingDecision, setPendingDecision] = useState<'approve' | 'reject' | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');
  const reviewSurface = String(review.surface ?? target.review_surface ?? 'gateway');
  const canVote = review.can_vote === true;

  async function submitDecision() {
    if (!pendingDecision) return;
    setSubmitting(true);
    setSubmitError('');
    try {
      await registryApi.voteApproval(record.id, pendingDecision, reason);
      setPendingDecision(null);
      setReason('');
      await onRefresh();
    } catch (error) {
      setSubmitError(errorMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <section className="registry-detail-section">
        <h3>Review state</h3>
        <div className="registry-detail-grid">
          <SemanticDetailField label="Review surface" value={reviewSurface} valueKey="surface" />
          <SemanticDetailField label="Eligible reviewer" value={review.authorized} valueKey="authorized" />
          <SemanticDetailField label="Can vote now" value={review.can_vote} valueKey="can_vote" />
          <SemanticDetailField label="Approvals" value={review.approve_count} valueKey="approve_count" />
          <SemanticDetailField label="Required quorum" value={review.quorum_required} valueKey="quorum_required" />
          <SemanticDetailField label="Quorum met" value={review.quorum_met} valueKey="quorum_met" />
          <SemanticDetailField label="Admin approval required" value={review.admin_required} valueKey="admin_required" />
          <SemanticDetailField label="Admin approvals" value={review.admin_approve_count} valueKey="admin_approve_count" />
          <SemanticDetailField label="Rejections" value={review.reject_count} valueKey="reject_count" />
          <SemanticDetailField label="Expired" value={review.expired} valueKey="expired" />
          <SemanticDetailField label="Current reviewer decision" value={review.current_voter_decision} valueKey="current_voter_decision" />
          <SemanticDetailField label="Eligibility state" value={review.reason} valueKey="reason" />
        </div>
      </section>
      <section className="registry-detail-section">
        <h3>Immutable target</h3>
        <div className="registry-detail-grid">
          <SemanticDetailField label="Target kind" value={target.kind} valueKey="kind" />
          <SemanticDetailField label="Provider" value={target.provider} valueKey="provider" />
          <SemanticDetailField label="Server" value={target.server_name ?? target.server_id} valueKey="server_name" />
          <SemanticDetailField label="Tool" value={target.tool_name ?? target.tool_id} valueKey="tool_name" />
          <SemanticDetailField label="Preparation" value={target.preparation_id} valueKey="preparation_id" />
          <SemanticDetailField label="Server ID" value={target.server_id} valueKey="server_id" />
          <SemanticDetailField label="Tool ID" value={target.tool_id} valueKey="tool_id" />
          <SemanticDetailField label="Revision ID" value={target.revision_id} valueKey="revision_id" />
        </div>
      </section>
      <section className="registry-detail-section">
        <h3>Votes</h3>
        {votes.length === 0 ? (
          <p className="registry-detail-muted">No votes recorded.</p>
        ) : (
          <div className="registry-votes">
            {votes.map((vote, index) => {
              const item = objectValue(vote);
              return (
                <div className="registry-vote" key={String(item.id ?? index)}>
                  <strong>{displayValue(item.voter_subject)}</strong>
                  <StatusPill status={displayValue(item.decision)} />
                  <span>{formatDate(item.created_at)}</span>
                  {item.reason ? <p>{displayValue(item.reason)}</p> : null}
                </div>
              );
            })}
          </div>
        )}
      </section>
      <section className="registry-detail-section registry-review-actions">
        <h3>Decision</h3>
        {reviewSurface === 'affine' ? (
          <p className="registry-review-routing">
            This automated AFFiNE action is reviewed in AFFiNE Notifications. Gateway keeps the canonical approval state but does not expose duplicate decision controls here.
          </p>
        ) : canVote ? (
          <>
            <label className="registry-review-reason">
              <span>Decision reason (optional)</span>
              <textarea
                disabled={submitting}
                maxLength={10000}
                onChange={(event) => setReason(event.target.value)}
                rows={3}
                value={reason}
              />
            </label>
            <div className="registry-review-buttons">
              <Button disabled={submitting} onClick={() => setPendingDecision('approve')} type="button">Approve</Button>
              <Button disabled={submitting} onClick={() => setPendingDecision('reject')} type="button">Reject</Button>
            </div>
          </>
        ) : (
          <p className="registry-detail-muted">{displayValue(review.reason ?? 'No decision is available for the current reviewer.')}</p>
        )}
        {pendingDecision ? (
          <div className="registry-confirmation" role="alertdialog" aria-label={`Confirm ${pendingDecision}`}>
            <strong>Confirm {pendingDecision}</strong>
            <p>
              Submit this decision for approval request <span className="selectable">{record.id}</span>? Gateway will revalidate your identity, current policy, expiry and quorum state.
            </p>
            <div className="registry-confirmation-actions">
              <Button disabled={submitting} onClick={() => setPendingDecision(null)} type="button">Cancel</Button>
              <Button disabled={submitting} onClick={submitDecision} type="button">
                {submitting ? 'Submitting…' : `Confirm ${pendingDecision}`}
              </Button>
            </div>
          </div>
        ) : null}
        {submitError ? <p className="registry-review-error" role="alert">{submitError}</p> : null}
      </section>
    </>
  );
}

function objectValue(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function semanticValue(key: string, value: unknown) {
  if (key.endsWith('_at') || key === 'expires_at') return formatDate(value);
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return displayValue(value);
}

function textColumn(key: string, label: string): RegistryColumn {
  return { key, label, render: (record) => truncate(displayValue(record[key])) };
}

function numberColumn(key: string, label: string): RegistryColumn {
  return { key, label, render: (record) => displayValue(record[key]) };
}

function primaryColumn(primary: string, fallback: string, label: string): RegistryColumn {
  return {
    key: primary,
    label,
    render: (record) => <strong>{truncate(displayValue(record[primary] ?? record[fallback]), 90)}</strong>
  };
}

function dateColumn(key: string, label: string): RegistryColumn {
  return { key, label, render: (record) => formatDate(record[key]) };
}

function statusColumn(): RegistryColumn {
  return {
    key: 'status',
    label: 'Status',
    render: (record) => <StatusPill status={displayValue(record.status ?? 'unknown')} />
  };
}

function stateColumn(): RegistryColumn {
  return {
    key: 'state',
    label: 'State',
    render: (record) => <StatusPill status={displayValue(record.state ?? 'unknown')} />
  };
}

function rangeColumn(): RegistryColumn {
  return {
    key: 'range',
    label: 'Lines',
    render: (record) => `${displayValue(record.start_line)}–${displayValue(record.end_line)}`
  };
}

function diffColumn(): RegistryColumn {
  return {
    key: 'diff',
    label: 'Diff',
    render: (record) => `+${displayValue(record.added_lines)} / -${displayValue(record.removed_lines)}`
  };
}

function resourceColumn(): RegistryColumn {
  return {
    key: 'resource',
    label: 'Resource',
    render: (record) => `${displayValue(record.resource_type)} · ${truncate(displayValue(record.resource_id), 28)}`
  };
}

function countColumn(key: string, label: string): RegistryColumn {
  return {
    key,
    label,
    render: (record) => Array.isArray(record[key]) ? record[key].length : 0
  };
}

function quorumColumn(): RegistryColumn {
  return {
    key: 'quorum',
    label: 'Quorum',
    render: (record) => `${Array.isArray(record.votes) ? record.votes.length : 0}/${displayValue(record.quorum_required)}`
  };
}

function usageColumn(): RegistryColumn {
  return {
    key: 'usage',
    label: 'Uses',
    render: (record) => `${displayValue(record.use_count)}/${displayValue(record.max_uses)}`
  };
}

function attemptsColumn(): RegistryColumn {
  return {
    key: 'attempts',
    label: 'Attempts',
    render: (record) => `${displayValue(record.attempt_count)}/${displayValue(record.max_attempts)}`
  };
}

function deliveryBudgetColumn(): RegistryColumn {
  return {
    key: 'delivery-budget',
    label: 'Attempts',
    render: (record) => `${displayValue(record.attempt_count)}/${displayValue(record.max_attempts)}`
  };
}

function displayValue(value: unknown) {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.join(', ');
  return JSON.stringify(value);
}

function truncate(value: string, maximum = 48) {
  return value.length > maximum ? `${value.slice(0, maximum - 1)}…` : value;
}

function formatDate(value: unknown) {
  if (typeof value !== 'string' || !value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error || 'Registry unavailable');
}

const emptyPage: CursorPage = { items: [], next_cursor: null, has_more: false };
