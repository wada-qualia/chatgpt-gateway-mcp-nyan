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
        {selected ? <RegistryDetail record={selected} onClose={() => setSelectedId('')} /> : null}
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

function RegistryDetail({ record, onClose }: { record: RegistryRecord; onClose: () => void }) {
  return (
    <aside className="registry-detail">
      <header>
        <div>
          <strong>Registry record</strong>
          <span>{record.id}</span>
        </div>
        <Button onClick={onClose} type="button">Close</Button>
      </header>
      <pre className="selectable"><code>{JSON.stringify(record, null, 2)}</code></pre>
    </aside>
  );
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
