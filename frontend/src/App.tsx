import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Bell,
  Box,
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  Edit3,
  FileText,
  Filter,
  HelpCircle,
  KeyRound,
  Laptop,
  Menu,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  Server,
  TerminalSquare,
  Trash2,
  X
} from 'lucide-react';
import { api, type Device } from './generated/client';
import { fallbackAudit, fallbackDevices, fallbackGrants, fallbackThinClients, fallbackWorkspaces } from './shared/fallbackData';

const nav = [
  { id: 'devices', label: 'Devices', icon: Server },
  { id: 'workspaces', label: 'Docker Workspaces', icon: Box },
  { id: 'thin', label: 'Thin Clients', icon: TerminalSquare },
  { id: 'access', label: 'ChatGPT Access', icon: KeyRound },
  { id: 'audit', label: 'Audit', icon: FileText }
];

function statusClass(status: string) {
  if (status === 'online' || status === 'running' || status === 'active' || status === 'success') return 'good';
  if (status === 'pending') return 'warn';
  return 'bad';
}

export function App() {
  const [active, setActive] = useState('devices');
  const [selectedId, setSelectedId] = useState('2');
  const [search, setSearch] = useState('');
  const [target, setTarget] = useState('devops@10.10.1.91:22');
  const [secret, setSecret] = useState('');
  const [authType, setAuthType] = useState<'password' | 'private_key'>('password');
  const [clientCommand, setClientCommand] = useState('python -m gateway_cli login --gateway http://localhost:8000 --serve');
  const queryClient = useQueryClient();

  const me = useQuery({ queryKey: ['me'], queryFn: api.me });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const workspacesQuery = useQuery({ queryKey: ['workspaces'], queryFn: api.workspaces });
  const thinClientsQuery = useQuery({ queryKey: ['thinClients'], queryFn: api.thinClients });
  const grantsQuery = useQuery({ queryKey: ['grants'], queryFn: api.grants });
  const auditQuery = useQuery({ queryKey: ['audit'], queryFn: api.audit });
  const imagesQuery = useQuery({ queryKey: ['images'], queryFn: api.images });

  const devices = devicesQuery.data?.length ? devicesQuery.data : fallbackDevices;
  const workspaces = workspacesQuery.data?.length ? workspacesQuery.data : fallbackWorkspaces;
  const thinClients = thinClientsQuery.data?.length ? thinClientsQuery.data : fallbackThinClients;
  const grants = grantsQuery.data?.length ? grantsQuery.data : fallbackGrants;
  const audit = auditQuery.data?.length ? auditQuery.data : fallbackAudit;

  const selected = devices.find((device) => device.id === selectedId) ?? devices[0];
  const filtered = useMemo(
    () => devices.filter((device) => `${device.name} ${device.host} ${device.username}`.toLowerCase().includes(search.toLowerCase())),
    [devices, search]
  );

  const createDevice = useMutation({
    mutationFn: () =>
      api.createDevice({
        name: target.split('@')[1]?.split(':')[0] ?? target,
        target,
        auth_type: authType,
        password: authType === 'password' ? secret || 'change-me' : undefined,
        private_key: authType === 'private_key' ? secret || '-----BEGIN PRIVATE KEY-----\\nlocal-dev\\n-----END PRIVATE KEY-----' : undefined
      }),
    onSuccess: (device) => {
      setSelectedId(device.id);
      queryClient.invalidateQueries({ queryKey: ['devices'] });
    }
  });

  const createWorkspace = useMutation({
    mutationFn: () => api.createWorkspace({ name: `ubuntu-${Date.now().toString().slice(-4)}`, image: imagesQuery.data?.images[0] ?? 'ubuntu:24.04' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['workspaces'] })
  });

  const cloneWorkspace = useMutation({
    mutationFn: () => api.cloneWorkspace({ source_workspace_id: workspaces[0]?.id ?? 'w1', name: `clone-${Date.now().toString().slice(-4)}` }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['workspaces'] })
  });

  const installClient = useMutation({
    mutationFn: api.createDeviceCode,
    onSuccess: (code) => setClientCommand(`python -m gateway_cli login --gateway http://localhost:8000 --serve  # code ${code.user_code}`)
  });

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <button className="icon-button" aria-label="Menu">
            <Menu size={20} />
          </button>
          <strong>ChatGPT MCP SSH Gateway</strong>
        </div>
        <nav>
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={`nav-item ${active === item.id ? 'active' : ''}`} onClick={() => setActive(item.id)}>
                <Icon size={20} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <button className="collapse-button">
          <ChevronLeft size={18} />
          <span>Collapse</span>
        </button>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="realm-control">
            <span>Keycloak realm</span>
            <button>
              chatgpt-mcp <ChevronDown size={16} />
            </button>
          </div>
          <div className="system-ok">
            <span className="dot good-dot" /> All systems operational
          </div>
          <button className="icon-button" aria-label="Help">
            <HelpCircle size={20} />
          </button>
          <button className="icon-button" aria-label="Notifications">
            <Bell size={20} />
          </button>
          <div className="avatar">{(me.data?.username ?? 'DK').slice(0, 2).toUpperCase()}</div>
          <div className="user-block">
            <strong>{me.data?.username ?? 'Darius'}</strong>
            <span>{me.data?.email ?? 'dev@k-lab.local'}</span>
          </div>
        </header>

        <section className="toolbar" aria-label="Gateway actions">
          <button className="primary-action" onClick={() => createDevice.mutate()}>
            <Plus size={20} /> Add SSH Device
          </button>
          <button onClick={() => createWorkspace.mutate()}>
            <Box size={20} /> Create Ubuntu
          </button>
          <button onClick={() => cloneWorkspace.mutate()}>
            <Copy size={20} /> Clone Container
          </button>
          <button onClick={() => installClient.mutate()}>
            <Download size={20} /> Install Client
          </button>
        </section>

        <section className="content-grid">
          <div className="main-pane">
            {active === 'devices' && (
              <DevicesView
                devices={filtered}
                total={devices.length}
                selectedId={selected?.id}
                search={search}
                onSearch={setSearch}
                onSelect={setSelectedId}
                target={target}
                setTarget={setTarget}
                secret={secret}
                setSecret={setSecret}
                authType={authType}
                setAuthType={setAuthType}
                onCreate={() => createDevice.mutate()}
              />
            )}
            {active === 'workspaces' && <WorkspacesView workspaces={workspaces} onCreate={() => createWorkspace.mutate()} onClone={() => cloneWorkspace.mutate()} />}
            {active === 'thin' && <ThinClientsView thinClients={thinClients} clientCommand={clientCommand} onInstall={() => installClient.mutate()} />}
            {active === 'access' && <AccessView grants={grants} />}
            {active === 'audit' && <AuditView audit={audit} />}
          </div>
          <DetailPanel selected={selected} workspaces={workspaces.length} thinClients={thinClients.length} />
        </section>
      </main>
    </div>
  );
}

type DevicesProps = {
  devices: Device[];
  total: number;
  selectedId?: string;
  search: string;
  onSearch: (value: string) => void;
  onSelect: (id: string) => void;
  target: string;
  setTarget: (value: string) => void;
  secret: string;
  setSecret: (value: string) => void;
  authType: 'password' | 'private_key';
  setAuthType: (value: 'password' | 'private_key') => void;
  onCreate: () => void;
};

function DevicesView(props: DevicesProps) {
  return (
    <>
      <div className="section-title">
        <h1>Devices</h1>
      </div>
      <div className="list-controls">
        <label className="search-field">
          <input value={props.search} onChange={(event) => props.onSearch(event.target.value)} placeholder="Search devices..." />
          <Search size={18} />
        </label>
        <button>
          <Filter size={18} /> Filters
        </button>
        <span className="spacer" />
        <span className="muted">{props.total} devices</span>
        <button className="icon-button" aria-label="Refresh">
          <RefreshCw size={18} />
        </button>
      </div>
      <div className="table-frame">
        <table>
          <thead>
            <tr>
              <th className="check-cell"><input type="checkbox" aria-label="Select all devices" /></th>
              <th>Status</th>
              <th>Hostname</th>
              <th>User</th>
              <th>IP Address</th>
              <th>Auth</th>
              <th>Last Seen</th>
              <th>SSO Linked</th>
              <th className="menu-cell" />
            </tr>
          </thead>
          <tbody>
            {props.devices.map((device) => (
              <tr key={device.id} className={props.selectedId === device.id ? 'selected' : ''} onClick={() => props.onSelect(device.id)}>
                <td className="check-cell"><input type="checkbox" checked={props.selectedId === device.id} readOnly aria-label={`Select ${device.name}`} /></td>
                <td><StatusPill status={device.status} /></td>
                <td>{device.name}</td>
                <td>{device.username}</td>
                <td>{device.host}</td>
                <td>{device.auth_type === 'private_key' ? 'SSH Key' : 'Password'}</td>
                <td>2m ago</td>
                <td><span className="linked">Linked</span></td>
                <td className="menu-cell"><MoreVertical size={18} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pager">
        <span>Rows per page:</span>
        <button>10 <ChevronDown size={14} /></button>
        <span className="spacer" />
        <span>1-{Math.min(10, props.total)} of {props.total}</span>
        <button className="icon-button"><ChevronLeft size={16} /></button>
        <button className="page active">1</button>
        <button className="page">2</button>
        <button className="page">3</button>
        <button className="icon-button"><ChevronRight size={16} /></button>
      </div>
      <div className="inline-panel">
        <div className="panel-heading">
          <h2>New SSH device</h2>
          <button className="icon-button" aria-label="Close form"><X size={18} /></button>
        </div>
        <div className="form-grid">
          <label>
            user@host
            <input value={props.target} onChange={(event) => props.setTarget(event.target.value)} />
          </label>
          <label>
            Secret
            <input value={props.secret} onChange={(event) => props.setSecret(event.target.value)} placeholder={props.authType === 'password' ? 'Password' : 'Private key'} type="password" />
          </label>
          <label>
            Auth method
            <div className="segmented">
              <button className={props.authType === 'password' ? 'active' : ''} onClick={() => props.setAuthType('password')}>Password</button>
              <button className={props.authType === 'private_key' ? 'active' : ''} onClick={() => props.setAuthType('private_key')}>Key</button>
            </div>
          </label>
          <label>
            Directory
            <input placeholder="/home/user" />
          </label>
          <label>
            Access scope
            <select defaultValue="engineers">
              <option value="engineers">K-Lab Engineers</option>
              <option value="chatgpt">ChatGPT Connector</option>
            </select>
          </label>
          <div className="form-actions">
            <button>Cancel</button>
            <button className="solid" onClick={props.onCreate}>Add device</button>
          </div>
        </div>
      </div>
    </>
  );
}

function WorkspacesView({ workspaces, onCreate, onClone }: { workspaces: typeof fallbackWorkspaces; onCreate: () => void; onClone: () => void }) {
  return (
    <div className="subview">
      <div className="section-title"><h1>Docker Workspaces</h1><button className="solid" onClick={onCreate}><Plus size={18} /> Create Ubuntu</button></div>
      <div className="cards-grid">
        {workspaces.map((workspace) => (
          <article className="resource-card" key={workspace.id}>
            <Box size={22} />
            <h2>{workspace.name}</h2>
            <p>{workspace.image}</p>
            <StatusPill status={workspace.status} />
            <button onClick={onClone}><Copy size={16} /> Clone</button>
          </article>
        ))}
      </div>
    </div>
  );
}

function ThinClientsView({ thinClients, clientCommand, onInstall }: { thinClients: typeof fallbackThinClients; clientCommand: string; onInstall: () => void }) {
  return (
    <div className="subview">
      <div className="section-title"><h1>Thin Clients</h1><button className="solid" onClick={onInstall}><Download size={18} /> Issue device code</button></div>
      <pre className="command-box">{clientCommand}</pre>
      <div className="cards-grid">
        {thinClients.map((client) => (
          <article className="resource-card" key={client.id}>
            <Laptop size={22} />
            <h2>{client.hostname}</h2>
            <p>{client.directory}</p>
            <StatusPill status={client.status} />
          </article>
        ))}
      </div>
    </div>
  );
}

function AccessView({ grants }: { grants: typeof fallbackGrants }) {
  return (
    <div className="subview">
      <div className="section-title"><h1>ChatGPT Access</h1></div>
      <div className="table-frame compact">
        <table>
          <thead><tr><th>Grantee</th><th>Resource</th><th>Scopes</th><th>Status</th></tr></thead>
          <tbody>{grants.map((grant) => <tr key={grant.id}><td>{grant.grantee_subject}</td><td>{grant.resource_type}:{grant.resource_id}</td><td>{grant.scopes.join(', ')}</td><td><StatusPill status={grant.status} /></td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}

function AuditView({ audit }: { audit: typeof fallbackAudit }) {
  return (
    <div className="subview">
      <div className="section-title"><h1>Audit</h1></div>
      <div className="table-frame compact">
        <table>
          <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Status</th></tr></thead>
          <tbody>{audit.map((event) => <tr key={event.id}><td>{new Date(event.created_at).toLocaleTimeString()}</td><td>{event.event_type}</td><td>{event.actor_subject}</td><td><StatusPill status={event.status} /></td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}

function DetailPanel({ selected, workspaces, thinClients }: { selected?: Device; workspaces: number; thinClients: number }) {
  if (!selected) return null;
  return (
    <aside className="detail-panel">
      <div className="detail-head">
        <Server size={22} />
        <h2>{selected.name}</h2>
        <StatusPill status={selected.status} />
        <button className="icon-button" aria-label="Close details"><X size={18} /></button>
      </div>
      <div className="tabs">
        <button className="active">Overview</button>
        <button>Workspaces ({workspaces})</button>
        <button>Thin Clients ({thinClients})</button>
        <button>Audit</button>
      </div>
      <dl className="details">
        <dt>Hostname</dt><dd>{selected.name} <Copy size={15} /></dd>
        <dt>IP Address</dt><dd>{selected.host} <Copy size={15} /></dd>
        <dt>User</dt><dd>{selected.username}</dd>
        <dt>Port</dt><dd>{selected.port}</dd>
        <dt>OS</dt><dd>Ubuntu 22.04 LTS</dd>
        <dt>Status</dt><dd><StatusPill status={selected.status} /></dd>
        <dt>Auth Method</dt><dd>{selected.auth_type === 'private_key' ? 'SSH Key' : 'Password'}</dd>
        <dt>Directory</dt><dd>/home/{selected.username}</dd>
        <dt>Access Scope</dt><dd><span className="scope-chip">K-Lab Engineers <Copy size={14} /></span></dd>
        <dt>SSO Linked</dt><dd><span className="linked">Linked</span></dd>
      </dl>
      <div className="recent-head">
        <h3>Recent Connection Logs</h3>
        <button>View all</button>
      </div>
      <div className="log-list">
        {['SSO login', 'SSH session', 'SSH session', 'Auth failed', 'SSH session'].map((item, index) => (
          <div className="log-row" key={item + index}>
            {index === 3 ? <X className="log-bad" size={16} /> : <CheckCircle2 className="log-good" size={16} />}
            <span>10:{13 - index}:07</span>
            <strong>{item}</strong>
            <span>{index === 0 ? 'jane.kim@k-lab.io' : selected.username}</span>
          </div>
        ))}
      </div>
      <div className="detail-actions">
        <button><RefreshCw size={17} /> Test Connection</button>
        <button><Edit3 size={17} /> Edit</button>
        <button className="danger"><Trash2 size={17} /> Delete</button>
      </div>
    </aside>
  );
}

function StatusPill({ status }: { status: string }) {
  return <span className={`status-pill ${statusClass(status)}`}><span className="dot" />{status}</span>;
}
