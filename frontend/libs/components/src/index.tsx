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
  Filter,
  HelpCircle,
  Laptop,
  Menu,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  Server,
  Trash2,
  X
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Button, CommandBox, IconButton, ResourceCard, SearchField, SegmentedControl, StatusPill, TableFrame } from '@gateway/ui';

export type GatewayNavItem = {
  id: string;
  label: string;
  icon: LucideIcon;
};

export type GatewayUserSummary = {
  email: string | null;
  username: string;
};

export type GatewayDevice = {
  auth_type: string;
  host: string;
  id: string;
  name: string;
  port: number;
  status: string;
  username: string;
};

export type GatewayWorkspace = {
  id: string;
  image: string;
  name: string;
  status: string;
};

export type GatewayThinClient = {
  directory: string;
  hostname: string;
  id: string;
  status: string;
};

export type GatewayAccessGrant = {
  grantee_subject: string;
  id: string;
  resource_id: string;
  resource_type: string;
  scopes: string[];
  status: string;
};

export type GatewayAuditEvent = {
  actor_subject: string;
  created_at: string;
  event_type: string;
  id: string;
  status: string;
};

export function GatewaySidebar({ active, items, onSelect }: { active: string; items: GatewayNavItem[]; onSelect: (id: string) => void }) {
  return (
    <aside className="sidebar">
      <div className="brand-row">
        <IconButton aria-label="Menu">
          <Menu size={20} />
        </IconButton>
        <strong>ChatGPT MCP SSH Gateway</strong>
      </div>
      <nav>
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <Button key={item.id} className={`nav-item ${active === item.id ? 'active' : ''}`} onClick={() => onSelect(item.id)} type="button">
              <Icon size={20} />
              <span>{item.label}</span>
            </Button>
          );
        })}
      </nav>
      <Button className="collapse-button" type="button">
        <ChevronLeft size={18} />
        <span>Collapse</span>
      </Button>
    </aside>
  );
}

export function GatewayTopbar({ user }: { user?: GatewayUserSummary }) {
  const username = user?.username ?? 'Darius';
  return (
    <header className="topbar">
      <div className="realm-control">
        <span>Keycloak realm</span>
        <Button type="button">
          chatgpt-mcp <ChevronDown size={16} />
        </Button>
      </div>
      <div className="system-ok">
        <span className="dot good-dot" /> All systems operational
      </div>
      <IconButton aria-label="Help">
        <HelpCircle size={20} />
      </IconButton>
      <IconButton aria-label="Notifications">
        <Bell size={20} />
      </IconButton>
      <div className="avatar">{username.slice(0, 2).toUpperCase()}</div>
      <div className="user-block">
        <strong>{username}</strong>
        <span>{user?.email ?? 'dev@k-lab.local'}</span>
      </div>
    </header>
  );
}

export function GatewayToolbar({
  onCloneWorkspace,
  onCreateDevice,
  onCreateWorkspace,
  onInstallClient
}: {
  onCloneWorkspace: () => void;
  onCreateDevice: () => void;
  onCreateWorkspace: () => void;
  onInstallClient: () => void;
}) {
  return (
    <section className="toolbar" aria-label="Gateway actions">
      <Button variant="primary" onClick={onCreateDevice} type="button">
        <Plus size={20} /> Add SSH Device
      </Button>
      <Button onClick={onCreateWorkspace} type="button">
        <Box size={20} /> Create Ubuntu
      </Button>
      <Button onClick={onCloneWorkspace} type="button">
        <Copy size={20} /> Clone Container
      </Button>
      <Button onClick={onInstallClient} type="button">
        <Download size={20} /> Install Client
      </Button>
    </section>
  );
}

export function DeviceTable({
  devices,
  onSearch,
  onSelect,
  search,
  selectedId,
  total
}: {
  devices: GatewayDevice[];
  onSearch: (value: string) => void;
  onSelect: (id: string) => void;
  search: string;
  selectedId?: string;
  total: number;
}) {
  return (
    <>
      <div className="list-controls">
        <SearchField icon={<Search size={18} />} onChange={onSearch} placeholder="Search devices..." value={search} />
        <Button type="button">
          <Filter size={18} /> Filters
        </Button>
        <span className="spacer" />
        <span className="muted">{total} devices</span>
        <IconButton aria-label="Refresh">
          <RefreshCw size={18} />
        </IconButton>
      </div>
      <TableFrame>
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
            {devices.map((device) => (
              <tr key={device.id} className={selectedId === device.id ? 'selected' : ''} onClick={() => onSelect(device.id)}>
                <td className="check-cell"><input type="checkbox" checked={selectedId === device.id} readOnly aria-label={`Select ${device.name}`} /></td>
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
      </TableFrame>
      <div className="pager">
        <span>Rows per page:</span>
        <Button type="button">10 <ChevronDown size={14} /></Button>
        <span className="spacer" />
        <span>1-{Math.min(10, total)} of {total}</span>
        <IconButton aria-label="Previous page"><ChevronLeft size={16} /></IconButton>
        <Button className="page active" type="button">1</Button>
        <Button className="page" type="button">2</Button>
        <Button className="page" type="button">3</Button>
        <IconButton aria-label="Next page"><ChevronRight size={16} /></IconButton>
      </div>
    </>
  );
}

export function DeviceForm({
  authType,
  onCreate,
  secret,
  setAuthType,
  setSecret,
  setTarget,
  target
}: {
  authType: 'password' | 'private_key';
  onCreate: () => void;
  secret: string;
  setAuthType: (value: 'password' | 'private_key') => void;
  setSecret: (value: string) => void;
  setTarget: (value: string) => void;
  target: string;
}) {
  return (
    <div className="inline-panel">
      <div className="panel-heading">
        <h2>New SSH device</h2>
        <IconButton aria-label="Close form"><X size={18} /></IconButton>
      </div>
      <div className="form-grid">
        <label>
          user@host
          <input value={target} onChange={(event) => setTarget(event.target.value)} />
        </label>
        <label>
          Secret
          <input value={secret} onChange={(event) => setSecret(event.target.value)} placeholder={authType === 'password' ? 'Password' : 'Private key'} type="password" />
        </label>
        <label>
          Auth method
          <SegmentedControl
            onChange={setAuthType}
            options={[
              { label: 'Password', value: 'password' },
              { label: 'Key', value: 'private_key' }
            ]}
            value={authType}
          />
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
          <Button type="button">Cancel</Button>
          <Button variant="solid" onClick={onCreate} type="button">Add device</Button>
        </div>
      </div>
    </div>
  );
}

export function DeviceDetailPanel({ selected, thinClients, workspaces }: { selected?: GatewayDevice; thinClients: number; workspaces: number }) {
  if (!selected) return null;
  return (
    <aside className="detail-panel">
      <div className="detail-head">
        <Server size={22} />
        <h2>{selected.name}</h2>
        <StatusPill status={selected.status} />
        <IconButton aria-label="Close details"><X size={18} /></IconButton>
      </div>
      <div className="tabs">
        <Button className="active" type="button">Overview</Button>
        <Button type="button">Workspaces ({workspaces})</Button>
        <Button type="button">Thin Clients ({thinClients})</Button>
        <Button type="button">Audit</Button>
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
        <Button type="button">View all</Button>
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
        <Button type="button"><RefreshCw size={17} /> Test Connection</Button>
        <Button type="button"><Edit3 size={17} /> Edit</Button>
        <Button variant="danger" type="button"><Trash2 size={17} /> Delete</Button>
      </div>
    </aside>
  );
}

export function DockerWorkspaceGrid({ onClone, workspaces }: { onClone: () => void; workspaces: GatewayWorkspace[] }) {
  return (
    <div className="cards-grid">
      {workspaces.map((workspace) => (
        <ResourceCard key={workspace.id}>
          <Box size={22} />
          <h2>{workspace.name}</h2>
          <p>{workspace.image}</p>
          <StatusPill status={workspace.status} />
          <Button onClick={onClone} type="button"><Copy size={16} /> Clone</Button>
        </ResourceCard>
      ))}
    </div>
  );
}

export function ThinClientPanel({ clientCommand, thinClients }: { clientCommand: string; thinClients: GatewayThinClient[] }) {
  return (
    <>
      <CommandBox>{clientCommand}</CommandBox>
      <div className="cards-grid">
        {thinClients.map((client) => (
          <ResourceCard key={client.id}>
            <Laptop size={22} />
            <h2>{client.hostname}</h2>
            <p>{client.directory}</p>
            <StatusPill status={client.status} />
          </ResourceCard>
        ))}
      </div>
    </>
  );
}

export function AccessGrantsTable({ grants }: { grants: GatewayAccessGrant[] }) {
  return (
    <TableFrame compact>
      <table>
        <thead><tr><th>Grantee</th><th>Resource</th><th>Scopes</th><th>Status</th></tr></thead>
        <tbody>{grants.map((grant) => <tr key={grant.id}><td>{grant.grantee_subject}</td><td>{grant.resource_type}:{grant.resource_id}</td><td>{grant.scopes.join(', ')}</td><td><StatusPill status={grant.status} /></td></tr>)}</tbody>
      </table>
    </TableFrame>
  );
}

export function AuditEventsTable({ audit }: { audit: GatewayAuditEvent[] }) {
  return (
    <TableFrame compact>
      <table>
        <thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Status</th></tr></thead>
        <tbody>{audit.map((event) => <tr key={event.id}><td>{new Date(event.created_at).toLocaleTimeString()}</td><td>{event.event_type}</td><td>{event.actor_subject}</td><td><StatusPill status={event.status} /></td></tr>)}</tbody>
      </table>
    </TableFrame>
  );
}
