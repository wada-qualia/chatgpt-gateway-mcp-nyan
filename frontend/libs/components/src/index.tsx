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
  LoaderCircle,
  Laptop,
  Menu,
  MoreVertical,
  PauseCircle,
  PlayCircle,
  Plus,
  RefreshCw,
  Search,
  Server,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Button,
  CommandBox,
  IconButton,
  ResourceCard,
  SearchField,
  SegmentedControl,
  StatusPill,
  TableFrame,
} from "@gateway/ui";

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
  container_id?: string | null;
  description?: string | null;
  id: string;
  image: string;
  name: string;
  status: string;
};

export type GatewayThinClient = {
  directory: string;
  hostname: string;
  id: string;
  meta?: {
    labels?: Record<string, string>;
  } & Record<string, unknown>;
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

export type GatewayCommandOutputLine = {
  agent_requested: boolean;
  auto_sent: boolean;
  line: number;
  stream: string;
  text: string;
  timestamp: string | null;
};

export type GatewayCommandSession = {
  command: string;
  completed_at: string | null;
  cwd: string;
  exit_code: number | null;
  id: string;
  line_count: number;
  name: string | null;
  origin: string;
  status: string;
  updated_at: string;
};

export type GatewayCommandSessionOutput = {
  end_line: number;
  lines: GatewayCommandOutputLine[];
  session_id: string;
  start_line: number;
  total_lines: number;
};

export type GatewayAgentToolCall = {
  arguments: Record<string, unknown>;
  completed_at: string | null;
  created_at: string;
  error: string | null;
  id: string;
  status: string;
  tool_name: string;
};

export type GatewayDataStateProps = {
  emptyMessage?: string;
  errorMessage?: string | null;
  isLoading?: boolean;
};

export function GatewaySidebar({
  active,
  items,
  onSelect,
}: {
  active: string;
  items: GatewayNavItem[];
  onSelect: (id: string) => void;
}) {
  return (
    <aside className="sidebar">
      <div className="brand-row">
        <strong>ChatGPT MCP SSH Gateway</strong>
      </div>
      <nav>
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <Button
              key={item.id}
              className={`nav-item ${active === item.id ? "active" : ""}`}
              onClick={() => onSelect(item.id)}
              type="button"
            >
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

export function GatewayTopbar({
  errorMessage,
  isLoading = false,
  user,
}: {
  errorMessage?: string | null;
  isLoading?: boolean;
  user?: GatewayUserSummary;
}) {
  const username = isLoading
    ? "Loading SSO user"
    : (user?.username ?? "No SSO session");
  return (
    <header className="topbar">
      <div className="avatar">{username.slice(0, 2).toUpperCase()}</div>
      <div className="user-block">
        <strong>{username}</strong>
        <span>{errorMessage ?? user?.email ?? "No email from SSO"}</span>
      </div>
    </header>
  );
}

export function DeviceTable({
  devices,
  emptyMessage = "No devices registered yet.",
  errorMessage,
  isLoading = false,
  onSearch,
  onSelect,
  search,
  selectedId,
  total,
}: {
  devices: GatewayDevice[];
} & GatewayDataStateProps & {
    onSearch: (value: string) => void;
    onSelect: (id: string) => void;
    search: string;
    selectedId?: string;
    total: number;
  }) {
  return (
    <>
      <div className="list-controls">
        <SearchField
          icon={<Search size={18} />}
          onChange={onSearch}
          placeholder="Search devices..."
          value={search}
        />
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
              <th className="check-cell">
                <input type="checkbox" aria-label="Select all devices" />
              </th>
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
            {isLoading ? (
              <TableNoticeRow
                colSpan={9}
                state="loading"
                title="Loading devices..."
              />
            ) : errorMessage ? (
              <TableNoticeRow
                colSpan={9}
                state="error"
                title="Devices unavailable"
                description={errorMessage}
              />
            ) : devices.length === 0 ? (
              <TableNoticeRow colSpan={9} state="empty" title={emptyMessage} />
            ) : (
              devices.map((device) => (
                <tr
                  key={device.id}
                  className={selectedId === device.id ? "selected" : ""}
                  onClick={() => onSelect(device.id)}
                >
                  <td className="check-cell">
                    <input
                      type="checkbox"
                      checked={selectedId === device.id}
                      readOnly
                      aria-label={`Select ${device.name}`}
                    />
                  </td>
                  <td>
                    <StatusPill status={device.status} />
                  </td>
                  <td>{device.name}</td>
                  <td>{device.username}</td>
                  <td>{device.host}</td>
                  <td>
                    {device.auth_type === "private_key"
                      ? "SSH Key"
                      : "Password"}
                  </td>
                  <td>2m ago</td>
                  <td>
                    <span className="linked">Linked</span>
                  </td>
                  <td className="menu-cell">
                    <MoreVertical size={18} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </TableFrame>
      <div className="pager">
        <span>Rows per page:</span>
        <Button type="button">
          10 <ChevronDown size={14} />
        </Button>
        <span className="spacer" />
        <span>
          1-{Math.min(10, total)} of {total}
        </span>
        <IconButton aria-label="Previous page">
          <ChevronLeft size={16} />
        </IconButton>
        <Button className="page active" type="button">
          1
        </Button>
        <Button className="page" type="button">
          2
        </Button>
        <Button className="page" type="button">
          3
        </Button>
        <IconButton aria-label="Next page">
          <ChevronRight size={16} />
        </IconButton>
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
  target,
}: {
  authType: "password" | "private_key";
  onCreate: () => void;
  secret: string;
  setAuthType: (value: "password" | "private_key") => void;
  setSecret: (value: string) => void;
  setTarget: (value: string) => void;
  target: string;
}) {
  return (
    <div className="inline-panel">
      <div className="panel-heading">
        <h2>New SSH device</h2>
        <IconButton aria-label="Close form">
          <X size={18} />
        </IconButton>
      </div>
      <div className="form-grid">
        <label>
          user@host
          <input
            placeholder="user@host:22"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
          />
        </label>
        <label>
          Secret
          <input
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            placeholder={authType === "password" ? "Password" : "Private key"}
            type="password"
          />
        </label>
        <label>
          Auth method
          <SegmentedControl
            onChange={setAuthType}
            options={[
              { label: "Password", value: "password" },
              { label: "Key", value: "private_key" },
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
          <Button variant="solid" onClick={onCreate} type="button">
            Add device
          </Button>
        </div>
      </div>
    </div>
  );
}

export function DeviceDetailPanel({
  selected,
  thinClients,
  workspaces,
}: {
  selected?: GatewayDevice;
  thinClients: number;
  workspaces: number;
}) {
  if (!selected) {
    return (
      <aside className="detail-panel">
        <DataNotice
          description="Register an SSH device or wait for the devices API to return data."
          title="No device selected"
        />
      </aside>
    );
  }
  return (
    <aside className="detail-panel">
      <div className="detail-head">
        <Server size={22} />
        <h2>{selected.name}</h2>
        <StatusPill status={selected.status} />
        <IconButton aria-label="Close details">
          <X size={18} />
        </IconButton>
      </div>
      <div className="tabs">
        <Button className="active" type="button">
          Overview
        </Button>
        <Button type="button">Workspaces ({workspaces})</Button>
        <Button type="button">Thin Clients ({thinClients})</Button>
        <Button type="button">Audit</Button>
      </div>
      <dl className="details">
        <dt>Hostname</dt>
        <dd>
          {selected.name} <Copy size={15} />
        </dd>
        <dt>IP Address</dt>
        <dd>
          {selected.host} <Copy size={15} />
        </dd>
        <dt>User</dt>
        <dd>{selected.username}</dd>
        <dt>Port</dt>
        <dd>{selected.port}</dd>
        <dt>OS</dt>
        <dd>Ubuntu 22.04 LTS</dd>
        <dt>Status</dt>
        <dd>
          <StatusPill status={selected.status} />
        </dd>
        <dt>Auth Method</dt>
        <dd>{selected.auth_type === "private_key" ? "SSH Key" : "Password"}</dd>
        <dt>Directory</dt>
        <dd>/home/{selected.username}</dd>
        <dt>Access Scope</dt>
        <dd>
          <span className="scope-chip">
            K-Lab Engineers <Copy size={14} />
          </span>
        </dd>
        <dt>SSO Linked</dt>
        <dd>
          <span className="linked">Linked</span>
        </dd>
      </dl>
      <div className="recent-head">
        <h3>Recent Connection Logs</h3>
        <Button type="button">View all</Button>
      </div>
      <div className="log-list">
        {[
          "SSO login",
          "SSH session",
          "SSH session",
          "Auth failed",
          "SSH session",
        ].map((item, index) => (
          <div className="log-row" key={item + index}>
            {index === 3 ? (
              <X className="log-bad" size={16} />
            ) : (
              <CheckCircle2 className="log-good" size={16} />
            )}
            <span>10:{13 - index}:07</span>
            <strong>{item}</strong>
            <span>{index === 0 ? "jane.kim@k-lab.io" : selected.username}</span>
          </div>
        ))}
      </div>
      <div className="detail-actions">
        <Button type="button">
          <RefreshCw size={17} /> Test Connection
        </Button>
        <Button type="button">
          <Edit3 size={17} /> Edit
        </Button>
        <Button variant="danger" type="button">
          <Trash2 size={17} /> Delete
        </Button>
      </div>
    </aside>
  );
}

export function DockerWorkspaceGrid({
  editDescription,
  editName,
  editingWorkspaceId,
  emptyMessage = "No Docker workspaces yet.",
  errorMessage,
  isLoading = false,
  onBeginEdit,
  onCancelEdit,
  onClone,
  onDelete,
  onEditDescription,
  onEditName,
  onSaveEdit,
  onStart,
  onStop,
  workspaces,
}: {
  editDescription: string;
  editName: string;
  editingWorkspaceId?: string;
  onBeginEdit: (workspace: GatewayWorkspace) => void;
  onCancelEdit: () => void;
  onClone: (workspaceId: string) => void;
  onDelete: (workspaceId: string) => void;
  onEditDescription: (value: string) => void;
  onEditName: (value: string) => void;
  onSaveEdit: (workspaceId: string) => void;
  onStart: (workspaceId: string) => void;
  onStop: (workspaceId: string) => void;
  workspaces: GatewayWorkspace[];
} & GatewayDataStateProps) {
  if (isLoading) {
    return <DataNotice state="loading" title="Loading Docker workspaces..." />;
  }
  if (errorMessage) {
    return (
      <DataNotice
        description={errorMessage}
        state="error"
        title="Docker workspaces unavailable"
      />
    );
  }
  if (workspaces.length === 0) {
    return <DataNotice title={emptyMessage} />;
  }
  return (
    <div className="cards-grid">
      {workspaces.map((workspace) => {
        const isRunning = workspace.status === "running";
        const isEditing = editingWorkspaceId === workspace.id;
        return (
          <ResourceCard key={workspace.id}>
            <Box size={22} />
            {isEditing ? (
              <input
                aria-label="Workspace name"
                className="workspace-title-input"
                onChange={(event) => onEditName(event.target.value)}
                value={editName}
              />
            ) : (
              <h2>{workspace.name}</h2>
            )}
            <p>{workspace.image}</p>
            {isEditing ? (
              <textarea
                aria-label="Workspace description"
                className="workspace-description-input"
                onChange={(event) => onEditDescription(event.target.value)}
                placeholder="Optional context for this container"
                rows={3}
                value={editDescription}
              />
            ) : workspace.description ? (
              <p className="workspace-description">{workspace.description}</p>
            ) : null}
            {workspace.container_id ? (
              <p className="resource-meta">
                {workspace.container_id.slice(0, 12)}
              </p>
            ) : null}
            <StatusPill status={workspace.status} />
            <div className={`workspace-actions ${isEditing ? "editing" : ""}`}>
              {isEditing ? (
                <>
                  <Button
                    onClick={() => onSaveEdit(workspace.id)}
                    type="button"
                    variant="solid"
                  >
                    Save
                  </Button>
                  <Button onClick={onCancelEdit} type="button">
                    Cancel
                  </Button>
                </>
              ) : (
                <>
                  <Button onClick={() => onBeginEdit(workspace)} type="button">
                    <Edit3 size={16} /> Edit
                  </Button>
                  <Button onClick={() => onClone(workspace.id)} type="button">
                    <Copy size={16} /> Clone
                  </Button>
                  {isRunning ? (
                    <Button onClick={() => onStop(workspace.id)} type="button">
                      <PauseCircle size={16} /> Freeze
                    </Button>
                  ) : (
                    <Button onClick={() => onStart(workspace.id)} type="button">
                      <PlayCircle size={16} /> Resume
                    </Button>
                  )}
                  <Button
                    onClick={() => onDelete(workspace.id)}
                    type="button"
                    variant="danger"
                  >
                    <Trash2 size={16} /> Delete
                  </Button>
                </>
              )}
            </div>
          </ResourceCard>
        );
      })}
    </div>
  );
}

export function ThinClientPanel({
  clientCommand,
  emptyMessage = "No thin clients registered yet.",
  errorMessage,
  isLoading = false,
  onDelete,
  thinClients,
}: {
  clientCommand: string;
  onDelete: (clientId: string) => void;
  thinClients: GatewayThinClient[];
} & GatewayDataStateProps) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">(
    "idle",
  );
  const copyLabel =
    copyState === "copied"
      ? "Copied"
      : copyState === "failed"
        ? "Copy failed"
        : "Copy";

  async function copyClientCommand() {
    try {
      await copyTextToClipboard(clientCommand);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <>
      <div className="command-panel">
        <div className="command-panel-head">
          <strong>Install command</strong>
          <Button
            aria-label={`${copyLabel} thin client install command`}
            onClick={copyClientCommand}
            type="button"
          >
            <Copy size={16} /> {copyLabel}
          </Button>
        </div>
        <CommandBox selectable>{clientCommand}</CommandBox>
      </div>
      {isLoading ? (
        <DataNotice state="loading" title="Loading thin clients..." />
      ) : errorMessage ? (
        <DataNotice
          description={errorMessage}
          state="error"
          title="Thin clients unavailable"
        />
      ) : thinClients.length === 0 ? (
        <DataNotice title={emptyMessage} />
      ) : (
        <div className="cards-grid">
          {thinClients.map((client) => {
            const version = client.meta?.labels?.version;
            return (
              <ResourceCard key={client.id}>
                <Laptop size={22} />
                <h2>{client.hostname}</h2>
                <p>{client.directory}</p>
                {version ? (
                  <p className="resource-meta">gateway-cli {version}</p>
                ) : null}
                <StatusPill status={client.status} />
                <div className="workspace-actions">
                  <Button
                    aria-label={`Delete thin client ${client.hostname}`}
                    onClick={() => onDelete(client.id)}
                    type="button"
                    variant="danger"
                  >
                    <Trash2 size={16} /> Delete
                  </Button>
                </div>
              </ResourceCard>
            );
          })}
        </div>
      )}
    </>
  );
}

async function copyTextToClipboard(text: string) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return;
    }
  } catch {
    // Fall back below for browser contexts that expose Clipboard API but deny it.
  }

  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.setAttribute("readonly", "");
  textArea.style.left = "-9999px";
  textArea.style.position = "fixed";
  textArea.style.top = "0";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  const copied = document.execCommand("copy");
  textArea.remove();
  if (!copied) {
    throw new Error("Copy command was rejected.");
  }
}

export function AccessGrantsTable({
  emptyMessage = "No ChatGPT access grants yet.",
  errorMessage,
  isLoading = false,
  grants,
}: {
  grants: GatewayAccessGrant[];
} & GatewayDataStateProps) {
  return (
    <TableFrame compact>
      <table>
        <thead>
          <tr>
            <th>Grantee</th>
            <th>Resource</th>
            <th>Scopes</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            <TableNoticeRow
              colSpan={4}
              state="loading"
              title="Loading access grants..."
            />
          ) : errorMessage ? (
            <TableNoticeRow
              colSpan={4}
              state="error"
              title="Access grants unavailable"
              description={errorMessage}
            />
          ) : grants.length === 0 ? (
            <TableNoticeRow colSpan={4} state="empty" title={emptyMessage} />
          ) : (
            grants.map((grant) => (
              <tr key={grant.id}>
                <td>{grant.grantee_subject}</td>
                <td>
                  {grant.resource_type}:{grant.resource_id}
                </td>
                <td>{grant.scopes.join(", ")}</td>
                <td>
                  <StatusPill status={grant.status} />
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </TableFrame>
  );
}

export function AuditEventsTable({
  audit,
  emptyMessage = "No audit events recorded yet.",
  errorMessage,
  isLoading = false,
}: {
  audit: GatewayAuditEvent[];
} & GatewayDataStateProps) {
  return (
    <TableFrame compact>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Actor</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            <TableNoticeRow
              colSpan={4}
              state="loading"
              title="Loading audit events..."
            />
          ) : errorMessage ? (
            <TableNoticeRow
              colSpan={4}
              state="error"
              title="Audit events unavailable"
              description={errorMessage}
            />
          ) : audit.length === 0 ? (
            <TableNoticeRow colSpan={4} state="empty" title={emptyMessage} />
          ) : (
            audit.map((event) => (
              <tr key={event.id}>
                <td>{new Date(event.created_at).toLocaleTimeString()}</td>
                <td>{event.event_type}</td>
                <td>{event.actor_subject}</td>
                <td>
                  <StatusPill status={event.status} />
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </TableFrame>
  );
}

export function MonitoringSessionsPanel({
  emptyMessage = "No command sessions yet.",
  errorMessage,
  isLoading = false,
  onForceTerminate,
  onSelect,
  onTerminate,
  output,
  outputErrorMessage,
  outputIsLoading = false,
  selectedId,
  sessions,
  toolCalls,
}: {
  onForceTerminate: (sessionId: string) => void;
  onSelect: (sessionId: string) => void;
  onTerminate: (sessionId: string) => void;
  output?: GatewayCommandSessionOutput;
  outputErrorMessage?: string | null;
  outputIsLoading?: boolean;
  selectedId?: string;
  sessions: GatewayCommandSession[];
  toolCalls: GatewayAgentToolCall[];
} & GatewayDataStateProps) {
  const selected = sessions.find((session) => session.id === selectedId) ?? sessions[0];
  return (
    <div className="monitoring-layout">
      <TableFrame compact>
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Origin</th>
              <th>Command</th>
              <th>Lines</th>
              <th>Updated</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <TableNoticeRow colSpan={6} state="loading" title="Loading command sessions..." />
            ) : errorMessage ? (
              <TableNoticeRow colSpan={6} state="error" title="Command sessions unavailable" description={errorMessage} />
            ) : sessions.length === 0 ? (
              <TableNoticeRow colSpan={6} state="empty" title={emptyMessage} />
            ) : (
              sessions.map((session) => (
                <tr
                  className={session.id === selected?.id ? "selected-row" : ""}
                  key={session.id}
                  onClick={() => onSelect(session.id)}
                >
                  <td><StatusPill status={session.status} /></td>
                  <td>{session.origin}</td>
                  <td className="command-cell">
                    <strong>{session.name ?? session.command}</strong>
                    <span>{session.cwd}</span>
                  </td>
                  <td>{session.line_count}</td>
                  <td>{new Date(session.updated_at).toLocaleTimeString()}</td>
                  <td className="session-actions">
                    <Button disabled={!isRunningStatus(session.status)} onClick={(event) => { event.stopPropagation(); onTerminate(session.id); }} type="button">
                      <PauseCircle size={16} /> Stop
                    </Button>
                    <Button disabled={!isRunningStatus(session.status)} onClick={(event) => { event.stopPropagation(); onForceTerminate(session.id); }} type="button" variant="danger">
                      <Trash2 size={16} /> Kill
                    </Button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </TableFrame>
      <div className="monitoring-output-panel">
        <div className="panel-heading">
          <strong>{selected ? selected.name ?? selected.command : "Session output"}</strong>
          {selected ? <StatusPill status={selected.status} /> : null}
        </div>
        {outputIsLoading ? (
          <DataNotice state="loading" title="Loading output..." />
        ) : outputErrorMessage ? (
          <DataNotice state="error" title="Output unavailable" description={outputErrorMessage} />
        ) : !output || output.lines.length === 0 ? (
          <DataNotice title="No output captured yet." />
        ) : (
          <div className="session-output selectable">
            {output.lines.map((line) => (
              <div className={`output-line ${line.stream}`} key={line.line}>
                <span className="line-number">{line.line}</span>
                <span className="line-markers">
                  {line.auto_sent ? <span className="context-badge auto">auto</span> : null}
                  {line.agent_requested ? <span className="context-badge requested">agent</span> : null}
                </span>
                <code>{line.text}</code>
              </div>
            ))}
          </div>
        )}
        <div className="tool-history">
          <strong>Agent tool history</strong>
          {toolCalls.length === 0 ? (
            <span className="muted">No tool calls linked to this session.</span>
          ) : (
            toolCalls.map((call) => (
              <div className="tool-call-row" key={call.id}>
                <StatusPill status={call.status} />
                <span>{call.tool_name}</span>
                <code>{JSON.stringify(call.arguments)}</code>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function isRunningStatus(status: string) {
  return status === "running" || status === "disconnecting";
}

function TableNoticeRow({
  colSpan,
  description,
  state = "empty",
  title,
}: {
  colSpan: number;
  description?: string;
  state?: "empty" | "error" | "loading";
  title: string;
}) {
  return (
    <tr className="notice-row">
      <td colSpan={colSpan}>
        <DataNotice
          compact
          description={description}
          state={state}
          title={title}
        />
      </td>
    </tr>
  );
}

function DataNotice({
  compact = false,
  description,
  state = "empty",
  title,
}: {
  compact?: boolean;
  description?: string;
  state?: "empty" | "error" | "loading";
  title: string;
}) {
  return (
    <div
      className={`data-notice ${compact ? "compact" : ""} ${state}`}
      role={state === "error" ? "alert" : "status"}
    >
      {state === "loading" ? (
        <LoaderCircle className="notice-spinner" size={22} />
      ) : (
        <Server size={22} />
      )}
      <strong>{title}</strong>
      {description ? <span>{description}</span> : null}
    </div>
  );
}
