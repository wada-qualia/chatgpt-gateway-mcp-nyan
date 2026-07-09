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
import { useEffect, useState } from "react";
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
  meta?: Record<string, unknown>;
  name: string | null;
  origin: string;
  resource_id?: string | null;
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

export type GatewayFileChangeDiffLine = {
  kind: "context" | "delete" | "insert";
  text: string;
};

export type GatewayFileChangeDiffHunk = {
  old_count: number;
  old_start: number;
  new_count: number;
  new_start: number;
  lines: GatewayFileChangeDiffLine[];
};

export type GatewayFileChangeDiff = {
  added_lines: number;
  format: string;
  hunks: GatewayFileChangeDiffHunk[];
  reason?: string | null;
  removed_lines: number;
  suppressed: boolean;
  truncated: boolean;
};

export type GatewayFileChange = {
  added_lines: number;
  bytes_after: number;
  bytes_before: number;
  created_at: string;
  diff_json: GatewayFileChangeDiff;
  id: string;
  operation: string;
  origin: string;
  path: string;
  removed_lines: number;
  replacements: number;
  resource_id: string | null;
  suppressed: boolean;
  tool_call_id: string | null;
  truncated: boolean;
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
  const rowsPerPage = 10;
  const [currentPage, setCurrentPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(devices.length / rowsPerPage));
  const safeCurrentPage = Math.min(currentPage, pageCount);
  const pageStartIndex = devices.length === 0 ? 0 : (safeCurrentPage - 1) * rowsPerPage;
  const pageEndIndex = Math.min(pageStartIndex + rowsPerPage, devices.length);
  const pagedDevices = devices.slice(pageStartIndex, pageEndIndex);
  const rangeStart = devices.length === 0 ? 0 : pageStartIndex + 1;
  const rangeEnd = pageEndIndex;

  useEffect(() => {
    setCurrentPage((page) => Math.min(Math.max(page, 1), pageCount));
  }, [pageCount]);

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
              <th>SSH Ready</th>
              <th>Last Seen</th>
              <th>SSO Linked</th>
              <th className="menu-cell" />
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <TableNoticeRow
                colSpan={10}
                state="loading"
                title="Loading devices..."
              />
            ) : errorMessage ? (
              <TableNoticeRow
                colSpan={10}
                state="error"
                title="Devices unavailable"
                description={errorMessage}
              />
            ) : devices.length === 0 ? (
              <TableNoticeRow colSpan={9} state="empty" title={emptyMessage} />
            ) : (
              pagedDevices.map((device) => (
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
                  <td>
                    <span className={`readiness-badge ${sshReadinessClass(device.status)}`}>
                      {sshReadinessLabel(device.status)}
                    </span>
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
          {rangeStart}-{rangeEnd} of {devices.length}
        </span>
        <IconButton
          aria-label="Previous page"
          disabled={safeCurrentPage <= 1}
          onClick={() => setCurrentPage((page) => Math.max(1, page - 1))}
        >
          <ChevronLeft size={16} />
        </IconButton>
        {Array.from({ length: pageCount }, (_, index) => {
          const page = index + 1;
          return (
            <Button
              className={`page ${page === safeCurrentPage ? "active" : ""}`}
              key={page}
              onClick={() => setCurrentPage(page)}
              type="button"
            >
              {page}
            </Button>
          );
        })}
        <IconButton
          aria-label="Next page"
          disabled={safeCurrentPage >= pageCount}
          onClick={() => setCurrentPage((page) => Math.min(pageCount, page + 1))}
        >
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
  isDeleting = false,
  isTesting = false,
  isUpdating = false,
  onClose,
  onDelete,
  onTestConnection,
  onUpdate,
  selected,
  thinClients,
  workspaces,
}: {
  isDeleting?: boolean;
  isTesting?: boolean;
  isUpdating?: boolean;
  onClose: () => void;
  onDelete: (deviceId: string) => void;
  onTestConnection: (deviceId: string) => void;
  onUpdate: (
    deviceId: string,
    payload: {
      auth_type?: string;
      name?: string;
      password?: string;
      private_key?: string;
      target?: string;
    },
  ) => void;
  selected?: GatewayDevice;
  thinClients: number;
  workspaces: number;
}) {
  const [activeTab, setActiveTab] = useState<"overview" | "workspaces" | "thin" | "audit">("overview");
  const [isEditing, setIsEditing] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [editName, setEditName] = useState("");
  const [editTarget, setEditTarget] = useState("");
  const [editAuthType, setEditAuthType] = useState<"password" | "private_key">("password");
  const [editSecret, setEditSecret] = useState("");

  useEffect(() => {
    if (!selected) return;
    setActiveTab("overview");
    setIsEditing(false);
    setShowDeleteConfirm(false);
    setEditName(selected.name);
    setEditTarget(`${selected.username}@${selected.host}:${selected.port}`);
    setEditAuthType(selected.auth_type === "private_key" ? "private_key" : "password");
    setEditSecret("");
  }, [selected?.id]);

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

  const logs = [
    { label: "SSO login", actor: "jane.kim@k-lab.io", status: "ok", time: "10:13:07" },
    { label: "SSH session", actor: selected.username, status: "ok", time: "10:12:07" },
    { label: "SSH session", actor: selected.username, status: "ok", time: "10:11:07" },
    { label: "Auth failed", actor: selected.username, status: "bad", time: "10:10:07" },
    { label: "SSH session", actor: selected.username, status: "ok", time: "10:09:07" },
  ];

  const saveEdit = () => {
    const trimmedSecret = editSecret.trim();
    onUpdate(selected.id, {
      auth_type: editAuthType,
      name: editName.trim(),
      target: editTarget.trim(),
      password: editAuthType === "password" && trimmedSecret ? trimmedSecret : undefined,
      private_key: editAuthType === "private_key" && trimmedSecret ? trimmedSecret : undefined,
    });
    setIsEditing(false);
  };

  return (
    <aside className="detail-panel">
      <div className="detail-head">
        <Server size={22} />
        <h2>{selected.name}</h2>
        <StatusPill status={selected.status} />
        <IconButton aria-label="Close details" onClick={onClose}>
          <X size={18} />
        </IconButton>
      </div>
      <div className="tabs" role="tablist" aria-label="Device details">
        <Button
          className={activeTab === "overview" ? "active" : ""}
          onClick={() => setActiveTab("overview")}
          role="tab"
          type="button"
        >
          Overview
        </Button>
        <Button
          className={activeTab === "workspaces" ? "active" : ""}
          onClick={() => setActiveTab("workspaces")}
          role="tab"
          type="button"
        >
          Workspaces ({workspaces})
        </Button>
        <Button
          className={activeTab === "thin" ? "active" : ""}
          onClick={() => setActiveTab("thin")}
          role="tab"
          type="button"
        >
          Thin Clients ({thinClients})
        </Button>
        <Button
          className={activeTab === "audit" ? "active" : ""}
          onClick={() => setActiveTab("audit")}
          role="tab"
          type="button"
        >
          Audit
        </Button>
      </div>

      {activeTab === "overview" ? (
        isEditing ? (
          <div className="detail-edit-form">
            <label>
              Device name
              <input
                aria-label="Device name"
                onChange={(event) => setEditName(event.target.value)}
                value={editName}
              />
            </label>
            <label>
              SSH target
              <input
                aria-label="SSH target"
                onChange={(event) => setEditTarget(event.target.value)}
                value={editTarget}
              />
            </label>
            <label>
              Auth method
              <SegmentedControl
                options={[
                  { label: "Password", value: "password" },
                  { label: "Key", value: "private_key" },
                ]}
                onChange={(value) => setEditAuthType(value as "password" | "private_key")}
                value={editAuthType}
              />
            </label>
            <label>
              New secret
              <input
                aria-label="New secret"
                onChange={(event) => setEditSecret(event.target.value)}
                placeholder="Leave empty to keep current credential"
                type={editAuthType === "password" ? "password" : "text"}
                value={editSecret}
              />
            </label>
            <div className="edit-actions">
              <Button disabled={isUpdating} onClick={saveEdit} type="button" variant="solid">
                {isUpdating ? "Saving..." : "Save"}
              </Button>
              <Button onClick={() => setIsEditing(false)} type="button">
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          <>
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
              <dt>SSH Readiness</dt>
              <dd>
                <span className={`readiness-badge ${sshReadinessClass(selected.status)}`}>
                  {sshReadinessLabel(selected.status)}
                </span>
              </dd>
              <dt>MCP Tools</dt>
              <dd>{sshMcpToolSummary(selected.status)}</dd>
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
              <Button onClick={() => setActiveTab("audit")} type="button">
                View all
              </Button>
            </div>
            <ConnectionLogList logs={logs} />
          </>
        )
      ) : null}

      {activeTab === "workspaces" ? (
        <DataNotice
          description="Device-linked workspace attachment is not configured for this resource yet."
          title={workspaces > 0 ? `${workspaces} workspaces available` : "No workspaces attached"}
        />
      ) : null}

      {activeTab === "thin" ? (
        <DataNotice
          description="Thin clients are shown globally until per-device linking is implemented."
          title={thinClients > 0 ? `${thinClients} thin clients online or registered` : "No thin clients linked"}
        />
      ) : null}

      {activeTab === "audit" ? (
        <>
          <div className="recent-head no-border">
            <h3>Device Audit</h3>
          </div>
          <ConnectionLogList logs={logs} />
        </>
      ) : null}

      <div className="detail-actions">
        <Button disabled={isTesting} onClick={() => onTestConnection(selected.id)} type="button">
          <RefreshCw size={17} /> {isTesting ? "Testing..." : "Test Connection"}
        </Button>
        <Button
          onClick={() => {
            setActiveTab("overview");
            setIsEditing(true);
          }}
          type="button"
        >
          <Edit3 size={17} /> Edit
        </Button>
        <Button disabled={isDeleting} onClick={() => setShowDeleteConfirm(true)} variant="danger" type="button">
          <Trash2 size={17} /> Delete
        </Button>
      </div>

      {showDeleteConfirm ? (
        <div className="modal-backdrop" role="presentation">
          <div aria-modal="true" className="confirm-modal" role="dialog" aria-labelledby="delete-device-title">
            <h3 id="delete-device-title">Delete SSH device?</h3>
            <p>
              This will remove {selected.name} from the gateway and revoke its stored credential reference.
            </p>
            <div className="confirm-actions">
              <Button onClick={() => setShowDeleteConfirm(false)} type="button">
                Cancel
              </Button>
              <Button
                disabled={isDeleting}
                onClick={() => {
                  onDelete(selected.id);
                  setShowDeleteConfirm(false);
                }}
                type="button"
                variant="danger"
              >
                {isDeleting ? "Deleting..." : "Delete device"}
              </Button>
            </div>
          </div>
        </div>
      ) : null}
    </aside>
  );
}

type ConnectionLog = {
  actor: string;
  label: string;
  status: string;
  time: string;
};

function ConnectionLogList({ logs }: { logs: ConnectionLog[] }) {
  return (
    <div className="log-list">
      {logs.map((item) => (
        <div className="log-row" key={`${item.time}-${item.label}`}>
          {item.status === "bad" ? (
            <X className="log-bad" size={16} />
          ) : (
            <CheckCircle2 className="log-good" size={16} />
          )}
          <span>{item.time}</span>
          <strong>{item.label}</strong>
          <span>{item.actor}</span>
        </div>
      ))}
    </div>
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
  fileChanges,
  fileChangesErrorMessage,
  fileChangesIsLoading = false,
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
  fileChanges: GatewayFileChange[];
  fileChangesErrorMessage?: string | null;
  fileChangesIsLoading?: boolean;
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
  const selected = selectedId
    ? sessions.find((session) => session.id === selectedId)
    : undefined;
  const rowsPerPage = 10;
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(sessions.length / rowsPerPage));
  const safePage = Math.min(page, totalPages);
  const pageStart = sessions.length === 0 ? 0 : (safePage - 1) * rowsPerPage;
  const pageEnd = Math.min(pageStart + rowsPerPage, sessions.length);
  const visibleSessions = sessions.slice(pageStart, pageEnd);

  useEffect(() => {
    setPage((current) => Math.min(Math.max(current, 1), totalPages));
  }, [totalPages]);

  return (
    <div className={`monitoring-layout ${selected ? "has-selected-session" : ""}`}>
      <div className="monitoring-main-column">
        <div className="monitoring-sessions-panel">
          <div className="monitoring-panel-title">
            <strong>Command sessions</strong>
            <span className="muted">{sessions.length} sessions</span>
          </div>
          <TableFrame compact>
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Origin</th>
                  <th>Resource</th>
                  <th>Command</th>
                  <th>Lines</th>
                  <th>Updated</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <TableNoticeRow colSpan={7} state="loading" title="Loading command sessions..." />
                ) : errorMessage ? (
                  <TableNoticeRow colSpan={7} state="error" title="Command sessions unavailable" description={errorMessage} />
                ) : sessions.length === 0 ? (
                  <TableNoticeRow colSpan={7} state="empty" title={emptyMessage} />
                ) : (
                  visibleSessions.map((session) => (
                    <tr
                      className={session.id === selected?.id ? "selected-row" : ""}
                      key={session.id}
                      onClick={() => onSelect(session.id)}
                    >
                      <td><StatusPill status={session.status} /></td>
                      <td>
                        <span className={`origin-badge ${originBadgeClass(session.origin)}`}>
                          {originLabel(session.origin)}
                        </span>
                      </td>
                      <td className="resource-cell">{sessionResourceLabel(session)}</td>
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
          {!isLoading && !errorMessage && sessions.length > 0 ? (
            <div className="pager monitoring-pager">
              <span>Rows per page:</span>
              <Button type="button">{rowsPerPage}</Button>
              <span className="spacer" />
              <span>{pageStart + 1}-{pageEnd} of {sessions.length}</span>
              <IconButton aria-label="Previous command sessions page" disabled={safePage <= 1} onClick={() => setPage((current) => Math.max(1, current - 1))} type="button">
                <ChevronLeft size={16} />
              </IconButton>
              {Array.from({ length: totalPages }, (_, index) => index + 1).map((pageNumber) => (
                <Button className={`page ${pageNumber === safePage ? "active" : ""}`} key={pageNumber} onClick={() => setPage(pageNumber)} type="button">
                  {pageNumber}
                </Button>
              ))}
              <IconButton aria-label="Next command sessions page" disabled={safePage >= totalPages} onClick={() => setPage((current) => Math.min(totalPages, current + 1))} type="button">
                <ChevronRight size={16} />
              </IconButton>
            </div>
          ) : null}
        </div>
      </div>

      {selected ? (
      <div className="monitoring-output-panel terminal-output-panel">
        <div className="panel-heading session-heading">
          <div className="session-title-block">
            <strong>{selected ? selected.name ?? selected.command : "Session output"}</strong>
            {selected ? (
              <span className="muted">
                {originLabel(selected.origin)} · {sessionResourceLabel(selected)}
              </span>
            ) : null}
          </div>
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
      ) : null}

      <div className="file-changes-panel">
        <div className="panel-heading">
          <strong>Recent file changes</strong>
          <span className="muted">{fileChanges.length} changes</span>
        </div>
        {fileChangesIsLoading ? (
          <DataNotice state="loading" title="Loading file changes..." />
        ) : fileChangesErrorMessage ? (
          <DataNotice state="error" title="File changes unavailable" description={fileChangesErrorMessage} />
        ) : fileChanges.length === 0 ? (
          <DataNotice title="No file changes recorded yet." />
        ) : (
          <div className="file-change-list">
            {fileChanges.map((change) => (
              <article className="file-change-card" key={change.id}>
                <header>
                  <div>
                    <strong>{change.path}</strong>
                    <span>{change.operation} · {change.origin}</span>
                  </div>
                  <div className="diff-stats" aria-label={`Diff stats for ${change.path}`}>
                    <span className="diff-added">+{change.added_lines}</span>
                    <span className="diff-removed">-{change.removed_lines}</span>
                    {change.truncated ? <span className="context-badge requested">truncated</span> : null}
                    {change.suppressed ? <span className="context-badge auto">suppressed</span> : null}
                  </div>
                </header>
                <FileDiffView change={change} />
              </article>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function FileDiffView({ change }: { change: GatewayFileChange }) {
  const diff = change.diff_json;
  if (!diff || diff.suppressed) {
    return (
      <div className="diff-suppressed">
        Diff content suppressed{diff?.reason ? `: ${diff.reason}` : "."}
      </div>
    );
  }
  if (!diff.hunks.length) {
    return <div className="diff-suppressed">No visible line changes.</div>;
  }
  return (
    <pre className="diff-view selectable" aria-label={`Diff for ${change.path}`}>
      {diff.hunks.map((hunk, hunkIndex) => (
        <div className="diff-hunk" key={`${change.id}-${hunkIndex}`}>
          <div className="diff-line diff-header">
            @@ -{hunk.old_start},{hunk.old_count} +{hunk.new_start},{hunk.new_count} @@
          </div>
          {hunk.lines.map((line, lineIndex) => (
            <div className={`diff-line ${line.kind}`} key={`${hunkIndex}-${lineIndex}`}>
              <span className="diff-prefix">{diffPrefix(line.kind)}</span>
              <code>{line.text || " "}</code>
            </div>
          ))}
        </div>
      ))}
    </pre>
  );
}

function diffPrefix(kind: GatewayFileChangeDiffLine["kind"]) {
  if (kind === "insert") return "+";
  if (kind === "delete") return "-";
  return " ";
}

function sshReadinessLabel(status: string) {
  if (status === "verified") return "MCP ready";
  if (status === "reachable") return "TCP only";
  if (status === "auth_failed") return "Auth failed";
  if (status === "unreachable") return "Unreachable";
  return "Needs test";
}

function sshReadinessClass(status: string) {
  if (status === "verified") return "ready";
  if (status === "reachable" || status === "registered") return "partial";
  if (status === "auth_failed" || status === "unreachable") return "blocked";
  return "partial";
}

function sshMcpToolSummary(status: string) {
  if (status === "verified") {
    return "ssh_device_info, ssh_device_check_connection and allowlisted SSH actions are ready.";
  }
  if (status === "auth_failed") return "Credentials need attention before SSH actions can run.";
  if (status === "unreachable") return "Host is unreachable; SSH actions are blocked.";
  return "Run Test Connection to verify backend-side SSH authentication.";
}

function originLabel(origin: string) {
  if (origin === "ssh") return "SSH host";
  if (origin === "thin_client") return "Thin client";
  if (origin === "docker") return "Docker";
  if (origin === "server") return "Server";
  return origin;
}

function originBadgeClass(origin: string) {
  if (origin === "ssh") return "ssh";
  if (origin === "thin_client") return "thin";
  if (origin === "docker") return "docker";
  return "server";
}

function sessionResourceLabel(session: GatewayCommandSession) {
  if (session.origin === "ssh") {
    const host = stringMeta(session, "host");
    const username = stringMeta(session, "username");
    if (host && username) return `${username}@${host}`;
    if (host) return host;
  }
  if (session.origin === "thin_client") {
    const hostname = stringMeta(session, "hostname");
    if (hostname) return hostname;
  }
  return session.resource_id ?? "—";
}

function stringMeta(session: GatewayCommandSession, key: string) {
  const value = session.meta?.[key];
  return typeof value === "string" && value ? value : null;
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
