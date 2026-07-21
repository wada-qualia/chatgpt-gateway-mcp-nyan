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
import i18n from "@gateway/shared/i18n";
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

function tr(key: string, options?: Record<string, unknown>): string {
  return String(i18n.t(key, options));
}

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
        <strong>{tr("brand")}</strong>
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
        <span>{tr("nav.collapse")}</span>
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
    ? tr("auth.loadingUser")
    : (user?.username ?? tr("auth.noSession"));
  const nextPath = typeof window === "undefined" ? "/" : window.location.pathname;
  return (
    <header className="topbar">
      {!isLoading && !user ? (
        <a className="login-link" href={`/auth/login?next=${encodeURIComponent(nextPath)}`}>
          {tr("auth.signIn")}
        </a>
      ) : null}
      <div className="avatar">{username.slice(0, 2).toUpperCase()}</div>
      <div className="user-block">
        <strong>{username}</strong>
        <span>{errorMessage ?? user?.email ?? tr("auth.noEmail")}</span>
      </div>
    </header>
  );
}

export function DeviceTable({
  devices,
  emptyMessage = tr("devices.empty"),
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
          placeholder={tr("devices.search")}
          value={search}
        />
        <Button type="button">
          <Filter size={18} /> {tr("devices.filters")}
        </Button>
        <span className="spacer" />
        <span className="muted">{tr("devices.count", { count: total })}</span>
        <IconButton aria-label={tr("common.actions.refresh")}>
          <RefreshCw size={18} />
        </IconButton>
      </div>
      <TableFrame>
        <table>
          <thead>
            <tr>
              <th className="check-cell">
                <input type="checkbox" aria-label={tr("devices.selectAll")} />
              </th>
              <th>{tr("common.fields.status")}</th>
              <th>{tr("common.fields.hostname")}</th>
              <th>{tr("common.fields.user")}</th>
              <th>{tr("common.fields.ipAddress")}</th>
              <th>{tr("common.fields.auth")}</th>
              <th>{tr("devices.table.sshReady")}</th>
              <th>{tr("devices.table.lastSeen")}</th>
              <th>{tr("devices.table.ssoLinked")}</th>
              <th className="menu-cell" />
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <TableNoticeRow
                colSpan={10}
                state="loading"
                title={tr("devices.loading")}
              />
            ) : errorMessage ? (
              <TableNoticeRow
                colSpan={10}
                state="error"
                title={tr("devices.unavailable")}
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
                      aria-label={tr("devices.select", { name: device.name })}
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
                      ? tr("devices.auth.key")
                      : tr("devices.auth.password")}
                  </td>
                  <td>
                    <span className={`readiness-badge ${sshReadinessClass(device.status)}`}>
                      {sshReadinessLabel(device.status)}
                    </span>
                  </td>
                  <td>{tr("devices.lastSeenTwoMinutes")}</td>
                  <td>
                    <span className="linked">{tr("common.linked")}</span>
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
        <span>{tr("common.rowsPerPage")}</span>
        <Button type="button">
          10 <ChevronDown size={14} />
        </Button>
        <span className="spacer" />
        <span>
          {tr("common.range", { start: rangeStart, end: rangeEnd, total: devices.length })}
        </span>
        <IconButton
          aria-label={tr("common.previousPage")}
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
          aria-label={tr("common.nextPage")}
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
        <h2>{tr("devices.form.title")}</h2>
        <IconButton aria-label={tr("devices.form.close")}>
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
          {tr("devices.form.secret")}
          <input
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            placeholder={authType === "password" ? tr("devices.auth.password") : tr("devices.form.privateKey")}
            type="password"
          />
        </label>
        <label>
          {tr("devices.auth.method")}
          <SegmentedControl
            onChange={setAuthType}
            options={[
              { label: tr("devices.auth.password"), value: "password" },
              { label: tr("devices.auth.shortKey"), value: "private_key" },
            ]}
            value={authType}
          />
        </label>
        <label>
          {tr("common.fields.directory")}
          <input placeholder="/home/user" />
        </label>
        <label>
          {tr("devices.form.accessScope")}
          <select defaultValue="engineers">
            <option value="engineers">{tr("devices.form.engineers")}</option>
            <option value="chatgpt">{tr("devices.form.connector")}</option>
          </select>
        </label>
        <div className="form-actions">
          <Button type="button">{tr("common.actions.cancel")}</Button>
          <Button variant="solid" onClick={onCreate} type="button">
            {tr("devices.form.add")}
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
          description={tr("devices.detail.noneDescription")}
          title={tr("devices.detail.noneTitle")}
        />
      </aside>
    );
  }

  const logs = [
    { label: tr("devices.logs.ssoLogin"), actor: "jane.kim@k-lab.io", status: "ok", time: "10:13:07" },
    { label: tr("devices.logs.sshSession"), actor: selected.username, status: "ok", time: "10:12:07" },
    { label: tr("devices.logs.sshSession"), actor: selected.username, status: "ok", time: "10:11:07" },
    { label: tr("devices.logs.authFailed"), actor: selected.username, status: "bad", time: "10:10:07" },
    { label: tr("devices.logs.sshSession"), actor: selected.username, status: "ok", time: "10:09:07" },
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
        <IconButton aria-label={tr("devices.detail.close")} onClick={onClose}>
          <X size={18} />
        </IconButton>
      </div>
      <div className="tabs" role="tablist" aria-label={tr("devices.detail.aria")}>
        <Button
          className={activeTab === "overview" ? "active" : ""}
          onClick={() => setActiveTab("overview")}
          role="tab"
          type="button"
        >
          {tr("devices.detail.overview")}
        </Button>
        <Button
          className={activeTab === "workspaces" ? "active" : ""}
          onClick={() => setActiveTab("workspaces")}
          role="tab"
          type="button"
        >
          {tr("devices.detail.workspaces", { count: workspaces })}
        </Button>
        <Button
          className={activeTab === "thin" ? "active" : ""}
          onClick={() => setActiveTab("thin")}
          role="tab"
          type="button"
        >
          {tr("devices.detail.thinClients", { count: thinClients })}
        </Button>
        <Button
          className={activeTab === "audit" ? "active" : ""}
          onClick={() => setActiveTab("audit")}
          role="tab"
          type="button"
        >
          {tr("nav.audit")}
        </Button>
      </div>

      {activeTab === "overview" ? (
        isEditing ? (
          <div className="detail-edit-form">
            <label>
              {tr("devices.detail.deviceName")}
              <input
                aria-label={tr("devices.detail.deviceName")}
                onChange={(event) => setEditName(event.target.value)}
                value={editName}
              />
            </label>
            <label>
              {tr("devices.detail.sshTarget")}
              <input
                aria-label={tr("devices.detail.sshTarget")}
                onChange={(event) => setEditTarget(event.target.value)}
                value={editTarget}
              />
            </label>
            <label>
              {tr("devices.auth.method")}
              <SegmentedControl
                options={[
                  { label: tr("devices.auth.password"), value: "password" },
                  { label: tr("devices.auth.shortKey"), value: "private_key" },
                ]}
                onChange={(value) => setEditAuthType(value as "password" | "private_key")}
                value={editAuthType}
              />
            </label>
            <label>
              {tr("devices.detail.newSecret")}
              <input
                aria-label={tr("devices.detail.newSecret")}
                onChange={(event) => setEditSecret(event.target.value)}
                placeholder={tr("devices.detail.keepSecret")}
                type={editAuthType === "password" ? "password" : "text"}
                value={editSecret}
              />
            </label>
            <div className="edit-actions">
              <Button disabled={isUpdating} onClick={saveEdit} type="button" variant="solid">
                {isUpdating ? tr("common.actions.saving") : tr("common.actions.save")}
              </Button>
              <Button onClick={() => setIsEditing(false)} type="button">
                {tr("common.actions.cancel")}
              </Button>
            </div>
          </div>
        ) : (
          <>
            <dl className="details">
              <dt>{tr("common.fields.hostname")}</dt>
              <dd>
                {selected.name} <Copy size={15} />
              </dd>
              <dt>{tr("common.fields.ipAddress")}</dt>
              <dd>
                {selected.host} <Copy size={15} />
              </dd>
              <dt>{tr("common.fields.user")}</dt>
              <dd>{selected.username}</dd>
              <dt>{tr("common.fields.port")}</dt>
              <dd>{selected.port}</dd>
              <dt>{tr("devices.detail.os")}</dt>
              <dd>Ubuntu 22.04 LTS</dd>
              <dt>{tr("common.fields.status")}</dt>
              <dd>
                <StatusPill status={selected.status} />
              </dd>
              <dt>{tr("devices.detail.sshReadiness")}</dt>
              <dd>
                <span className={`readiness-badge ${sshReadinessClass(selected.status)}`}>
                  {sshReadinessLabel(selected.status)}
                </span>
              </dd>
              <dt>{tr("devices.detail.mcpTools")}</dt>
              <dd>{sshMcpToolSummary(selected.status)}</dd>
              <dt>{tr("devices.detail.authMethod")}</dt>
              <dd>{selected.auth_type === "private_key" ? tr("devices.auth.key") : tr("devices.auth.password")}</dd>
              <dt>{tr("common.fields.directory")}</dt>
              <dd>/home/{selected.username}</dd>
              <dt>{tr("devices.detail.accessScope")}</dt>
              <dd>
                <span className="scope-chip">
                  {tr("devices.form.engineers")} <Copy size={14} />
                </span>
              </dd>
              <dt>{tr("devices.detail.ssoLinked")}</dt>
              <dd>
                <span className="linked">{tr("common.linked")}</span>
              </dd>
            </dl>
            <div className="recent-head">
              <h3>{tr("devices.detail.recentLogs")}</h3>
              <Button onClick={() => setActiveTab("audit")} type="button">
                {tr("common.actions.viewAll")}
              </Button>
            </div>
            <ConnectionLogList logs={logs} />
          </>
        )
      ) : null}

      {activeTab === "workspaces" ? (
        <DataNotice
          description={tr("devices.detail.workspaceDescription")}
          title={workspaces > 0 ? tr("devices.detail.workspaceCount", { count: workspaces }) : tr("devices.detail.workspaceNone")}
        />
      ) : null}

      {activeTab === "thin" ? (
        <DataNotice
          description={tr("devices.detail.thinDescription")}
          title={thinClients > 0 ? tr("devices.detail.thinCount", { count: thinClients }) : tr("devices.detail.thinNone")}
        />
      ) : null}

      {activeTab === "audit" ? (
        <>
          <div className="recent-head no-border">
            <h3>{tr("devices.detail.audit")}</h3>
          </div>
          <ConnectionLogList logs={logs} />
        </>
      ) : null}

      <div className="detail-actions">
        <Button disabled={isTesting} onClick={() => onTestConnection(selected.id)} type="button">
          <RefreshCw size={17} /> {isTesting ? tr("common.actions.testing") : tr("devices.detail.testConnection")}
        </Button>
        <Button
          onClick={() => {
            setActiveTab("overview");
            setIsEditing(true);
          }}
          type="button"
        >
          <Edit3 size={17} /> {tr("common.actions.edit")}
        </Button>
        <Button disabled={isDeleting} onClick={() => setShowDeleteConfirm(true)} variant="danger" type="button">
          <Trash2 size={17} /> {tr("common.actions.delete")}
        </Button>
      </div>

      {showDeleteConfirm ? (
        <div className="modal-backdrop" role="presentation">
          <div aria-modal="true" className="confirm-modal" role="dialog" aria-labelledby="delete-device-title">
            <h3 id="delete-device-title">{tr("devices.detail.deleteTitle")}</h3>
            <p>
              {tr("devices.detail.deleteDescription", { name: selected.name })}
            </p>
            <div className="confirm-actions">
              <Button onClick={() => setShowDeleteConfirm(false)} type="button">
                {tr("common.actions.cancel")}
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
                {isDeleting ? tr("devices.detail.deleting") : tr("devices.detail.deleteDevice")}
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
  emptyMessage = tr("workspaces.empty"),
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
    return <DataNotice state="loading" title={tr("workspaces.loading")} />;
  }
  if (errorMessage) {
    return (
      <DataNotice
        description={errorMessage}
        state="error"
        title={tr("workspaces.unavailable")}
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
                aria-label={tr("workspaces.name")}
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
                aria-label={tr("workspaces.description")}
                className="workspace-description-input"
                onChange={(event) => onEditDescription(event.target.value)}
                placeholder={tr("workspaces.optionalDescription")}
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
                    {tr("common.actions.save")}
                  </Button>
                  <Button onClick={onCancelEdit} type="button">
                    {tr("common.actions.cancel")}
                  </Button>
                </>
              ) : (
                <>
                  <Button onClick={() => onBeginEdit(workspace)} type="button">
                    <Edit3 size={16} /> {tr("common.actions.edit")}
                  </Button>
                  <Button onClick={() => onClone(workspace.id)} type="button">
                    <Copy size={16} /> {tr("common.actions.clone")}
                  </Button>
                  {isRunning ? (
                    <Button onClick={() => onStop(workspace.id)} type="button">
                      <PauseCircle size={16} /> {tr("common.actions.freeze")}
                    </Button>
                  ) : (
                    <Button onClick={() => onStart(workspace.id)} type="button">
                      <PlayCircle size={16} /> {tr("common.actions.resume")}
                    </Button>
                  )}
                  <Button
                    onClick={() => onDelete(workspace.id)}
                    type="button"
                    variant="danger"
                  >
                    <Trash2 size={16} /> {tr("common.actions.delete")}
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
  emptyMessage = tr("thinClients.empty"),
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
      ? tr("common.actions.copied")
      : copyState === "failed"
        ? tr("common.actions.copyFailed")
        : tr("common.actions.copy");

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
          <strong>{tr("thinClients.installCommand")}</strong>
          <Button
            aria-label={tr("thinClients.copyCommand", { action: copyLabel })}
            onClick={copyClientCommand}
            type="button"
          >
            <Copy size={16} /> {copyLabel}
          </Button>
        </div>
        <CommandBox selectable>{clientCommand}</CommandBox>
      </div>
      {isLoading ? (
        <DataNotice state="loading" title={tr("thinClients.loading")} />
      ) : errorMessage ? (
        <DataNotice
          description={errorMessage}
          state="error"
          title={tr("thinClients.unavailable")}
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
                    aria-label={tr("thinClients.deleteClient", { hostname: client.hostname })}
                    onClick={() => onDelete(client.id)}
                    type="button"
                    variant="danger"
                  >
                    <Trash2 size={16} /> {tr("common.actions.delete")}
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
  emptyMessage = tr("access.empty"),
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
            <th>{tr("access.grantee")}</th>
            <th>{tr("common.fields.resource")}</th>
            <th>{tr("common.fields.scopes")}</th>
            <th>{tr("common.fields.status")}</th>
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            <TableNoticeRow
              colSpan={4}
              state="loading"
              title={tr("access.loading")}
            />
          ) : errorMessage ? (
            <TableNoticeRow
              colSpan={4}
              state="error"
              title={tr("access.unavailable")}
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
  emptyMessage = tr("audit.empty"),
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
            <th>{tr("common.fields.time")}</th>
            <th>{tr("common.fields.event")}</th>
            <th>{tr("common.fields.actor")}</th>
            <th>{tr("common.fields.status")}</th>
          </tr>
        </thead>
        <tbody>
          {isLoading ? (
            <TableNoticeRow
              colSpan={4}
              state="loading"
              title={tr("audit.loading")}
            />
          ) : errorMessage ? (
            <TableNoticeRow
              colSpan={4}
              state="error"
              title={tr("audit.unavailable")}
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
  emptyMessage = tr("monitoring.empty"),
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
            <strong>{tr("monitoring.sessions")}</strong>
            <span className="muted">{tr("monitoring.sessionCount", { count: sessions.length })}</span>
          </div>
          <TableFrame compact>
            <table>
              <thead>
                <tr>
                  <th>{tr("common.fields.status")}</th>
                  <th>{tr("common.fields.origin")}</th>
                  <th>{tr("common.fields.resource")}</th>
                  <th>{tr("common.fields.command")}</th>
                  <th>{tr("common.fields.lines")}</th>
                  <th>{tr("common.fields.updated")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <TableNoticeRow colSpan={7} state="loading" title={tr("monitoring.loadingSessions")} />
                ) : errorMessage ? (
                  <TableNoticeRow colSpan={7} state="error" title={tr("monitoring.sessionsUnavailable")} description={errorMessage} />
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
                          <PauseCircle size={16} /> {tr("common.actions.stop")}
                        </Button>
                        <Button disabled={!isRunningStatus(session.status)} onClick={(event) => { event.stopPropagation(); onForceTerminate(session.id); }} type="button" variant="danger">
                          <Trash2 size={16} /> {tr("common.actions.kill")}
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
              <span>{tr("common.rowsPerPage")}</span>
              <Button type="button">{rowsPerPage}</Button>
              <span className="spacer" />
              <span>{tr("common.range", { start: pageStart + 1, end: pageEnd, total: sessions.length })}</span>
              <IconButton aria-label={tr("monitoring.previousSessionsPage")} disabled={safePage <= 1} onClick={() => setPage((current) => Math.max(1, current - 1))} type="button">
                <ChevronLeft size={16} />
              </IconButton>
              {Array.from({ length: totalPages }, (_, index) => index + 1).map((pageNumber) => (
                <Button className={`page ${pageNumber === safePage ? "active" : ""}`} key={pageNumber} onClick={() => setPage(pageNumber)} type="button">
                  {pageNumber}
                </Button>
              ))}
              <IconButton aria-label={tr("monitoring.nextSessionsPage")} disabled={safePage >= totalPages} onClick={() => setPage((current) => Math.min(totalPages, current + 1))} type="button">
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
            <strong>{selected ? selected.name ?? selected.command : tr("monitoring.sessionOutput")}</strong>
            {selected ? (
              <span className="muted">
                {originLabel(selected.origin)} · {sessionResourceLabel(selected)}
              </span>
            ) : null}
          </div>
          {selected ? <StatusPill status={selected.status} /> : null}
        </div>
        {outputIsLoading ? (
          <DataNotice state="loading" title={tr("monitoring.loadingOutput")} />
        ) : outputErrorMessage ? (
          <DataNotice state="error" title={tr("monitoring.outputUnavailable")} description={outputErrorMessage} />
        ) : !output || output.lines.length === 0 ? (
          <DataNotice title={tr("monitoring.noOutput")} />
        ) : (
          <div className="session-output selectable">
            {output.lines.map((line) => (
              <div className={`output-line ${line.stream}`} key={line.line}>
                <span className="line-number">{line.line}</span>
                <span className="line-markers">
                  {line.auto_sent ? <span className="context-badge auto">{tr("monitoring.auto")}</span> : null}
                  {line.agent_requested ? <span className="context-badge requested">{tr("monitoring.agent")}</span> : null}
                </span>
                <code>{line.text}</code>
              </div>
            ))}
          </div>
        )}
        <div className="tool-history">
          <strong>{tr("monitoring.agentToolHistory")}</strong>
          {toolCalls.length === 0 ? (
            <span className="muted">{tr("monitoring.noToolCalls")}</span>
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
          <strong>{tr("monitoring.recentFileChanges")}</strong>
          <span className="muted">{tr("monitoring.changeCount", { count: fileChanges.length })}</span>
        </div>
        {fileChangesIsLoading ? (
          <DataNotice state="loading" title={tr("monitoring.loadingChanges")} />
        ) : fileChangesErrorMessage ? (
          <DataNotice state="error" title={tr("monitoring.changesUnavailable")} description={fileChangesErrorMessage} />
        ) : fileChanges.length === 0 ? (
          <DataNotice title={tr("monitoring.noChanges")} />
        ) : (
          <div className="file-change-list">
            {fileChanges.map((change) => (
              <article className="file-change-card" key={change.id}>
                <header>
                  <div>
                    <strong>{change.path}</strong>
                    <span>{change.operation} · {change.origin}</span>
                  </div>
                  <div className="diff-stats" aria-label={tr("monitoring.diffStats", { path: change.path })}>
                    <span className="diff-added">+{change.added_lines}</span>
                    <span className="diff-removed">-{change.removed_lines}</span>
                    {change.truncated ? <span className="context-badge requested">{tr("monitoring.truncated")}</span> : null}
                    {change.suppressed ? <span className="context-badge auto">{tr("monitoring.suppressed")}</span> : null}
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
        {tr("monitoring.diffSuppressed", { reason: diff?.reason ? `: ${diff.reason}` : "." })}
      </div>
    );
  }
  if (!diff.hunks.length) {
    return <div className="diff-suppressed">{tr("monitoring.noVisibleChanges")}</div>;
  }
  return (
    <pre className="diff-view selectable" aria-label={tr("monitoring.diffFor", { path: change.path })}>
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
  if (status === "verified") return tr("devices.readiness.mcpReady");
  if (status === "reachable") return tr("devices.readiness.tcpOnly");
  if (status === "host_key_untrusted") return tr("devices.readiness.hostKeyUntrusted");
  if (status === "auth_failed") return tr("devices.readiness.authFailed");
  if (status === "unreachable") return tr("devices.readiness.unreachable");
  return tr("devices.readiness.needsTest");
}

function sshReadinessClass(status: string) {
  if (status === "verified") return "ready";
  if (status === "reachable" || status === "registered") return "partial";
  if (status === "auth_failed" || status === "host_key_untrusted" || status === "unreachable") return "blocked";
  return "partial";
}

function sshMcpToolSummary(status: string) {
  if (status === "verified") return tr("devices.mcp.readyDetail");
  if (status === "auth_failed") return tr("devices.mcp.credentialsAttention");
  if (status === "host_key_untrusted") return tr("devices.mcp.fingerprintBlocked");
  if (status === "unreachable") return tr("devices.mcp.hostBlocked");
  return tr("devices.mcp.runTest");
}

function originLabel(origin: string) {
  if (origin === "ssh") return tr("monitoring.origins.sshHost");
  if (origin === "thin_client") return tr("monitoring.origins.thinClient");
  if (origin === "docker") return tr("monitoring.origins.docker");
  if (origin === "server") return tr("monitoring.origins.server");
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
