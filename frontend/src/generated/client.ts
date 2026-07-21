export type GatewayUser = {
  subject: string;
  username: string;
  email: string | null;
  roles: string[];
  provider: string;
};

export type SshCommandProfile = 'restricted' | 'filtered' | 'unrestricted';

export type UiLanguage = 'en' | 'ru';

export type AccountSettings = {
  ui_language: UiLanguage;
  ssh_command_profile: SshCommandProfile;
  ssh_command_profile_override: SshCommandProfile | null;
  ssh_command_profile_default: SshCommandProfile;
  raw_commands_enabled: boolean;
  deny_patterns_enabled: boolean;
};

export type Device = {
  id: string;
  owner_subject: string;
  name: string;
  kind: string;
  host: string;
  port: number;
  username: string;
  auth_type: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Workspace = {
  id: string;
  owner_subject: string;
  name: string;
  description: string | null;
  image: string;
  container_name: string;
  container_id: string | null;
  status: string;
  source_workspace_id: string | null;
  created_at: string;
  updated_at: string;
};

export type WorkspaceExecResult = {
  exit_code: number | null;
  output: string;
  session_id?: string | null;
  status?: string | null;
  backgrounded?: boolean;
  recommendation?: string | null;
};

export type ThinClient = {
  id: string;
  owner_subject: string;
  hostname: string;
  directory: string;
  status: string;
  meta: {
    labels?: Record<string, string>;
  } & Record<string, unknown>;
  created_at: string;
  last_seen_at: string;
};

export type AccessGrant = {
  id: string;
  owner_subject: string;
  grantee_subject: string;
  resource_type: string;
  resource_id: string;
  scopes: string[];
  status: string;
  created_at: string;
};

export type AuditEvent = {
  id: string;
  event_type: string;
  actor_subject: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  status: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type CommandOutputLine = {
  line: number;
  stream: string;
  text: string;
  timestamp: string | null;
  auto_sent: boolean;
  agent_requested: boolean;
};

export type CommandSession = {
  id: string;
  owner_subject: string;
  origin: string;
  resource_id: string | null;
  name: string | null;
  command: string;
  cwd: string;
  status: string;
  pid: string | null;
  exit_code: number | null;
  line_count: number;
  truncated: boolean;
  meta: Record<string, unknown>;
  created_at: string;
  started_at: string;
  completed_at: string | null;
  updated_at: string;
};

export type CommandSessionOutput = {
  session_id: string;
  start_line: number;
  end_line: number;
  total_lines: number;
  lines: CommandOutputLine[];
};

export type AgentToolCall = {
  id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  status: string;
  session_id: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
};

export type FileChangeDiffLine = {
  kind: 'context' | 'delete' | 'insert';
  text: string;
};

export type FileChangeDiffHunk = {
  old_start: number;
  old_count: number;
  new_start: number;
  new_count: number;
  lines: FileChangeDiffLine[];
};

export type FileChangeDiff = {
  format: string;
  suppressed: boolean;
  reason?: string | null;
  truncated: boolean;
  added_lines: number;
  removed_lines: number;
  hunks: FileChangeDiffHunk[];
};

export type FileChangeSet = {
  id: string;
  owner_subject: string;
  origin: string;
  resource_id: string | null;
  tool_call_id: string | null;
  path: string;
  operation: string;
  added_lines: number;
  removed_lines: number;
  bytes_before: number;
  bytes_after: number;
  replacements: number;
  diff_json: FileChangeDiff;
  truncated: boolean;
  suppressed: boolean;
  created_at: string;
};

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers ?? {})
    },
    ...init
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<T>;
}

export const api = {
  me: () => request<GatewayUser>('/auth/me'),
  accountSettings: () => request<AccountSettings>('/api/account/settings'),
  updateAccountSettings: (payload: {
    ui_language?: UiLanguage;
    ssh_command_profile?: 'inherit' | SshCommandProfile;
  }) =>
    request<AccountSettings>('/api/account/settings', {
      method: 'PATCH',
      body: JSON.stringify(payload)
    }),
  devices: () => request<Device[]>('/api/devices'),
  createDevice: (payload: { name: string; target: string; auth_type: string; password?: string; private_key?: string }) =>
    request<Device>('/api/devices', { method: 'POST', body: JSON.stringify(payload) }),
  updateDevice: (deviceId: string, payload: { name?: string; target?: string; auth_type?: string; password?: string; private_key?: string }) =>
    request<Device>(`/api/devices/${deviceId}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  testDeviceConnection: (deviceId: string) =>
    request<Device>(`/api/devices/${deviceId}/test`, { method: 'POST', body: '{}' }),
  deleteDevice: (deviceId: string) =>
    request<{ ok: boolean }>(`/api/devices/${deviceId}`, { method: 'DELETE' }),
  images: () => request<{ images: string[] }>('/api/docker/images'),
  workspaces: () => request<Workspace[]>('/api/docker/workspaces'),
  createWorkspace: (payload: { name: string; image: string }) =>
    request<Workspace>('/api/docker/workspaces', { method: 'POST', body: JSON.stringify(payload) }),
  cloneWorkspace: (payload: { source_workspace_id: string; name: string }) =>
    request<Workspace>('/api/docker/workspaces/clone', { method: 'POST', body: JSON.stringify(payload) }),
  updateWorkspace: (workspaceId: string, payload: { name?: string; description?: string | null }) =>
    request<Workspace>(`/api/docker/workspaces/${workspaceId}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  stopWorkspace: (workspaceId: string) =>
    request<Workspace>(`/api/docker/workspaces/${workspaceId}/stop`, { method: 'POST', body: '{}' }),
  startWorkspace: (workspaceId: string) =>
    request<Workspace>(`/api/docker/workspaces/${workspaceId}/start`, { method: 'POST', body: '{}' }),
  deleteWorkspace: (workspaceId: string) =>
    request<{ ok: boolean }>(`/api/docker/workspaces/${workspaceId}`, { method: 'DELETE' }),
  execWorkspace: (workspaceId: string, payload: { command: string; timeout_seconds?: number; workdir?: string; background?: boolean; session_name?: string }) =>
    request<WorkspaceExecResult>(`/api/docker/workspaces/${workspaceId}/exec`, { method: 'POST', body: JSON.stringify(payload) }),
  thinClients: () => request<ThinClient[]>('/api/thin-clients'),
  createDeviceCode: () => request<{ device_code: string; user_code: string; verification_uri: string; interval?: number }>('/api/thin-clients/device-code', { method: 'POST', body: '{}' }),
  callThinClientTool: (clientId: string, payload: { tool: string; arguments?: Record<string, unknown>; timeout_seconds?: number }) =>
    request<{ ok: boolean; result?: Record<string, unknown>; error?: string }>(`/api/thin-clients/${clientId}/tools`, { method: 'POST', body: JSON.stringify(payload) }),
  deleteThinClient: (clientId: string) =>
    request<{ ok: boolean }>(`/api/thin-clients/${clientId}`, { method: 'DELETE' }),
  commandSessions: () => request<CommandSession[]>('/api/command-sessions'),
  fileChanges: (params: { limit?: number; origin?: string; resource_id?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', String(params.limit));
    if (params.origin) query.set('origin', params.origin);
    if (params.resource_id) query.set('resource_id', params.resource_id);
    const suffix = query.toString() ? `?${query.toString()}` : '';
    return request<FileChangeSet[]>(`/api/file-changes${suffix}`);
  },
  commandSessionOutput: (sessionId: string, params: { start_line?: number; limit?: number; tail?: number } = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) query.set(key, String(value));
    });
    const suffix = query.toString() ? `?${query.toString()}` : '';
    return request<CommandSessionOutput>(`/api/command-sessions/${sessionId}/output${suffix}`);
  },
  terminateCommandSession: (sessionId: string, payload: { force?: boolean } = {}) =>
    request<CommandSession>(`/api/command-sessions/${sessionId}/terminate`, { method: 'POST', body: JSON.stringify(payload) }),
  commandSessionToolCalls: (sessionId: string) =>
    request<AgentToolCall[]>(`/api/command-sessions/${sessionId}/tool-calls`),
  grants: () => request<AccessGrant[]>('/api/access/grants'),
  audit: () => request<AuditEvent[]>('/api/audit/events')
};
