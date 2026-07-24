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


export type McpCredentialBinding = {
  id: string;
  owner_subject: string;
  binding_type: 'oauth' | 'service_account' | 'thin_client_local';
  provider: string | null;
  secret_blob_id: string | null;
  audience: string | null;
  scopes: string[];
  status: string;
  version: number;
  meta: Record<string, unknown>;
  rotated_at: string | null;
  revoked_at: string | null;
  created_at: string;
  updated_at: string;
};

export type McpServer = {
  id: string;
  owner_subject: string;
  normalized_slug: string;
  display_name: string;
  origin: 'gateway' | 'thin_client';
  transport: string;
  endpoint_url: string | null;
  credential_binding_id: string | null;
  status: string;
  trust_level: string;
  negotiated_protocol_version: string | null;
  capabilities: Record<string, unknown>;
  catalog_generation: number;
  policy_generation: number;
  last_connected_at: string | null;
  last_catalog_refreshed_at: string | null;
  disabled_at: string | null;
  quarantine_reason: string | null;
  version: number;
  created_at: string;
  updated_at: string;
};

export type McpServerHealth = {
  server_id: string;
  status: string;
  trust_level: string;
  catalog_generation: number;
  negotiated_protocol_version: string | null;
  last_connected_at: string | null;
  last_catalog_refreshed_at: string | null;
  latency_ms: number | null;
  tool_count: number | null;
  session_id_present: boolean | null;
  circuit_state: 'closed' | 'open' | 'half_open';
  normalized_error_code: string | null;
};

export type McpOAuthAuthorizationStarted = {
  server_id: string;
  binding_id: string;
  authorization_url: string;
  state: string;
  expires_at: string;
};


export type McpTool = {
  id: string;
  owner_subject: string;
  server_id: string;
  upstream_name: string;
  normalized_name: string;
  lifecycle_state: string;
  current_revision_id: string | null;
  version: number;
  first_observed_at: string;
  last_observed_at: string;
  created_at: string;
  updated_at: string;
};

export type McpToolRevision = {
  id: string;
  owner_subject: string;
  server_id: string;
  tool_id: string;
  revision_number: number;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown> | null;
  sanitized_title: string | null;
  sanitized_description: string;
  annotations: Record<string, unknown>;
  schema_hash: string;
  protocol_version: string | null;
  catalog_generation: number;
  action_class: string;
  read_only_status: string;
  risk_evidence: Record<string, unknown>;
  version: number;
  classified_by_subject: string | null;
  classified_at: string | null;
  superseded_by_revision_id: string | null;
  discovered_at: string;
  created_at: string;
};

export type McpToolExposure = {
  id: string;
  owner_subject: string;
  server_id: string;
  tool_id: string;
  revision_id: string;
  mode: 'hidden' | 'catalog_only' | 'native_projected';
  projected_name: string | null;
  enabled: boolean;
  required_role: string | null;
  required_scope: string | null;
  approval_class: string;
  projection_generation: number;
  policy_generation: number;
  version: number;
  reviewed_by_subject: string | null;
  reviewed_at: string | null;
  created_at: string;
  updated_at: string;
};

export type McpPresentationProfileId = 'chatgpt-stable' | 'developer-dynamic' | 'agent-restricted';

export type McpPresentationProfile = {
  id: McpPresentationProfileId;
  label: string;
  description: string;
  supports_list_changed: boolean;
  chatgpt_refresh_required: boolean;
};

export type McpProjectionTool = {
  id: string;
  position: number;
  public_name: string;
  revision_id: string;
  source_schema_hash: string;
  input_schema: Record<string, unknown>;
  output_schema: Record<string, unknown> | null;
  sanitized_title: string | null;
  sanitized_description: string;
  annotations: Record<string, unknown>;
  action_class: string;
  required_role: string | null;
  required_scope: string | null;
  approval_class: string;
  change_classification: string;
};

export type McpProjectionGeneration = {
  id: string;
  profile_id: McpPresentationProfileId;
  generation_number: number;
  status: 'candidate' | 'active' | 'superseded' | 'retired';
  previous_generation_id: string | null;
  content_hash: string;
  schema_hash: string;
  change_summary: { counts?: Record<string, number>; removed?: string[]; tool_count?: number };
  tools_list_changed_state: 'not_required' | 'pending' | 'notified';
  chatgpt_refresh_state: 'not_required' | 'pending' | 'verified';
  created_by_subject: string;
  published_by_subject: string | null;
  created_at: string;
  published_at: string | null;
  updated_at: string;
  tools?: McpProjectionTool[];
};

export type McpOAuthPresentation = {
  client_id: string;
  client_name: string;
  presentation_profile: McpPresentationProfileId;
  presentation_policy_generation: number;
  allowed_tool_names: string[];
  updated_at: string;
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
  createDevice: (payload: { name: string; target: string; auth_type: string; password?: string; private_key?: string; verify_connection?: boolean }) =>
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
  mcpServers: () => request<McpServer[]>('/api/mcp/servers'),
  mcpCredentialBindings: () => request<McpCredentialBinding[]>('/api/mcp/credential-bindings'),
  createMcpCredentialMaterial: (payload: {
    binding_type: 'service_account';
    mode: 'bearer' | 'header';
    provider?: string | null;
    access_token?: string;
    header_name?: string;
    header_value?: string;
    scopes?: string[];
  }, idempotencyKey: string) =>
    request<McpCredentialBinding>('/api/mcp/credential-bindings/material', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(payload)
    }),
  createMcpServer: (payload: {
    display_name: string;
    origin: 'gateway';
    transport: 'streamable_http';
    endpoint_url: string;
    thin_client_id: null;
    runtime_id: null;
    credential_binding_id: string | null;
  }, idempotencyKey: string) =>
    request<McpServer>('/api/mcp/servers', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(payload)
    }),
  testMcpServer: (serverId: string) =>
    request<McpServerHealth>(`/api/mcp/servers/${serverId}/test`, { method: 'POST', body: '{}' }),
  refreshMcpServer: (server: Pick<McpServer, 'id' | 'version'>, idempotencyKey: string) =>
    request<McpServer>(`/api/mcp/servers/${server.id}/refresh`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expected_version: server.version })
    }),
  disableMcpServer: (server: Pick<McpServer, 'id' | 'version'>, idempotencyKey: string) =>
    request<McpServer>(`/api/mcp/servers/${server.id}`, {
      method: 'DELETE',
      headers: {
        'Idempotency-Key': idempotencyKey,
        'If-Match': String(server.version)
      }
    }),
  enableMcpServer: (server: Pick<McpServer, 'id' | 'version'>, idempotencyKey: string) =>
    request<McpServer>(`/api/mcp/servers/${server.id}`, {
      method: 'PATCH',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expected_version: server.version, enabled: true })
    }),
  mcpServerTools: (serverId: string) =>
    request<McpTool[]>(`/api/mcp/servers/${serverId}/tools`),
  mcpToolRevisions: (toolId: string) =>
    request<McpToolRevision[]>(`/api/mcp/tools/${toolId}/revisions`),
  mcpToolExposure: (toolId: string) =>
    request<McpToolExposure | null>(`/api/mcp/tools/${toolId}/exposure`),
  startMcpOAuth: (server: Pick<McpServer, 'id' | 'version'>, payload: {
    authorization_endpoint: string;
    token_endpoint: string;
    client_id: string;
    client_secret?: string;
    redirect_uri: string;
    scopes: string[];
    audience: string;
    extra_authorization_parameters?: Record<string, string>;
  }, idempotencyKey: string) =>
    request<McpOAuthAuthorizationStarted>(`/api/mcp/servers/${server.id}/oauth/start`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({ expected_version: server.version, ...payload })
    }),
  completeMcpOAuth: (state: string, code: string) =>
    request<McpCredentialBinding>('/api/mcp/oauth/complete', {
      method: 'POST',
      body: JSON.stringify({ state, code })
    }),
  mcpPresentationProfiles: () =>
    request<McpPresentationProfile[]>('/api/mcp/presentation-profiles'),
  mcpOAuthPresentations: () =>
    request<McpOAuthPresentation[]>('/api/mcp/oauth-clients/presentation'),
  updateMcpOAuthPresentation: (clientId: string, payload: {
    profile_id: McpPresentationProfileId;
    allowed_tool_names?: string[];
  }) => request<McpOAuthPresentation>(`/api/mcp/oauth-clients/${clientId}/presentation`, {
    method: 'PATCH',
    body: JSON.stringify(payload)
  }),
  mcpProjectionGenerations: (profileId?: McpPresentationProfileId) => {
    const suffix = profileId ? `?profile_id=${encodeURIComponent(profileId)}` : '';
    return request<McpProjectionGeneration[]>(`/api/mcp/projection-generations${suffix}`);
  },
  createMcpProjectionGeneration: (payload: {
    profile_id: McpPresentationProfileId;
    exposure_ids?: string[];
  }) => request<McpProjectionGeneration>('/api/mcp/projection-generations', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),
  mcpProjectionGeneration: (generationId: string) =>
    request<McpProjectionGeneration>(`/api/mcp/projection-generations/${generationId}`),
  publishMcpProjectionGeneration: (generationId: string) =>
    request<McpProjectionGeneration>(`/api/mcp/projection-generations/${generationId}/publish`, { method: 'POST', body: '{}' }),
  rollbackMcpProjectionGeneration: (generationId: string) =>
    request<McpProjectionGeneration>(`/api/mcp/projection-generations/${generationId}/rollback`, { method: 'POST', body: '{}' }),
  verifyMcpProjectionGeneration: (generation: Pick<McpProjectionGeneration, 'id' | 'schema_hash'>, verificationKind: 'generic_tools_list_changed' | 'chatgpt_actions', evidence: Record<string, unknown>) =>
    request<{ generation: McpProjectionGeneration }>(`/api/mcp/projection-generations/${generation.id}/verify`, {
      method: 'POST',
      body: JSON.stringify({ verification_kind: verificationKind, observed_schema_hash: generation.schema_hash, evidence })
    }),
  audit: () => request<AuditEvent[]>('/api/audit/events')
};
