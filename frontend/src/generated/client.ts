export type GatewayUser = {
  subject: string;
  username: string;
  email: string | null;
  roles: string[];
  provider: string;
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
  image: string;
  container_name: string;
  container_id: string | null;
  status: string;
  source_workspace_id: string | null;
  created_at: string;
  updated_at: string;
};

export type ThinClient = {
  id: string;
  owner_subject: string;
  hostname: string;
  directory: string;
  status: string;
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
  devices: () => request<Device[]>('/api/devices'),
  createDevice: (payload: { name: string; target: string; auth_type: string; password?: string; private_key?: string }) =>
    request<Device>('/api/devices', { method: 'POST', body: JSON.stringify(payload) }),
  images: () => request<{ images: string[] }>('/api/docker/images'),
  workspaces: () => request<Workspace[]>('/api/docker/workspaces'),
  createWorkspace: (payload: { name: string; image: string }) =>
    request<Workspace>('/api/docker/workspaces', { method: 'POST', body: JSON.stringify(payload) }),
  cloneWorkspace: (payload: { source_workspace_id: string; name: string }) =>
    request<Workspace>('/api/docker/workspaces/clone', { method: 'POST', body: JSON.stringify(payload) }),
  thinClients: () => request<ThinClient[]>('/api/thin-clients'),
  createDeviceCode: () => request<{ user_code: string; verification_uri: string }>('/api/thin-clients/device-code', { method: 'POST', body: '{}' }),
  grants: () => request<AccessGrant[]>('/api/access/grants'),
  audit: () => request<AuditEvent[]>('/api/audit/events')
};
