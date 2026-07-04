import type { AccessGrant, AuditEvent, Device, ThinClient, Workspace } from '../generated/client';

const now = new Date().toISOString();

export const fallbackDevices: Device[] = [
  { id: '1', owner_subject: 'dev:local', name: 'bastion-01.k-lab.io', kind: 'ssh', host: '10.10.1.11', port: 22, username: 'ubuntu', auth_type: 'private_key', status: 'online', created_at: now, updated_at: now },
  { id: '2', owner_subject: 'dev:local', name: 'devbox-01.k-lab.io', kind: 'ssh', host: '10.10.1.21', port: 22, username: 'devops', auth_type: 'private_key', status: 'online', created_at: now, updated_at: now },
  { id: '3', owner_subject: 'dev:local', name: 'build-02.k-lab.io', kind: 'ssh', host: '10.10.1.32', port: 22, username: 'ubuntu', auth_type: 'password', status: 'pending', created_at: now, updated_at: now },
  { id: '4', owner_subject: 'dev:local', name: 'legacy-ssh.k-lab.io', kind: 'ssh', host: '10.10.1.45', port: 22, username: 'admin', auth_type: 'password', status: 'error', created_at: now, updated_at: now }
];

export const fallbackWorkspaces: Workspace[] = [
  { id: 'w1', owner_subject: 'dev:local', name: 'ubuntu-lab', image: 'ubuntu:24.04', container_name: 'gw-darius-ubuntu-lab', container_id: null, status: 'pending', source_workspace_id: null, created_at: now, updated_at: now },
  { id: 'w2', owner_subject: 'dev:local', name: 'clone-staging', image: 'ubuntu:22.04', container_name: 'gw-darius-clone-staging', container_id: null, status: 'pending', source_workspace_id: 'w1', created_at: now, updated_at: now }
];

export const fallbackThinClients: ThinClient[] = [
  { id: 't1', owner_subject: 'dev:local', hostname: 'macbook-pro', directory: '/Users/darius/Documents/hello-world', status: 'online', created_at: now, last_seen_at: now },
  { id: 't2', owner_subject: 'dev:local', hostname: 'lab-mini', directory: '/opt/projects/agent', status: 'offline', created_at: now, last_seen_at: now }
];

export const fallbackGrants: AccessGrant[] = [
  { id: 'g1', owner_subject: 'dev:local', grantee_subject: 'chatgpt:connector', resource_type: 'device', resource_id: '2', scopes: ['workspace:read', 'workspace:exec'], status: 'active', created_at: now }
];

export const fallbackAudit: AuditEvent[] = [
  { id: 'a1', event_type: 'gateway.user.authenticated.v1', actor_subject: 'dev:local', action: 'authenticated', resource_type: 'user', resource_id: 'dev:local', status: 'success', payload: {}, created_at: now },
  { id: 'a2', event_type: 'gateway.device.registered.v1', actor_subject: 'dev:local', action: 'registered', resource_type: 'device', resource_id: '2', status: 'success', payload: {}, created_at: now },
  { id: 'a3', event_type: 'gateway.workspace.created.v1', actor_subject: 'dev:local', action: 'created', resource_type: 'docker_workspace', resource_id: 'w1', status: 'success', payload: {}, created_at: now }
];
