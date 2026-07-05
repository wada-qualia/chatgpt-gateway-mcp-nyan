import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Box, Download, FileText, KeyRound, Plus, Server, TerminalSquare } from 'lucide-react';
import {
  AccessGrantsTable,
  AuditEventsTable,
  DeviceDetailPanel,
  DeviceForm,
  DeviceTable,
  DockerWorkspaceGrid,
  GatewaySidebar,
  GatewayToolbar,
  GatewayTopbar,
  ThinClientPanel,
  type GatewayNavItem
} from '@gateway/components';
import { Button } from '@gateway/ui';
import { api } from '@gateway/generated/client';
import { fallbackAudit, fallbackDevices, fallbackGrants, fallbackThinClients, fallbackWorkspaces } from '@gateway/shared/fallbackData';

export type GatewayPageId = 'devices' | 'workspaces' | 'thin' | 'access' | 'audit';

const nav: GatewayNavItem[] = [
  { id: 'devices', label: 'Devices', icon: Server },
  { id: 'workspaces', label: 'Docker Workspaces', icon: Box },
  { id: 'thin', label: 'Thin Clients', icon: TerminalSquare },
  { id: 'access', label: 'ChatGPT Access', icon: KeyRound },
  { id: 'audit', label: 'Audit', icon: FileText }
];

export function GatewayDashboardPage({ initialPage = 'devices' }: { initialPage?: GatewayPageId }) {
  const controller = useGatewayController(initialPage);

  return (
    <div className="app-shell">
      <GatewaySidebar active={controller.active} items={nav} onSelect={(id) => controller.setActive(id as GatewayPageId)} />
      <main className="workspace">
        <GatewayTopbar user={controller.me.data} />
        <GatewayToolbar
          onCloneWorkspace={() => controller.cloneWorkspace.mutate()}
          onCreateDevice={() => controller.createDevice.mutate()}
          onCreateWorkspace={() => controller.createWorkspace.mutate()}
          onInstallClient={() => controller.installClient.mutate()}
        />
        <section className="content-grid">
          <div className="main-pane">
            <ActiveGatewayPage controller={controller} />
          </div>
          <DeviceDetailPanel selected={controller.selected} thinClients={controller.thinClients.length} workspaces={controller.workspaces.length} />
        </section>
      </main>
    </div>
  );
}

export function DevicesRemote() {
  const controller = useGatewayController('devices');
  return <RemotePageFrame><DevicesPage controller={controller} /></RemotePageFrame>;
}

export function DockerWorkspacesRemote() {
  const controller = useGatewayController('workspaces');
  return <RemotePageFrame><DockerWorkspacesPage controller={controller} /></RemotePageFrame>;
}

export function ThinClientsRemote() {
  const controller = useGatewayController('thin');
  return <RemotePageFrame><ThinClientsPage controller={controller} /></RemotePageFrame>;
}

export function ChatGPTAccessRemote() {
  const controller = useGatewayController('access');
  return <RemotePageFrame><ChatGPTAccessPage controller={controller} /></RemotePageFrame>;
}

export function AuditRemote() {
  const controller = useGatewayController('audit');
  return <RemotePageFrame><AuditPage controller={controller} /></RemotePageFrame>;
}

export function DevicesPage({ controller }: { controller: GatewayController }) {
  return (
    <>
      <div className="section-title">
        <h1>Devices</h1>
      </div>
      <DeviceTable
        devices={controller.filteredDevices}
        onSearch={controller.setSearch}
        onSelect={controller.setSelectedId}
        search={controller.search}
        selectedId={controller.selected?.id}
        total={controller.devices.length}
      />
      <DeviceForm
        authType={controller.authType}
        onCreate={() => controller.createDevice.mutate()}
        secret={controller.secret}
        setAuthType={controller.setAuthType}
        setSecret={controller.setSecret}
        setTarget={controller.setTarget}
        target={controller.target}
      />
    </>
  );
}

export function DockerWorkspacesPage({ controller }: { controller: GatewayController }) {
  return (
    <div className="subview">
      <div className="section-title">
        <h1>Docker Workspaces</h1>
        <Button variant="solid" onClick={() => controller.createWorkspace.mutate()} type="button"><Plus size={18} /> Create Ubuntu</Button>
      </div>
      <DockerWorkspaceGrid onClone={() => controller.cloneWorkspace.mutate()} workspaces={controller.workspaces} />
    </div>
  );
}

export function ThinClientsPage({ controller }: { controller: GatewayController }) {
  return (
    <div className="subview">
      <div className="section-title">
        <h1>Thin Clients</h1>
        <Button variant="solid" onClick={() => controller.installClient.mutate()} type="button"><Download size={18} /> Issue device code</Button>
      </div>
      <ThinClientPanel clientCommand={controller.clientCommand} thinClients={controller.thinClients} />
    </div>
  );
}

export function ChatGPTAccessPage({ controller }: { controller: GatewayController }) {
  return (
    <div className="subview">
      <div className="section-title"><h1>ChatGPT Access</h1></div>
      <AccessGrantsTable grants={controller.grants} />
    </div>
  );
}

export function AuditPage({ controller }: { controller: GatewayController }) {
  return (
    <div className="subview">
      <div className="section-title"><h1>Audit</h1></div>
      <AuditEventsTable audit={controller.audit} />
    </div>
  );
}

function ActiveGatewayPage({ controller }: { controller: GatewayController }) {
  if (controller.active === 'workspaces') return <DockerWorkspacesPage controller={controller} />;
  if (controller.active === 'thin') return <ThinClientsPage controller={controller} />;
  if (controller.active === 'access') return <ChatGPTAccessPage controller={controller} />;
  if (controller.active === 'audit') return <AuditPage controller={controller} />;
  return <DevicesPage controller={controller} />;
}

function RemotePageFrame({ children }: { children: ReactNode }) {
  return <div className="remote-page">{children}</div>;
}

function useGatewayController(initialPage: GatewayPageId) {
  const [active, setActive] = useState<GatewayPageId>(initialPage);
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
  const filteredDevices = useMemo(
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

  return {
    active,
    audit,
    authType,
    clientCommand,
    cloneWorkspace,
    createDevice,
    createWorkspace,
    devices,
    filteredDevices,
    grants,
    installClient,
    me,
    search,
    secret,
    selected,
    setActive,
    setAuthType,
    setSearch,
    setSecret,
    setSelectedId,
    setTarget,
    target,
    thinClients,
    workspaces
  };
}

export type GatewayController = ReturnType<typeof useGatewayController>;
