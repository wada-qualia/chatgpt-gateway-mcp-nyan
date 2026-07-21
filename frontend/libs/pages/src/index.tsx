import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import {
  Activity,
  Box,
  Download,
  FileText,
  KeyRound,
  Plus,
  Server,
  Settings,
  TerminalSquare,
} from "lucide-react";
import {
  AccessGrantsTable,
  AuditEventsTable,
  DeviceDetailPanel,
  DeviceForm,
  DeviceTable,
  DockerWorkspaceGrid,
  GatewaySidebar,
  GatewayTopbar,
  MonitoringSessionsPanel,
  ThinClientPanel,
  type GatewayNavItem,
} from "@gateway/components";
import { Button } from "@gateway/ui";
import {
  api,
  type AccountSettings,
  type UiLanguage,
} from "@gateway/generated/client";
import i18n from "@gateway/shared/i18n";

export type GatewayPageId =
  | "devices"
  | "workspaces"
  | "thin"
  | "monitoring"
  | "access"
  | "audit"
  | "settings";

const pageRoutes: Record<GatewayPageId, string> = {
  devices: "/devices",
  workspaces: "/workspaces",
  thin: "/thin-clients",
  monitoring: "/monitoring",
  access: "/chatgpt-access",
  audit: "/audit",
  settings: "/settings",
};

const pageByPath: Record<string, GatewayPageId> = {
  "/devices": "devices",
  "/workspaces": "workspaces",
  "/docker-workspaces": "workspaces",
  "/thin-clients": "thin",
  "/thin": "thin",
  "/monitoring": "monitoring",
  "/command-sessions": "monitoring",
  "/chatgpt-access": "access",
  "/access": "access",
  "/audit": "audit",
  "/settings": "settings",
};

const navDefinitions = [
  { id: "devices", labelKey: "nav.devices", icon: Server },
  { id: "workspaces", labelKey: "nav.workspaces", icon: Box },
  { id: "thin", labelKey: "nav.thinClients", icon: TerminalSquare },
  { id: "monitoring", labelKey: "nav.monitoring", icon: Activity },
  { id: "access", labelKey: "nav.access", icon: KeyRound },
  { id: "audit", labelKey: "nav.audit", icon: FileText },
  { id: "settings", labelKey: "nav.settings", icon: Settings },
] as const;

const DEVICE_PANEL_CLOSED = "__device_panel_closed__";

export function GatewayDashboardPage({
  initialPage = "devices",
}: {
  initialPage?: GatewayPageId;
}) {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const nav: GatewayNavItem[] = navDefinitions.map((item) => ({
    id: item.id,
    label: t(item.labelKey),
    icon: item.icon,
  }));
  const routePage = getPageFromPath(location.pathname);
  const activePage = routePage ?? initialPage;
  const setRoutePage = useCallback(
    (page: GatewayPageId) => navigate(pageRoutes[page]),
    [navigate],
  );
  const controller = useGatewayController(activePage, setRoutePage);

  if (location.pathname === "/" || routePage === null) {
    return <Navigate to={pageRoutes[activePage]} replace />;
  }

  return (
    <div className="app-shell">
        <GatewaySidebar
          active={controller.active}
          items={nav}
          onSelect={(id) => controller.setActive(id as GatewayPageId)}
        />
      <main className="workspace">
        <GatewayTopbar
          errorMessage={controller.meState.errorMessage}
          isLoading={controller.meState.isLoading}
          user={controller.me.data}
        />
        <section className={`content-grid ${controller.active === "devices" && controller.selected ? "" : "without-detail"}`}>
          <div className="main-pane">
            <OperationBanner message={controller.operationError} />
            <ActiveGatewayPage controller={controller} />
          </div>
          {controller.active === "devices" && controller.selected ? (
            <DeviceDetailPanel
              isDeleting={controller.deleteDevice.isPending}
              isTesting={controller.testDeviceConnection.isPending}
              isUpdating={controller.updateDevice.isPending}
              onClose={controller.closeDeviceDetails}
              onDelete={(deviceId) => controller.deleteDevice.mutate(deviceId)}
              onTestConnection={(deviceId) => controller.testDeviceConnection.mutate(deviceId)}
              onUpdate={(deviceId, payload) =>
                controller.updateDevice.mutate({ deviceId, payload })
              }
              selected={controller.selected}
              thinClients={controller.thinClients.length}
              workspaces={controller.workspaces.length}
            />
          ) : null}
        </section>
      </main>
    </div>
  );
}

function getPageFromPath(pathname: string): GatewayPageId | null {
  const normalized =
    pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  return pageByPath[normalized] ?? null;
}

export function DevicesRemote() {
  const controller = useGatewayController("devices");
  return (
    <RemotePageFrame>
      <DevicesPage controller={controller} />
    </RemotePageFrame>
  );
}

export function DockerWorkspacesRemote() {
  const controller = useGatewayController("workspaces");
  return (
    <RemotePageFrame>
      <DockerWorkspacesPage controller={controller} />
    </RemotePageFrame>
  );
}

export function ThinClientsRemote() {
  const controller = useGatewayController("thin");
  return (
    <RemotePageFrame>
      <ThinClientsPage controller={controller} />
    </RemotePageFrame>
  );
}

export function ChatGPTAccessRemote() {
  const controller = useGatewayController("access");
  return (
    <RemotePageFrame>
      <ChatGPTAccessPage controller={controller} />
    </RemotePageFrame>
  );
}

export function MonitoringRemote() {
  const controller = useGatewayController("monitoring");
  return (
    <RemotePageFrame>
      <MonitoringPage controller={controller} />
    </RemotePageFrame>
  );
}

export function AuditRemote() {
  const controller = useGatewayController("audit");
  return (
    <RemotePageFrame>
      <AuditPage controller={controller} />
    </RemotePageFrame>
  );
}

export function DevicesPage({ controller }: { controller: GatewayController }) {
  const { t } = useTranslation();
  return (
    <>
      <div className="section-title">
        <h1>{t("devices.title")}</h1>
      </div>
      <DeviceTable
        devices={controller.filteredDevices}
        emptyMessage={
          controller.devices.length === 0
            ? t("devices.empty")
            : t("devices.noMatch")
        }
        errorMessage={controller.devicesState.errorMessage}
        isLoading={controller.devicesState.isLoading}
        onSearch={controller.setSearch}
        onSelect={controller.setSelectedId}
        search={controller.search}
        selectedId={controller.selected?.id}
        total={controller.filteredDevices.length}
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

export function DockerWorkspacesPage({
  controller,
}: {
  controller: GatewayController;
}) {
  const { t } = useTranslation();
  return (
    <div className="subview">
      <div className="section-title">
        <h1>{t("workspaces.title")}</h1>
        <Button
          disabled={!controller.canCreateWorkspace}
          onClick={() => controller.createWorkspace.mutate()}
          title={controller.createWorkspaceTitle}
          type="button"
          variant="solid"
        >
          <Plus size={18} /> {t("workspaces.createUbuntu")}
        </Button>
      </div>
      <DockerWorkspaceGrid
        editDescription={controller.editWorkspaceDescription}
        editName={controller.editWorkspaceName}
        editingWorkspaceId={controller.editingWorkspaceId}
        emptyMessage={t("workspaces.empty")}
        errorMessage={controller.workspacesState.errorMessage}
        isLoading={controller.workspacesState.isLoading}
        onBeginEdit={controller.beginWorkspaceEdit}
        onCancelEdit={controller.cancelWorkspaceEdit}
        onClone={(workspaceId) => controller.cloneWorkspace.mutate(workspaceId)}
        onDelete={(workspaceId) =>
          controller.deleteWorkspace.mutate(workspaceId)
        }
        onEditDescription={controller.setEditWorkspaceDescription}
        onEditName={controller.setEditWorkspaceName}
        onSaveEdit={(workspaceId) =>
          controller.updateWorkspace.mutate(workspaceId)
        }
        onStart={(workspaceId) => controller.startWorkspace.mutate(workspaceId)}
        onStop={(workspaceId) => controller.stopWorkspace.mutate(workspaceId)}
        workspaces={controller.workspaces}
      />
    </div>
  );
}

export function ThinClientsPage({
  controller,
}: {
  controller: GatewayController;
}) {
  const { t } = useTranslation();
  return (
    <div className="subview">
      <div className="section-title">
        <h1>{t("thinClients.title")}</h1>
        <Button
          variant="solid"
          onClick={() => controller.installClient.mutate()}
          type="button"
        >
          <Download size={18} /> {t("thinClients.issueCode")}
        </Button>
      </div>
      <ThinClientPanel
        clientCommand={controller.clientCommand}
        emptyMessage={t("thinClients.empty")}
        errorMessage={controller.thinClientsState.errorMessage}
        isLoading={controller.thinClientsState.isLoading}
        onDelete={(clientId) => controller.deleteThinClient.mutate(clientId)}
        thinClients={controller.thinClients}
      />
    </div>
  );
}

export function ChatGPTAccessPage({
  controller,
}: {
  controller: GatewayController;
}) {
  const { t } = useTranslation();
  return (
    <div className="subview">
      <div className="section-title">
        <h1>{t("access.title")}</h1>
      </div>
      <AccessGrantsTable
        emptyMessage={t("access.empty")}
        errorMessage={controller.grantsState.errorMessage}
        grants={controller.grants}
        isLoading={controller.grantsState.isLoading}
      />
    </div>
  );
}

export function MonitoringPage({ controller }: { controller: GatewayController }) {
  const { t } = useTranslation();
  return (
    <div className="subview">
      <div className="section-title">
        <h1>{t("monitoring.title")}</h1>
      </div>
      <MonitoringSessionsPanel
        emptyMessage={t("monitoring.empty")}
        errorMessage={controller.commandSessionsState.errorMessage}
        fileChanges={controller.fileChanges}
        fileChangesErrorMessage={controller.fileChangesState.errorMessage}
        fileChangesIsLoading={controller.fileChangesState.isLoading}
        isLoading={controller.commandSessionsState.isLoading}
        onForceTerminate={(sessionId) =>
          controller.forceTerminateCommandSession.mutate(sessionId)
        }
        onSelect={controller.setSelectedCommandSessionId}
        onTerminate={(sessionId) =>
          controller.terminateCommandSession.mutate(sessionId)
        }
        output={controller.commandSessionOutput}
        outputErrorMessage={controller.commandSessionOutputState.errorMessage}
        outputIsLoading={controller.commandSessionOutputState.isLoading}
        selectedId={controller.selectedCommandSession?.id}
        sessions={controller.commandSessions}
        toolCalls={controller.commandSessionToolCalls}
      />
    </div>
  );
}

export function AuditPage({ controller }: { controller: GatewayController }) {
  const { t } = useTranslation();
  return (
    <div className="subview">
      <div className="section-title">
        <h1>{t("audit.title")}</h1>
      </div>
      <AuditEventsTable
        audit={controller.audit}
        emptyMessage={t("audit.empty")}
        errorMessage={controller.auditState.errorMessage}
        isLoading={controller.auditState.isLoading}
      />
    </div>
  );
}

export function SettingsPage({ controller }: { controller: GatewayController }) {
  const { t } = useTranslation();
  const settings = controller.accountSettings;
  const selectedProfile = settings?.ssh_command_profile_override ?? "inherit";
  const selectedLanguage = settings?.ui_language ?? "en";

  const changeLanguage = (language: UiLanguage) => {
    void i18n.changeLanguage(language);
    controller.updateAccountSettings.mutate({ ui_language: language });
  };

  return (
    <div className="subview">
      <div className="section-title">
        <h1>{t("settings.title")}</h1>
      </div>
      <div className="settings-stack">
        <section className="settings-card">
          <div>
            <h2>{t("settings.language.title")}</h2>
            <p>{t("settings.language.description")}</p>
          </div>
          {controller.accountSettingsState.isLoading ? (
            <p>{t("settings.loading")}</p>
          ) : controller.accountSettingsState.errorMessage ? (
            <p role="alert">{controller.accountSettingsState.errorMessage}</p>
          ) : (
            <label className="settings-field">
              <span>{t("settings.language.label")}</span>
              <select
                aria-label={t("settings.language.label")}
                disabled={controller.updateAccountSettings.isPending}
                onChange={(event) => changeLanguage(event.target.value as UiLanguage)}
                value={selectedLanguage}
              >
                <option value="en">{t("settings.language.english")}</option>
                <option value="ru">{t("settings.language.russian")}</option>
              </select>
            </label>
          )}
        </section>

        <section className="settings-card">
          <div>
            <h2>{t("settings.ssh.title")}</h2>
            <p>{t("settings.ssh.description")}</p>
          </div>
          {controller.accountSettingsState.isLoading ? (
            <p>{t("settings.loading")}</p>
          ) : controller.accountSettingsState.errorMessage ? (
            <p role="alert">{controller.accountSettingsState.errorMessage}</p>
          ) : (
            <label className="settings-field">
              <span>{t("settings.ssh.profile")}</span>
              <select
                disabled={controller.updateAccountSettings.isPending}
                onChange={(event) =>
                  controller.updateAccountSettings.mutate({
                    ssh_command_profile: event.target.value as
                      | "inherit"
                      | "restricted"
                      | "filtered"
                      | "unrestricted",
                  })
                }
                value={selectedProfile}
              >
                <option value="inherit">
                  {t("settings.ssh.inherit", {
                    profile: settings?.ssh_command_profile_default,
                  })}
                </option>
                <option value="unrestricted">{t("settings.ssh.unrestricted")}</option>
                <option value="filtered">{t("settings.ssh.filtered")}</option>
                <option value="restricted">{t("settings.ssh.restricted")}</option>
              </select>
            </label>
          )}
          <p className="settings-note">
            {t("settings.ssh.effective", {
              profile: settings?.ssh_command_profile ?? t("common.unknown"),
            })}{" "}
            {t("settings.ssh.permissions")}
          </p>
        </section>
      </div>
    </div>
  );
}

function ActiveGatewayPage({ controller }: { controller: GatewayController }) {
  if (controller.active === "workspaces")
    return <DockerWorkspacesPage controller={controller} />;
  if (controller.active === "thin")
    return <ThinClientsPage controller={controller} />;
  if (controller.active === "monitoring")
    return <MonitoringPage controller={controller} />;
  if (controller.active === "access")
    return <ChatGPTAccessPage controller={controller} />;
  if (controller.active === "audit")
    return <AuditPage controller={controller} />;
  if (controller.active === "settings")
    return <SettingsPage controller={controller} />;
  return <DevicesPage controller={controller} />;
}

function RemotePageFrame({ children }: { children: ReactNode }) {
  return <div className="remote-page">{children}</div>;
}

function useGatewayController(
  initialPage: GatewayPageId,
  navigateToPage?: (page: GatewayPageId) => void,
) {
  const { t } = useTranslation();
  const [localActive, setLocalActive] = useState<GatewayPageId>(initialPage);
  const active = navigateToPage ? initialPage : localActive;
  const setActive = useCallback(
    (page: GatewayPageId) => {
      if (navigateToPage) {
        navigateToPage(page);
        return;
      }
      setLocalActive(page);
    },
    [navigateToPage],
  );
  const [selectedId, setSelectedId] = useState("");
  const [search, setSearch] = useState("");
  const [target, setTarget] = useState("");
  const [secret, setSecret] = useState("");
  const [authType, setAuthType] = useState<"password" | "private_key">(
    "password",
  );
  const [clientCommand, setClientCommand] = useState(() =>
    [
      "./scripts/gateway-thin-client.sh install",
      "&&",
      "gateway-cli login",
      `--gateway ${shellQuote(currentGatewayOrigin())}`,
      '--directory "$PWD"',
      "--serve",
    ].join(" "),
  );
  const [editingWorkspaceId, setEditingWorkspaceId] = useState("");
  const [editWorkspaceName, setEditWorkspaceName] = useState("");
  const [editWorkspaceDescription, setEditWorkspaceDescription] = useState("");
  const [selectedCommandSessionId, setSelectedCommandSessionId] = useState("");
  const queryClient = useQueryClient();

  const me = useQuery({ queryKey: ["me"], queryFn: api.me });
  const accountSettingsQuery = useQuery({
    queryKey: ["accountSettings"],
    queryFn: api.accountSettings,
  });

  useEffect(() => {
    const language = accountSettingsQuery.data?.ui_language;
    if (language && i18n.resolvedLanguage !== language) {
      void i18n.changeLanguage(language);
    }
  }, [accountSettingsQuery.data?.ui_language]);
  const devicesQuery = useQuery({
    queryKey: ["devices"],
    queryFn: api.devices,
  });
  const workspacesQuery = useQuery({
    queryKey: ["workspaces"],
    queryFn: api.workspaces,
  });
  const thinClientsQuery = useQuery({
    queryKey: ["thinClients"],
    queryFn: api.thinClients,
  });
  const grantsQuery = useQuery({ queryKey: ["grants"], queryFn: api.grants });
  const auditQuery = useQuery({ queryKey: ["audit"], queryFn: api.audit });
  const imagesQuery = useQuery({ queryKey: ["images"], queryFn: api.images });
  const commandSessionsQuery = useQuery({
    queryKey: ["commandSessions"],
    queryFn: api.commandSessions,
    refetchInterval: 3000,
  });
  const fileChangesQuery = useQuery({
    queryKey: ["fileChanges"],
    queryFn: () => api.fileChanges({ limit: 50 }),
    refetchInterval: 5000,
  });

  const devices = devicesQuery.data ?? [];
  const workspaces = workspacesQuery.data ?? [];
  const thinClients = thinClientsQuery.data ?? [];
  const grants = grantsQuery.data ?? [];
  const audit = auditQuery.data ?? [];
  const commandSessions = commandSessionsQuery.data ?? [];
  const fileChanges = fileChangesQuery.data ?? [];
  const selectedCommandSession = commandSessions.find(
    (session) => session.id === selectedCommandSessionId,
  );
  const commandSessionOutputQuery = useQuery({
    enabled: Boolean(selectedCommandSession?.id),
    queryKey: ["commandSessionOutput", selectedCommandSession?.id],
    queryFn: () => api.commandSessionOutput(selectedCommandSession!.id, { tail: 200 }),
    refetchInterval: selectedCommandSession?.status === "running" ? 3000 : false,
  });
  const commandSessionToolCallsQuery = useQuery({
    enabled: Boolean(selectedCommandSession?.id),
    queryKey: ["commandSessionToolCalls", selectedCommandSession?.id],
    queryFn: () => api.commandSessionToolCalls(selectedCommandSession!.id),
    refetchInterval: selectedCommandSession?.status === "running" ? 3000 : false,
  });
  const availableImages = imagesQuery.data?.images ?? [];
  const createWorkspaceTitle = imagesQuery.isPending
    ? t("workspaces.imageAllowlistLoading")
    : imagesQuery.isError
      ? (getErrorMessage(imagesQuery.error) ?? t("workspaces.imagesUnavailable"))
      : availableImages.length === 0
        ? t("workspaces.noImages")
        : undefined;
  const selected =
    selectedId === DEVICE_PANEL_CLOSED
      ? undefined
      : devices.find((device) => device.id === selectedId) ?? devices[0];
  const filteredDevices = useMemo(
    () =>
      devices.filter((device) =>
        `${device.name} ${device.host} ${device.username}`
          .toLowerCase()
          .includes(search.toLowerCase()),
      ),
    [devices, search],
  );

  const createDevice = useMutation({
    mutationFn: () => {
      const trimmedTarget = target.trim();
      const trimmedSecret = secret.trim();
      if (!trimmedTarget) {
        throw new Error(t("devices.form.enterTarget"));
      }
      if (!trimmedSecret) {
        throw new Error(
          authType === "password"
            ? t("devices.form.enterPassword")
            : t("devices.form.enterPrivateKey"),
        );
      }
      return api.createDevice({
        name: trimmedTarget.split("@")[1]?.split(":")[0] ?? trimmedTarget,
        target: trimmedTarget,
        auth_type: authType,
        password: authType === "password" ? trimmedSecret : undefined,
        private_key: authType === "private_key" ? trimmedSecret : undefined,
      });
    },
    onSuccess: (device) => {
      setSelectedId(device.id);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });

  const updateDevice = useMutation({
    mutationFn: ({
      deviceId,
      payload,
    }: {
      deviceId: string;
      payload: {
        auth_type?: string;
        name?: string;
        password?: string;
        private_key?: string;
        target?: string;
      };
    }) => api.updateDevice(deviceId, payload),
    onSuccess: (device) => {
      setSelectedId(device.id);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });

  const testDeviceConnection = useMutation({
    mutationFn: api.testDeviceConnection,
    onSuccess: (device) => {
      setSelectedId(device.id);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });

  const deleteDevice = useMutation({
    mutationFn: api.deleteDevice,
    onSuccess: () => {
      setSelectedId(DEVICE_PANEL_CLOSED);
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });

  const closeDeviceDetails = () => setSelectedId(DEVICE_PANEL_CLOSED);

  const createWorkspace = useMutation({
    mutationFn: () => {
      const image = availableImages[0];
      if (!image) {
        throw new Error(
          t("workspaces.imageListEmpty"),
        );
      }
      return api.createWorkspace({
        name: `ubuntu-${Date.now().toString().slice(-4)}`,
        image,
      });
    },
    onSuccess: () => {
      setActive("workspaces");
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    },
  });
  const canCreateWorkspace =
    !createWorkspace.isPending &&
    !imagesQuery.isPending &&
    !imagesQuery.isError &&
    availableImages.length > 0;

  const beginWorkspaceEdit = (workspace: {
    description?: string | null;
    id: string;
    name: string;
  }) => {
    setEditingWorkspaceId(workspace.id);
    setEditWorkspaceName(workspace.name);
    setEditWorkspaceDescription(workspace.description ?? "");
  };

  const cancelWorkspaceEdit = () => {
    setEditingWorkspaceId("");
    setEditWorkspaceName("");
    setEditWorkspaceDescription("");
  };

  const updateWorkspace = useMutation({
    mutationFn: (workspaceId: string) => {
      const name = editWorkspaceName.trim();
      if (!name) {
        throw new Error(t("workspaces.enterName"));
      }
      return api.updateWorkspace(workspaceId, {
        name,
        description: editWorkspaceDescription.trim() || null,
      });
    },
    onSuccess: () => {
      cancelWorkspaceEdit();
      setActive("workspaces");
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    },
  });

  const cloneWorkspace = useMutation({
    mutationFn: (workspaceId?: string) => {
      const source =
        workspaces.find((workspace) => workspace.id === workspaceId) ??
        workspaces[0];
      if (!source) {
        throw new Error(t("workspaces.noCloneSource"));
      }
      return api.cloneWorkspace({
        source_workspace_id: source.id,
        name: `clone-${Date.now().toString().slice(-4)}`,
      });
    },
    onSuccess: () => {
      setActive("workspaces");
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    },
  });

  const stopWorkspace = useMutation({
    mutationFn: api.stopWorkspace,
    onSuccess: () => {
      setActive("workspaces");
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    },
  });

  const startWorkspace = useMutation({
    mutationFn: api.startWorkspace,
    onSuccess: () => {
      setActive("workspaces");
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    },
  });

  const deleteWorkspace = useMutation({
    mutationFn: api.deleteWorkspace,
    onSuccess: () => {
      setActive("workspaces");
      queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    },
  });

  const installClient = useMutation({
    mutationFn: api.createDeviceCode,
    onSuccess: (code) => {
      setActive("thin");
      const gatewayBaseUrl = gatewayBaseFromVerificationUri(code.verification_uri);
      setClientCommand(
        [
          "./scripts/gateway-thin-client.sh install",
          "&&",
          "gateway-cli login",
          `--gateway ${shellQuote(gatewayBaseUrl)}`,
          '--directory "$PWD"',
          `--device-code ${shellQuote(code.device_code)}`,
          `--user-code ${shellQuote(code.user_code)}`,
          `--verification-uri ${shellQuote(code.verification_uri)}`,
          `--interval ${code.interval ?? 3}`,
          "--serve",
        ].join(" "),
      );
    },
  });
  const deleteThinClient = useMutation({
    mutationFn: api.deleteThinClient,
    onSuccess: () => {
      setActive("thin");
      queryClient.invalidateQueries({ queryKey: ["thinClients"] });
    },
  });
  const terminateCommandSession = useMutation({
    mutationFn: (sessionId: string) => api.terminateCommandSession(sessionId, { force: false }),
    onSuccess: () => {
      setActive("monitoring");
      queryClient.invalidateQueries({ queryKey: ["commandSessions"] });
      queryClient.invalidateQueries({ queryKey: ["commandSessionOutput"] });
      queryClient.invalidateQueries({ queryKey: ["commandSessionToolCalls"] });
    },
  });
  const forceTerminateCommandSession = useMutation({
    mutationFn: (sessionId: string) => api.terminateCommandSession(sessionId, { force: true }),
    onSuccess: () => {
      setActive("monitoring");
      queryClient.invalidateQueries({ queryKey: ["commandSessions"] });
      queryClient.invalidateQueries({ queryKey: ["commandSessionOutput"] });
      queryClient.invalidateQueries({ queryKey: ["commandSessionToolCalls"] });
    },
  });
  const updateAccountSettings = useMutation({
    mutationFn: api.updateAccountSettings,
    onSuccess: (settings) => {
      queryClient.setQueryData(["accountSettings"], settings);
      if (i18n.resolvedLanguage !== settings.ui_language) {
        void i18n.changeLanguage(settings.ui_language);
      }
    },
    onError: () => {
      const current = queryClient.getQueryData<AccountSettings>([
        "accountSettings",
      ]);
      if (current && i18n.resolvedLanguage !== current.ui_language) {
        void i18n.changeLanguage(current.ui_language);
      }
    },
  });
  const operationError =
    [
      createDevice.error,
      updateDevice.error,
      testDeviceConnection.error,
      deleteDevice.error,
      createWorkspace.error,
      updateWorkspace.error,
      cloneWorkspace.error,
      stopWorkspace.error,
      startWorkspace.error,
      deleteWorkspace.error,
      installClient.error,
      deleteThinClient.error,
      terminateCommandSession.error,
      forceTerminateCommandSession.error,
      updateAccountSettings.error,
    ]
      .map(getErrorMessage)
      .find(Boolean) ?? null;

  return {
    active,
    accountSettings: accountSettingsQuery.data,
    accountSettingsState: getQueryState(accountSettingsQuery),
    audit,
    auditState: getQueryState(auditQuery),
    authType,
    availableImages,
    beginWorkspaceEdit,
    cancelWorkspaceEdit,
    clientCommand,
    cloneWorkspace,
    commandSessionOutput: commandSessionOutputQuery.data,
    commandSessionOutputState: getQueryState(commandSessionOutputQuery),
    closeDeviceDetails,
    commandSessions,
    commandSessionsState: getQueryState(commandSessionsQuery),
    commandSessionToolCalls: commandSessionToolCallsQuery.data ?? [],
    canCreateWorkspace,
    createDevice,
    createWorkspace,
    createWorkspaceTitle,
    deleteDevice,
    deleteWorkspace,
    devices,
    devicesState: getQueryState(devicesQuery),
    editWorkspaceDescription,
    editWorkspaceName,
    editingWorkspaceId,
    fileChanges,
    fileChangesState: getQueryState(fileChangesQuery),
    filteredDevices,
    forceTerminateCommandSession,
    grants,
    grantsState: getQueryState(grantsQuery),
    imagesState: getQueryState(imagesQuery),
    installClient,
    deleteThinClient,
    me,
    meState: getQueryState(me),
    operationError,
    search,
    secret,
    selected,
    selectedCommandSession,
    selectedCommandSessionId,
    setActive,
    setAuthType,
    setEditWorkspaceDescription,
    setEditWorkspaceName,
    setSearch,
    setSecret,
    setSelectedId,
    setSelectedCommandSessionId,
    setTarget,
    startWorkspace,
    stopWorkspace,
    target,
    thinClients,
    thinClientsState: getQueryState(thinClientsQuery),
    terminateCommandSession,
    testDeviceConnection,
    updateAccountSettings,
    updateDevice,
    updateWorkspace,
    workspaces,
    workspacesState: getQueryState(workspacesQuery),
  };
}

export type GatewayController = ReturnType<typeof useGatewayController>;

function OperationBanner({ message }: { message?: string | null }) {
  if (!message) return null;
  return (
    <div className="operation-banner" role="alert">
      {message}
    </div>
  );
}

function getQueryState(query: {
  error: unknown;
  isError: boolean;
  isPending: boolean;
}) {
  return {
    errorMessage: query.isError ? getErrorMessage(query.error) : null,
    isLoading: query.isPending,
  };
}

function getErrorMessage(error: unknown) {
  if (!error) return null;
  if (error instanceof Error) return error.message;
  return String(error);
}

function shellQuote(value: string) {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function currentGatewayOrigin() {
  if (typeof window === "undefined") return "http://localhost:8000";
  return window.location.origin;
}

function gatewayBaseFromVerificationUri(verificationUri: string) {
  const url = new URL(verificationUri);
  url.pathname = url.pathname.replace(/\/thin-clients\/activate\/?$/, "");
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}
