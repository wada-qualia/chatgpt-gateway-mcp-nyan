import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  CloudCog,
  Eye,
  LoaderCircle,
  Plus,
  Power,
  RefreshCw,
  ShieldOff,
  TestTube2,
} from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@gateway/ui";
import {
  api,
  type McpServer,
  type McpServerHealth,
  type McpTool,
} from "@gateway/generated/client";


type AuthMode = "none" | "bearer" | "header" | "oauth";

type FormState = {
  displayName: string;
  endpointUrl: string;
  authMode: AuthMode;
  bearerToken: string;
  headerName: string;
  headerValue: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  audience: string;
  scopes: string;
};

const initialForm: FormState = {
  displayName: "",
  endpointUrl: "",
  authMode: "none",
  bearerToken: "",
  headerName: "X-API-Key",
  headerValue: "",
  authorizationEndpoint: "",
  tokenEndpoint: "",
  clientId: "",
  clientSecret: "",
  audience: "",
  scopes: "",
};

function operationKey(prefix: string) {
  const random = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${random}`;
}

function scopes(value: string) {
  return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
}

function readableError(error: unknown) {
  if (!(error instanceof Error)) return "Unknown operation error";
  try {
    const payload = JSON.parse(error.message) as { detail?: string | { message?: string } };
    if (typeof payload.detail === "string") return payload.detail;
    if (payload.detail && typeof payload.detail.message === "string") return payload.detail.message;
  } catch {
    // The API helper may return a plain response body.
  }
  return error.message;
}

function formatDate(value: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function McpToolRow({ tool }: { tool: McpTool }) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const revisions = useQuery({
    queryKey: ["mcpToolRevisions", tool.id],
    queryFn: () => api.mcpToolRevisions(tool.id),
    enabled: expanded,
  });
  const exposure = useQuery({
    queryKey: ["mcpToolExposure", tool.id],
    queryFn: () => api.mcpToolExposure(tool.id),
    enabled: expanded,
  });
  const latest = revisions.data?.[0];

  return (
    <div className="mcp-tool-row">
      <button
        className="mcp-tool-toggle"
        type="button"
        aria-expanded={expanded}
        onClick={() => setExpanded((value) => !value)}
      >
        <span>
          <strong>{tool.upstream_name}</strong>
          <small>{tool.lifecycle_state} · {tool.current_revision_id ? `revision ${tool.current_revision_id.slice(0, 8)}` : t("mcpConnections.catalog.noRevision")}</small>
        </span>
        {expanded ? <ChevronUp size={17} /> : <ChevronDown size={17} />}
      </button>
      {expanded ? (
        <div className="mcp-tool-details">
          {revisions.isLoading || exposure.isLoading ? <LoaderCircle className="spin" size={17} /> : null}
          {revisions.isError ? <div className="operation-banner">{readableError(revisions.error)}</div> : null}
          {latest ? (
            <>
              <dl className="mcp-tool-meta">
                <div><dt>{t("mcpConnections.catalog.risk")}</dt><dd>{latest.action_class}</dd></div>
                <div><dt>{t("mcpConnections.catalog.readOnly")}</dt><dd>{latest.read_only_status}</dd></div>
                <div><dt>{t("mcpConnections.catalog.exposure")}</dt><dd>{exposure.data ? `${exposure.data.mode} / ${exposure.data.enabled ? "enabled" : "disabled"}` : "hidden / not published"}</dd></div>
                <div><dt>{t("mcpConnections.catalog.schemaHash")}</dt><dd><code>{latest.schema_hash}</code></dd></div>
              </dl>
              <p className="mcp-tool-description">{latest.sanitized_description || t("mcpConnections.catalog.noDescription")}</p>
              <details className="mcp-schema-details">
                <summary>{t("mcpConnections.catalog.inputSchema")}</summary>
                <pre>{JSON.stringify(latest.input_schema, null, 2)}</pre>
              </details>
              <p className="mcp-exposure-note">{t("mcpConnections.catalog.exposureNote")}</p>
            </>
          ) : revisions.isSuccess ? <span>{t("mcpConnections.catalog.noRevision")}</span> : null}
        </div>
      ) : null}
    </div>
  );
}

function McpCatalogPanel({ server }: { server: McpServer }) {
  const { t } = useTranslation();
  const tools = useQuery({
    queryKey: ["mcpServerTools", server.id, server.catalog_generation],
    queryFn: () => api.mcpServerTools(server.id),
  });

  return (
    <section className="mcp-catalog-panel">
      <div className="mcp-catalog-heading">
        <div><h3>{t("mcpConnections.catalog.title")}</h3><p>{t("mcpConnections.catalog.description")}</p></div>
        <span>{tools.data?.length ?? 0}</span>
      </div>
      {tools.isLoading ? <div className="mcp-catalog-loading"><LoaderCircle className="spin" size={18} /> {t("common.loading")}</div> : null}
      {tools.isError ? <div className="operation-banner">{readableError(tools.error)}</div> : null}
      {tools.isSuccess && tools.data.length === 0 ? <div className="mcp-catalog-loading">{t("mcpConnections.catalog.empty")}</div> : null}
      <div className="mcp-tool-list">{tools.data?.map((tool) => <McpToolRow key={tool.id} tool={tool} />)}</div>
    </section>
  );
}

export function McpConnectionsPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<FormState>(initialForm);
  const [showForm, setShowForm] = useState(false);
  const [expandedServerId, setExpandedServerId] = useState<string | null>(null);
  const [healthByServer, setHealthByServer] = useState<Record<string, McpServerHealth>>({});
  const [operationError, setOperationError] = useState("");
  const oauthHandled = useRef(false);

  const serverQuery = useQuery({ queryKey: ["mcpServers"], queryFn: api.mcpServers });
  const servers = serverQuery.data ?? [];

  const completeOAuth = useMutation({
    mutationFn: ({ state, code }: { state: string; code: string }) => api.completeMcpOAuth(state, code),
    onSuccess: async () => {
      const url = new URL(window.location.href);
      url.searchParams.delete("state");
      url.searchParams.delete("code");
      url.searchParams.delete("error");
      window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
      setOperationError("");
      await queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (error) => setOperationError(readableError(error)),
  });

  useEffect(() => {
    if (oauthHandled.current) return;
    const params = new URLSearchParams(window.location.search);
    const state = params.get("state");
    const code = params.get("code");
    const oauthError = params.get("error");
    if (oauthError) {
      oauthHandled.current = true;
      setOperationError(`OAuth authorization failed: ${oauthError}`);
      return;
    }
    if (state && code) {
      oauthHandled.current = true;
      completeOAuth.mutate({ state, code });
    }
  }, [completeOAuth]);

  const createConnection = useMutation({
    mutationFn: async (data: FormState) => {
      let bindingId: string | null = null;
      if (data.authMode === "bearer") {
        const binding = await api.createMcpCredentialMaterial({
          binding_type: "service_account",
          mode: "bearer",
          access_token: data.bearerToken,
          scopes: scopes(data.scopes),
        }, operationKey("mcp-credential"));
        bindingId = binding.id;
      }
      if (data.authMode === "header") {
        const binding = await api.createMcpCredentialMaterial({
          binding_type: "service_account",
          mode: "header",
          header_name: data.headerName,
          header_value: data.headerValue,
          scopes: scopes(data.scopes),
        }, operationKey("mcp-credential"));
        bindingId = binding.id;
      }
      const server = await api.createMcpServer({
        display_name: data.displayName,
        origin: "gateway",
        transport: "streamable_http",
        endpoint_url: data.endpointUrl,
        thin_client_id: null,
        runtime_id: null,
        credential_binding_id: bindingId,
      }, operationKey("mcp-server"));
      if (data.authMode === "oauth") {
        const authorization = await api.startMcpOAuth(server, {
          authorization_endpoint: data.authorizationEndpoint,
          token_endpoint: data.tokenEndpoint,
          client_id: data.clientId,
          client_secret: data.clientSecret || undefined,
          redirect_uri: `${window.location.origin}/mcp-connections`,
          scopes: scopes(data.scopes),
          audience: data.audience || new URL(data.endpointUrl).origin,
        }, operationKey("mcp-oauth-start"));
        window.location.assign(authorization.authorization_url);
      }
      return server;
    },
    onSuccess: async () => {
      setOperationError("");
      setForm(initialForm);
      setShowForm(false);
      await queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (error) => setOperationError(readableError(error)),
  });

  const testConnection = useMutation({
    mutationFn: (server: McpServer) => api.testMcpServer(server.id),
    onSuccess: (health) => {
      setHealthByServer((current) => ({ ...current, [health.server_id]: health }));
      setOperationError("");
      void queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (error) => setOperationError(readableError(error)),
  });

  const refreshCatalog = useMutation({
    mutationFn: (server: McpServer) => api.refreshMcpServer(server, operationKey("mcp-refresh")),
    onSuccess: async (server) => {
      setOperationError("");
      await queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
      await queryClient.invalidateQueries({ queryKey: ["mcpServerTools", server.id] });
    },
    onError: (error) => setOperationError(readableError(error)),
  });

  const disableConnection = useMutation({
    mutationFn: (server: McpServer) => api.disableMcpServer(server, operationKey("mcp-remove")),
    onSuccess: async () => {
      setOperationError("");
      await queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (error) => setOperationError(readableError(error)),
  });

  const enableConnection = useMutation({
    mutationFn: (server: McpServer) => api.enableMcpServer(server, operationKey("mcp-enable")),
    onSuccess: async () => {
      setOperationError("");
      await queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (error) => setOperationError(readableError(error)),
  });

  const pendingServerId = useMemo(() => {
    if (testConnection.isPending) return testConnection.variables?.id;
    if (refreshCatalog.isPending) return refreshCatalog.variables?.id;
    if (disableConnection.isPending) return disableConnection.variables?.id;
    if (enableConnection.isPending) return enableConnection.variables?.id;
    return undefined;
  }, [disableConnection.isPending, disableConnection.variables, enableConnection.isPending, enableConnection.variables, refreshCatalog.isPending, refreshCatalog.variables, testConnection.isPending, testConnection.variables]);

  return (
    <div className="mcp-connections-page">
      <header className="section-title mcp-connections-heading">
        <div>
          <h1>{t("mcpConnections.title")}</h1>
          <p>{t("mcpConnections.description")}</p>
        </div>
        <Button onClick={() => setShowForm((value) => !value)}>
          <Plus size={16} /> {t("mcpConnections.add")}
        </Button>
      </header>

      {operationError ? <div className="operation-banner" role="alert"><AlertCircle size={18} /> {operationError}</div> : null}
      {completeOAuth.isPending ? <div className="mcp-oauth-banner"><LoaderCircle className="spin" size={18} /> {t("mcpConnections.oauthCompleting")}</div> : null}

      {showForm ? (
        <form className="mcp-connection-form" onSubmit={(event) => { event.preventDefault(); createConnection.mutate(form); }}>
          <div className="mcp-form-intro"><CloudCog size={22} /><div><h2>{t("mcpConnections.form.title")}</h2><p>{t("mcpConnections.form.note")}</p></div></div>
          <div className="mcp-form-grid">
            <label><span>{t("mcpConnections.form.name")}</span><input required value={form.displayName} onChange={(event) => setForm({ ...form, displayName: event.target.value })} /></label>
            <label><span>{t("mcpConnections.form.endpoint")}</span><input required type="url" placeholder="https://mcp.example.com/mcp" value={form.endpointUrl} onChange={(event) => setForm({ ...form, endpointUrl: event.target.value })} /></label>
            <label><span>{t("mcpConnections.form.authMode")}</span><select value={form.authMode} onChange={(event) => setForm({ ...form, authMode: event.target.value as AuthMode })}><option value="none">{t("mcpConnections.auth.none")}</option><option value="bearer">{t("mcpConnections.auth.bearer")}</option><option value="header">{t("mcpConnections.auth.header")}</option><option value="oauth">OAuth 2.1 + PKCE</option></select></label>
            <label><span>{t("mcpConnections.form.scopes")}</span><input placeholder="mcp:read mcp:call" value={form.scopes} onChange={(event) => setForm({ ...form, scopes: event.target.value })} /></label>
          </div>
          {form.authMode === "bearer" ? <label className="mcp-secret-field"><span>{t("mcpConnections.form.bearerToken")}</span><input required type="password" autoComplete="new-password" value={form.bearerToken} onChange={(event) => setForm({ ...form, bearerToken: event.target.value })} /></label> : null}
          {form.authMode === "header" ? <div className="mcp-form-grid"><label><span>{t("mcpConnections.form.headerName")}</span><input required value={form.headerName} onChange={(event) => setForm({ ...form, headerName: event.target.value })} /></label><label><span>{t("mcpConnections.form.headerValue")}</span><input required type="password" autoComplete="new-password" value={form.headerValue} onChange={(event) => setForm({ ...form, headerValue: event.target.value })} /></label></div> : null}
          {form.authMode === "oauth" ? <div className="mcp-oauth-fields"><label><span>{t("mcpConnections.form.authorizationEndpoint")}</span><input required type="url" value={form.authorizationEndpoint} onChange={(event) => setForm({ ...form, authorizationEndpoint: event.target.value })} /></label><label><span>{t("mcpConnections.form.tokenEndpoint")}</span><input required type="url" value={form.tokenEndpoint} onChange={(event) => setForm({ ...form, tokenEndpoint: event.target.value })} /></label><label><span>{t("mcpConnections.form.clientId")}</span><input required value={form.clientId} onChange={(event) => setForm({ ...form, clientId: event.target.value })} /></label><label><span>{t("mcpConnections.form.clientSecret")}</span><input type="password" autoComplete="new-password" value={form.clientSecret} onChange={(event) => setForm({ ...form, clientSecret: event.target.value })} /></label><label><span>{t("mcpConnections.form.audience")}</span><input type="url" placeholder="Defaults to the MCP endpoint origin" value={form.audience} onChange={(event) => setForm({ ...form, audience: event.target.value })} /></label></div> : null}
          <div className="mcp-form-actions"><Button type="button" onClick={() => setShowForm(false)}>{t("common.actions.cancel")}</Button><Button type="submit" disabled={createConnection.isPending}>{createConnection.isPending ? <LoaderCircle className="spin" size={16} /> : <Plus size={16} />} {t("mcpConnections.form.submit")}</Button></div>
        </form>
      ) : null}

      {serverQuery.isLoading ? <div className="mcp-empty"><LoaderCircle className="spin" /> {t("common.loading")}</div> : null}
      {serverQuery.isError ? <div className="operation-banner" role="alert">{readableError(serverQuery.error)}</div> : null}
      {!serverQuery.isLoading && servers.length === 0 ? <div className="mcp-empty"><CloudCog size={30} /><strong>{t("mcpConnections.empty")}</strong><span>{t("mcpConnections.emptyNote")}</span></div> : null}

      <div className="mcp-server-grid">
        {servers.map((server) => {
          const health = healthByServer[server.id];
          const isPending = pendingServerId === server.id;
          const catalogExpanded = expandedServerId === server.id;
          return <article className="mcp-server-card" key={server.id}>
            <div className="mcp-server-card-head"><div><h2>{server.display_name}</h2><code>{server.endpoint_url}</code></div><span className={`mcp-status mcp-status-${server.status}`}>{server.status === "online" ? <CheckCircle2 size={14} /> : <AlertCircle size={14} />}{server.status}</span></div>
            <dl className="mcp-server-meta"><div><dt>{t("mcpConnections.fields.protocol")}</dt><dd>{server.negotiated_protocol_version ?? "—"}</dd></div><div><dt>{t("mcpConnections.fields.catalog")}</dt><dd>{server.catalog_generation}</dd></div><div><dt>{t("mcpConnections.fields.trust")}</dt><dd>{server.trust_level}</dd></div><div><dt>{t("mcpConnections.fields.lastConnected")}</dt><dd>{formatDate(server.last_connected_at)}</dd></div>{health ? <><div><dt>{t("mcpConnections.fields.tools")}</dt><dd>{health.tool_count ?? "—"}</dd></div><div><dt>{t("mcpConnections.fields.latency")}</dt><dd>{health.latency_ms == null ? "—" : `${health.latency_ms} ms`}</dd></div></> : null}</dl>
            <div className="mcp-card-actions">
              <Button disabled={isPending || server.status === "disabled"} onClick={() => testConnection.mutate(server)}><TestTube2 size={15} /> {t("common.actions.test")}</Button>
              <Button disabled={isPending || server.status === "disabled"} onClick={() => refreshCatalog.mutate(server)}><RefreshCw size={15} /> {t("mcpConnections.refreshCatalog")}</Button>
              <Button disabled={server.catalog_generation === 0} onClick={() => setExpandedServerId(catalogExpanded ? null : server.id)}><Eye size={15} /> {catalogExpanded ? t("mcpConnections.hideCatalog") : t("mcpConnections.inspectCatalog")}</Button>
              {server.status === "disabled" ? <Button disabled={isPending} onClick={() => enableConnection.mutate(server)}><Power size={15} /> {t("mcpConnections.enable")}</Button> : <Button disabled={isPending} onClick={() => disableConnection.mutate(server)}><ShieldOff size={15} /> {t("mcpConnections.remove")}</Button>}
            </div>
            {catalogExpanded ? <McpCatalogPanel server={server} /> : null}
            {server.status === "disabled" ? <p className="mcp-retention-note">{t("mcpConnections.retentionNote")}</p> : null}
          </article>;
        })}
      </div>
    </div>
  );
}
