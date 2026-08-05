"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Server, Project, AuditRun } from "@/lib/types";
import Shell from "@/components/Shell";
import StatusBadge from "@/components/StatusBadge";
import InstallToolsPanel from "@/components/InstallToolsPanel";
import RunHistoryTable from "@/components/RunHistoryTable";
import ServerFormModal from "@/components/ServerFormModal";
import LiveRunPanel from "@/components/LiveRunPanel";
import ActionOverlay from "@/components/ActionOverlay";
import { Play, RefreshCw, Download, Plug, Pencil, Trash2 } from "lucide-react";

export default function ServerDashboardPage() {
  const { id: projectId, serverId } = useParams<{ id: string; serverId: string }>();
  const router = useRouter();
  const qc = useQueryClient();
  const [selectedRun, setSelectedRun] = useState<AuditRun | null>(null);
  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [showEditModal, setShowEditModal] = useState(false);

  const { data: project } = useQuery<Project>({
    queryKey: ["project", projectId],
    queryFn: async () => (await api.get(`/projects/${projectId}`)).data,
  });

  const { data: server } = useQuery<Server>({
    queryKey: ["server", serverId],
    queryFn: async () => (await api.get(`/servers/${serverId}`)).data,
  });

  const { data: runs } = useQuery<AuditRun[]>({
    queryKey: ["server-runs", serverId],
    queryFn: async () => (await api.get(`/servers/${serverId}/audit-runs`)).data,
    refetchInterval: (query) => {
      const anyActive = query.state.data?.some((r) => r.status === "queued" || r.status === "running");
      return anyActive ? 3000 : 6000;
    },
  });

  const latestCompleted = runs?.find((r) => r.status === "completed" && r.report_path);

  useEffect(() => {
    const target = selectedRun ?? latestCompleted;
    if (!target) {
      setReportHtml(null);
      return;
    }
    api
      .get(`/audit-runs/${target.id}/report`, { responseType: "text" })
      .then((res) => setReportHtml(res.data))
      .catch(() => setReportHtml(null));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRun?.id, latestCompleted?.id]);

  const testConnection = useMutation({
    mutationFn: async () => (await api.post(`/servers/${serverId}/test-connection`)).data,
    onSuccess: (data) => {
      setTestResult(`Connected. Exit code ${data.exit_code}.`);
      qc.invalidateQueries({ queryKey: ["server", serverId] });
    },
    onError: (err: any) => setTestResult(err?.response?.data?.detail || "Connection failed"),
  });

  const runAudit = useMutation({
    mutationFn: async () =>
      (
        await api.post(`/servers/${serverId}/audit-runs`, {
          use_health_env: true,
        })
      ).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["server-runs", serverId] });
      qc.invalidateQueries({ queryKey: ["server", serverId] });
    },
  });

  const deleteServer = useMutation({
    mutationFn: async () => api.delete(`/servers/${serverId}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["project", projectId, "servers"] });
      router.push(`/projects/${projectId}`);
    },
  });

  function handleDelete() {
    if (
      confirm(
        `Delete "${server?.name}"? This removes its stored credentials and run history — this cannot be undone.`
      )
    ) {
      deleteServer.mutate();
    }
  }

  async function downloadLatest() {
    const target = selectedRun ?? latestCompleted;
    if (!target) return;
    const res = await api.get(`/audit-runs/${target.id}/report`, { responseType: "blob" });
    const url = URL.createObjectURL(res.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security_audit_report_${server?.name}_${target.id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const lastRun = runs?.[0];
  const isBusy = lastRun?.status === "queued" || lastRun?.status === "running";

  return (
    <Shell
      crumbs={[
        { label: project?.name || "…", href: `/projects/${projectId}` },
        { label: server?.name || "…" },
      ]}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold">{server?.name}</h1>
            <StatusBadge status={lastRun?.status || "idle"} />
          </div>
          <p className="text-sm text-text2 font-mono mt-0.5">
            {server?.username}@{server?.host}:{server?.port}
          </p>
          <p className="text-xs text-text2 mt-1">
            {lastRun?.finished_at
              ? `Last run: ${new Date(lastRun.finished_at).toLocaleString()}`
              : lastRun?.started_at
              ? `In progress since ${new Date(lastRun.started_at).toLocaleString()}`
              : "Never run"}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowEditModal(true)}
            className="flex items-center gap-1.5 border border-border text-sm rounded px-3 py-2 hover:border-accent/50 transition"
          >
            <Pencil size={14} /> Edit
          </button>
          <button
            onClick={handleDelete}
            disabled={deleteServer.isPending}
            className="flex items-center gap-1.5 border border-border text-crit text-sm rounded px-3 py-2 hover:border-crit/60 hover:bg-crit/10 transition disabled:opacity-50"
          >
            <Trash2 size={14} /> Delete
          </button>
          <button
            onClick={() => testConnection.mutate()}
            disabled={testConnection.isPending}
            className="flex items-center gap-1.5 border border-border text-sm rounded px-3 py-2 hover:border-accent/50 transition disabled:opacity-50"
          >
            <Plug size={14} /> Test connection
          </button>
          <button
            onClick={downloadLatest}
            disabled={!latestCompleted && !selectedRun}
            className="flex items-center gap-1.5 border border-border text-sm rounded px-3 py-2 hover:border-accent/50 transition disabled:opacity-50"
          >
            <Download size={14} /> Download report
          </button>
          <button
            onClick={() => runAudit.mutate()}
            disabled={isBusy || runAudit.isPending}
            className="flex items-center gap-1.5 bg-accent text-bg font-medium text-sm rounded px-3 py-2 hover:opacity-90 disabled:opacity-50 transition active:scale-[0.98]"
          >
            {isBusy ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
            {lastRun ? "Rerun audit" : "Run audit"}
          </button>
        </div>
      </div>

      {testResult && (
        <div className="mb-4 text-xs font-mono bg-surface2 border border-border rounded px-3 py-2 text-text2">
          {testResult}
        </div>
      )}

      {lastRun && (lastRun.status === "queued" || lastRun.status === "running") && (
        <LiveRunPanel run={lastRun} />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
        <div className="lg:col-span-2">
          <InstallToolsPanel serverId={serverId} isBusy={isBusy} />
        </div>
        <div className="bg-surface border border-border rounded-lg p-5">
          <h2 className="font-medium mb-3 text-sm">Tool status</h2>
          <div className="space-y-2">
            {server && Object.keys(server.installed_tools).length === 0 && (
              <p className="text-xs text-text2">Run "Test connection" to check what's installed.</p>
            )}
            {server &&
              Object.entries(server.installed_tools).map(([tool, installed]) => (
                <div key={tool} className="flex items-center justify-between text-xs font-mono">
                  <span>{tool}</span>
                  <span className={installed ? "text-ok" : "text-text2"}>
                    {installed ? "installed" : "missing"}
                  </span>
                </div>
              ))}
          </div>
        </div>
      </div>

      <h2 className="font-medium mb-3 text-sm">Run history</h2>
      <div className="mb-6">
        <RunHistoryTable runs={runs || []} onSelect={setSelectedRun} selectedId={selectedRun?.id} />
      </div>

      <h2 className="font-medium mb-3 text-sm">
        {selectedRun ? "Selected run" : "Latest run"}
      </h2>
      <div className="bg-surface border border-border rounded-lg overflow-hidden" style={{ height: "80vh" }}>
        {reportHtml ? (
          <iframe title="Audit report" srcDoc={reportHtml} className="w-full h-full" sandbox="allow-scripts" />
        ) : (selectedRun ?? lastRun)?.log_tail ? (
          <div className="h-full overflow-auto p-4">
            <p className="text-xs text-text2 mb-2">
              No report was generated for this run — showing its log instead.
            </p>
            <pre className="text-xs font-mono text-text2 whitespace-pre-wrap break-words">
              {(selectedRun ?? lastRun)?.log_tail}
            </pre>
          </div>
        ) : (
          <div className="h-full flex items-center justify-center text-sm text-text2">
            No report available yet — run an audit to generate one.
          </div>
        )}
      </div>
      {showEditModal && server && (
        <ServerFormModal projectId={projectId} server={server} onClose={() => setShowEditModal(false)} />
      )}

      <ActionOverlay
        status={
          testConnection.isPending
            ? "working"
            : testConnection.isSuccess
            ? "success"
            : testConnection.isError
            ? "error"
            : "idle"
        }
        label="Testing connection…"
        successMessage="Connected"
      />
      <ActionOverlay
        status={
          runAudit.isPending
            ? "working"
            : runAudit.isSuccess
            ? "success"
            : runAudit.isError
            ? "error"
            : "idle"
        }
        label="Starting audit…"
        successMessage="Run queued — tracking progress below"
      />
    </Shell>
  );
}
