"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Project, Server } from "@/lib/types";
import Shell from "@/components/Shell";
import ServerFormModal from "@/components/ServerFormModal";
import StatusBadge from "@/components/StatusBadge";
import { Plus, Key, Lock, Pencil, Trash2, Search } from "lucide-react";

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingServer, setEditingServer] = useState<Server | null>(null);
  const [search, setSearch] = useState("");

  const { data: project } = useQuery<Project>({
    queryKey: ["project", id],
    queryFn: async () => (await api.get(`/projects/${id}`)).data,
  });

  const { data: servers } = useQuery<Server[]>({
    queryKey: ["project", id, "servers"],
    queryFn: async () => (await api.get(`/projects/${id}/servers`)).data,
    refetchInterval: 8000,
  });

  const filteredServers = useMemo(() => {
    if (!servers) return servers;
    const q = search.trim().toLowerCase();
    if (!q) return servers;
    return servers.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.host.toLowerCase().includes(q) ||
        s.username.toLowerCase().includes(q)
    );
  }, [servers, search]);

  return (
    <Shell crumbs={[{ label: project?.name || "…" }]}>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold">{project?.name}</h1>
          <p className="text-sm text-text2 mt-0.5">{project?.description || "No description"}</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-1.5 bg-accent text-bg text-sm font-medium rounded px-3 py-2 hover:opacity-90 transition active:scale-[0.98]"
        >
          <Plus size={16} /> Add server
        </button>
      </div>

      {servers && servers.length > 0 && (
        <div className="relative mb-5 max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text2" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search servers by name, host, or user…"
            className="w-full bg-surface border border-border rounded-lg pl-9 pr-3 py-2 text-sm outline-none focus:border-accent transition-colors"
          />
        </div>
      )}

      {servers && servers.length === 0 && (
        <div className="border border-dashed border-border rounded-lg p-12 text-center">
          <p className="text-text2 text-sm">
            No servers in this project yet. Add one with its SSH credentials to get started.
          </p>
        </div>
      )}

      {filteredServers && filteredServers.length === 0 && servers && servers.length > 0 && (
        <div className="border border-dashed border-border rounded-lg p-12 text-center">
          <p className="text-text2 text-sm">No servers match "{search}".</p>
        </div>
      )}

      <div className="space-y-3">
        {filteredServers?.map((s, i) => (
          <ServerRow key={s.id} projectId={id} server={s} onEdit={() => setEditingServer(s)} index={i} />
        ))}
      </div>

      {showAddModal && <ServerFormModal projectId={id} onClose={() => setShowAddModal(false)} />}
      {editingServer && (
        <ServerFormModal projectId={id} server={editingServer} onClose={() => setEditingServer(null)} />
      )}
    </Shell>
  );
}

function ServerRow({
  projectId,
  server,
  onEdit,
  index,
}: {
  projectId: string;
  server: Server;
  onEdit: () => void;
  index: number;
}) {
  const qc = useQueryClient();
  const router = useRouter();

  const { data: lastRun } = useQuery({
    queryKey: ["run", server.last_run_id],
    queryFn: async () => (await api.get(`/audit-runs/${server.last_run_id}`)).data,
    enabled: !!server.last_run_id,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "queued" || status === "running" ? 3000 : false;
    },
  });

  const deleteServer = useMutation({
    mutationFn: async () => api.delete(`/servers/${server.id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["project", projectId, "servers"] }),
  });

  function handleDelete(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (confirm(`Delete "${server.name}"? This removes its stored credentials and run history — this cannot be undone.`)) {
      deleteServer.mutate();
    }
  }

  const active = lastRun?.status === "queued" || lastRun?.status === "running";

  return (
    <Link
      href={`/projects/${projectId}/servers/${server.id}`}
      style={{ animationDelay: `${Math.min(index, 8) * 40}ms` }}
      className="fade-up flex items-center gap-4 bg-surface border border-border rounded-lg px-5 py-4 transition-all duration-200 hover:border-accent/50 hover:-translate-y-0.5 hover:shadow-glow group"
    >
      {/* wire + node: literal visualization of the SSH connection this row represents */}
      <svg width="56" height="24" className="shrink-0">
        <line x1="0" y1="12" x2="40" y2="12" stroke="#2A3441" strokeWidth="2" />
        {active && (
          <line x1="0" y1="12" x2="40" y2="12" stroke="#4FD1C5" strokeWidth="2" className="wire-active" />
        )}
        <circle cx="46" cy="12" r="7" fill={active ? "#4FD1C5" : "#161B24"} stroke={active ? "#4FD1C5" : "#2A3441"} strokeWidth="1.5" />
      </svg>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <h3 className="font-medium group-hover:text-accent transition truncate">{server.name}</h3>
          {server.auth_type === "private_key" ? (
            <Key size={12} className="text-text2" />
          ) : (
            <Lock size={12} className="text-text2" />
          )}
        </div>
        <p className="text-xs text-text2 font-mono mt-0.5">
          {server.username}@{server.host}:{server.port}
        </p>
      </div>

      <div className="text-right shrink-0">
        <StatusBadge status={lastRun?.status || "idle"} />
        <p className="text-xs text-text2 mt-1">
          {lastRun?.finished_at
            ? `Last run ${new Date(lastRun.finished_at).toLocaleString()}`
            : lastRun?.started_at
            ? `Started ${new Date(lastRun.started_at).toLocaleString()}`
            : "Never run"}
        </p>
      </div>

      {lastRun?.summary?.lynis_grade && (
        <div className="shrink-0 h-9 w-9 rounded-full border border-border flex items-center justify-center font-mono text-sm font-semibold text-accent">
          {lastRun.summary.lynis_grade}
        </div>
      )}

      <div className="shrink-0 flex items-center gap-1 pl-2 border-l border-border">
        <button
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onEdit();
          }}
          className="p-1.5 text-text2 hover:text-accent transition"
          title="Edit server"
        >
          <Pencil size={14} />
        </button>
        <button
          onClick={handleDelete}
          disabled={deleteServer.isPending}
          className="p-1.5 text-text2 hover:text-crit transition disabled:opacity-50"
          title="Delete server"
        >
          <Trash2 size={14} />
        </button>
      </div>
    </Link>
  );
}
