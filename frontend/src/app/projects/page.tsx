"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Project } from "@/lib/types";
import Shell from "@/components/Shell";
import ActionOverlay from "@/components/ActionOverlay";
import { Plus, Server as ServerIcon, X, Search, Trash2 } from "lucide-react";

export default function ProjectsPage() {
  const qc = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [search, setSearch] = useState("");

  const { data: projects, isLoading } = useQuery<Project[]>({
    queryKey: ["projects"],
    queryFn: async () => (await api.get("/projects")).data,
  });

  const createProject = useMutation({
    mutationFn: async () => (await api.post("/projects", { name, description })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      setShowModal(false);
      setName("");
      setDescription("");
    },
  });

  const deleteProject = useMutation({
    mutationFn: async (id: string) => api.delete(`/projects/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });

  function handleDelete(e: React.MouseEvent, p: Project) {
    e.preventDefault();
    e.stopPropagation();
    if (
      confirm(
        `Delete "${p.name}"? This removes all ${p.server_count} server(s) in it — including their stored credentials and run history. This cannot be undone.`
      )
    ) {
      deleteProject.mutate(p.id);
    }
  }

  const filtered = useMemo(() => {
    if (!projects) return projects;
    const q = search.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter(
      (p) => p.name.toLowerCase().includes(q) || p.description.toLowerCase().includes(q)
    );
  }, [projects, search]);

  return (
    <Shell>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold">Projects</h1>
          <p className="text-sm text-text2 mt-0.5">
            Group servers by environment or client, then run security audits over SSH.
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-1.5 bg-accent text-bg text-sm font-medium rounded px-3 py-2 hover:opacity-90 transition active:scale-[0.98]"
        >
          <Plus size={16} /> New project
        </button>
      </div>

      {projects && projects.length > 0 && (
        <div className="relative mb-5 max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text2" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search projects…"
            className="w-full bg-surface border border-border rounded-lg pl-9 pr-3 py-2 text-sm outline-none focus:border-accent transition-colors"
          />
        </div>
      )}

      {isLoading && <p className="text-sm text-text2">Loading…</p>}

      {projects && projects.length === 0 && (
        <div className="border border-dashed border-border rounded-lg p-12 text-center">
          <p className="text-text2 text-sm">
            No projects yet. Create one to start adding servers and running audits.
          </p>
        </div>
      )}

      {filtered && filtered.length === 0 && projects && projects.length > 0 && (
        <div className="border border-dashed border-border rounded-lg p-12 text-center">
          <p className="text-text2 text-sm">No projects match "{search}".</p>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered?.map((p, i) => (
          <Link
            key={p.id}
            href={`/projects/${p.id}`}
            style={{ animationDelay: `${Math.min(i, 8) * 40}ms` }}
            className="fade-up relative bg-surface border border-border rounded-lg p-5 transition-all duration-200 hover:border-accent/50 hover:-translate-y-0.5 hover:shadow-glow group"
          >
            <button
              onClick={(e) => handleDelete(e, p)}
              disabled={deleteProject.isPending}
              className="absolute top-3 right-3 p-1.5 rounded text-text2 opacity-0 group-hover:opacity-100 hover:text-crit hover:bg-crit/10 transition disabled:opacity-50"
              title="Delete project"
            >
              <Trash2 size={14} />
            </button>
            <div className="flex items-start justify-between mb-3 pr-6">
              <h2 className="font-medium group-hover:text-accent transition-colors">{p.name}</h2>
              <span className="flex items-center gap-1 text-xs text-text2 font-mono shrink-0">
                <ServerIcon size={12} /> {p.server_count}
              </span>
            </div>
            <p className="text-xs text-text2 line-clamp-2">{p.description || "No description"}</p>
          </Link>
        ))}
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 px-4">
          <div className="fade-up bg-surface border border-border rounded-lg p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-medium">New project</h2>
              <button onClick={() => setShowModal(false)} className="text-text2 hover:text-text">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs text-text2">Name</label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-surface2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-accent"
                  placeholder="Ecosmob Production VoIP"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-text2">Description (optional)</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full bg-surface2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-accent"
                  rows={3}
                />
              </div>
              <button
                onClick={() => createProject.mutate()}
                disabled={!name || createProject.isPending}
                className="w-full bg-accent text-bg font-medium text-sm rounded py-2 hover:opacity-90 disabled:opacity-50 transition active:scale-[0.98]"
              >
                {createProject.isPending ? "Creating…" : "Create project"}
              </button>
            </div>
          </div>
        </div>
      )}

      <ActionOverlay
        status={
          createProject.isPending
            ? "working"
            : createProject.isSuccess
            ? "success"
            : createProject.isError
            ? "error"
            : "idle"
        }
        label="Creating project…"
      />
    </Shell>
  );
}
