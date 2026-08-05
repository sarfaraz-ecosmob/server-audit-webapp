"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { ToolName } from "@/lib/types";
import ActionOverlay from "@/components/ActionOverlay";

const TOOLS: { id: ToolName; label: string; desc: string }[] = [
  { id: "lynis", label: "Lynis", desc: "Infrastructure hardening scanner" },
  { id: "nmap", label: "Nmap", desc: "Local port scanner (127.0.0.1 only)" },
  { id: "rkhunter", label: "rkhunter", desc: "Rootkit scanner" },
  { id: "zap-docker", label: "OWASP ZAP (Docker)", desc: "Web app passive scan image" },
  { id: "trivy", label: "Trivy", desc: "Kernel & package vulnerability scanner" },
  { id: "jq", label: "jq", desc: "JSON processor (required by Trivy filtering)" },
];

export default function InstallToolsPanel({ serverId, isBusy }: { serverId: string; isBusy?: boolean }) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<Set<ToolName>>(new Set());

  const install = useMutation({
    mutationFn: async () =>
      (await api.post(`/servers/${serverId}/install-tools`, { tools: Array.from(selected) })).data,
    onSuccess: (run) => {
      qc.invalidateQueries({ queryKey: ["server", serverId] });
      qc.invalidateQueries({ queryKey: ["server-runs", serverId] });
    },
  });

  function toggle(t: ToolName) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(t) ? next.delete(t) : next.add(t);
      return next;
    });
  }

  const commandPreview =
    selected.size > 0
      ? `sudo ./install_tools.sh --only ${Array.from(selected).sort().join(",")} --yes`
      : null;

  return (
    <div className={`bg-surface border border-border rounded-lg p-5 transition-opacity ${isBusy ? "opacity-60" : ""}`}>
      <h2 className="font-medium mb-1">Install tools</h2>
      <p className="text-xs text-text2 mb-4">
        Only the tools below can ever be installed on a server through this app — exactly what{" "}
        <code className="mono">install_tools.sh</code> supports, nothing else.
      </p>

      <div className="grid grid-cols-2 gap-2 mb-4">
        {TOOLS.map((t) => (
          <label
            key={t.id}
            className={`flex items-start gap-2 border rounded px-3 py-2 transition ${
              isBusy ? "cursor-not-allowed border-border" : "cursor-pointer"
            } ${selected.has(t.id) ? "border-accent bg-accent/10" : "border-border"}`}
          >
            <input
              type="checkbox"
              checked={selected.has(t.id)}
              onChange={() => toggle(t.id)}
              disabled={isBusy}
              className="mt-0.5 accent-accent"
            />
            <span>
              <span className="text-sm block">{t.label}</span>
              <span className="text-xs text-text2">{t.desc}</span>
            </span>
          </label>
        ))}
      </div>

      {commandPreview && (
        <div className="mb-4 bg-surface2 border border-border rounded px-3 py-2 font-mono text-xs text-accent overflow-x-auto">
          {commandPreview}
        </div>
      )}

      <button
        onClick={() => install.mutate()}
        disabled={selected.size === 0 || install.isPending || isBusy}
        className="bg-accent text-bg font-medium text-sm rounded px-4 py-2 hover:opacity-90 disabled:opacity-50 transition active:scale-[0.98]"
      >
        {install.isPending ? "Queuing…" : isBusy ? "A run is already in progress…" : "Install selected tools"}
      </button>

      <ActionOverlay
        status={
          install.isPending
            ? "working"
            : install.isSuccess
            ? "success"
            : install.isError
            ? "error"
            : "idle"
        }
        label="Queuing install…"
        successMessage="Install queued — tracking progress above"
      />
    </div>
  );
}
