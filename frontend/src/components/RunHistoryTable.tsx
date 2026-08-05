"use client";

import { AuditRun } from "@/lib/types";
import StatusBadge from "@/components/StatusBadge";
import { api } from "@/lib/api";
import { Download, FileText } from "lucide-react";

export default function RunHistoryTable({
  runs,
  onSelect,
  selectedId,
}: {
  runs: AuditRun[];
  onSelect: (run: AuditRun) => void;
  selectedId?: string;
}) {
  async function download(run: AuditRun) {
    const res = await api.get(`/audit-runs/${run.id}/report`, { responseType: "blob" });
    const url = URL.createObjectURL(res.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security_audit_report_${run.id}.html`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="bg-surface border border-border rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-text2 border-b border-border">
            <th className="px-4 py-2.5 font-medium">Type</th>
            <th className="px-4 py-2.5 font-medium">Status</th>
            <th className="px-4 py-2.5 font-medium">Started</th>
            <th className="px-4 py-2.5 font-medium">Duration</th>
            <th className="px-4 py-2.5 font-medium"></th>
          </tr>
        </thead>
        <tbody>
          {runs.map((run) => {
            const duration =
              run.finished_at && run.started_at
                ? `${Math.round(
                    (new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000
                  )}s`
                : "—";
            return (
              <tr
                key={run.id}
                onClick={() => onSelect(run)}
                className={`border-b border-border last:border-0 cursor-pointer hover:bg-surface2 transition ${
                  selectedId === run.id ? "bg-surface2" : ""
                }`}
              >
                <td className="px-4 py-2.5 font-mono text-xs">{run.run_type}</td>
                <td className="px-4 py-2.5">
                  <StatusBadge status={run.status} />
                </td>
                <td className="px-4 py-2.5 text-text2 text-xs font-mono">
                  {new Date(run.started_at).toLocaleString()}
                </td>
                <td className="px-4 py-2.5 text-text2 text-xs font-mono">{duration}</td>
                <td className="px-4 py-2.5 text-right">
                  {run.report_path && run.status === "completed" && (
                    <div className="flex items-center gap-2 justify-end">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelect(run);
                        }}
                        className="text-text2 hover:text-accent transition"
                        title="View report"
                      >
                        <FileText size={14} />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          download(run);
                        }}
                        className="text-text2 hover:text-accent transition"
                        title="Download report"
                      >
                        <Download size={14} />
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
