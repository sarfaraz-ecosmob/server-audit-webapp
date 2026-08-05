"use client";

import { useEffect, useState } from "react";
import { AuditRun } from "@/lib/types";
import { Loader2, Check } from "lucide-react";

// The exact, real phase sequence server_audit.sh logs as it runs — sourced
// directly from its own `main()` function (see the backend's bundled copy).
// Every phase header always prints regardless of which tools were selected
// for this run (only the tool invocation inside a phase is conditionally
// skipped), so this fixed order is accurate for every audit run.
const AUDIT_PHASES = [
  "System Data Collection",
  "Infrastructure Audit (Lynis)",
  "Network Security",
  "SSH Security",
  "User & Auth Checks",
  "Service & OS Health Check",
  "Rootkit Scan (rkhunter)",
  "Web Application Scan (ZAP)",
  "HTML Report Generation",
];

function useElapsed(startedAt?: string) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!startedAt) return;
    const start = new Date(startedAt).getTime();
    const tick = () => setElapsed(Math.max(0, Math.floor((Date.now() - start) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);
  return elapsed;
}

function formatDuration(seconds: number) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return m > 0 ? `${m}m ${s.toString().padStart(2, "0")}s` : `${s}s`;
}

function phaseLabel(run: AuditRun, elapsed: number, currentPhase?: string) {
  if (run.status === "queued") return "Waiting for a worker to pick this up…";
  // Prefer the real, currently-observed phase (read from the run's own log)
  // over a generic time-based guess, the moment we have one.
  if (currentPhase) return `Currently: ${currentPhase}`;
  if (elapsed < 8) return "Opening SSH connection…";
  if (elapsed < 20) return "Preparing scripts on the target…";
  if (run.run_type === "install_tools") return "Installing selected tools…";
  return "Scan in progress — duration depends on which tools are selected…";
}

export default function LiveRunPanel({ run }: { run: AuditRun }) {
  const elapsed = useElapsed(run.started_at);
  const isQueued = run.status === "queued";
  const label = run.run_type === "install_tools" ? "Installing tools" : "Running audit";
  const currentPhase = run.summary?.current_phase;
  const currentIndex = currentPhase ? AUDIT_PHASES.indexOf(currentPhase) : -1;
  const showStepper = run.run_type === "audit" && !isQueued;

  return (
    <div className="relative overflow-hidden bg-surface border border-accent/30 rounded-lg px-5 py-4 mb-6 fade-up">
      <div className="absolute inset-0 bg-grid-drift opacity-40 pointer-events-none" />
      <div className="relative flex items-center gap-4">
        {/* Radar: literal "actively scanning" visualization, not decorative —
            a sweeping line + expanding rings, echoing what's actually
            happening on the target right now. */}
        <svg width="52" height="52" viewBox="0 0 52 52" className="shrink-0">
          <circle cx="26" cy="26" r="24" fill="none" stroke="#232935" strokeWidth="1.5" />
          <circle cx="26" cy="26" r="16" fill="none" stroke="#232935" strokeWidth="1" />
          <circle className="radar-ring" cx="26" cy="26" r="10" fill="none" stroke="#4FD1C5" strokeWidth="1.5" />
          <g className={isQueued ? "" : "radar-sweep"}>
            <line x1="26" y1="26" x2="26" y2="3" stroke="#4FD1C5" strokeWidth="2" strokeLinecap="round" opacity="0.9" />
          </g>
          <circle cx="26" cy="26" r="3" fill="#4FD1C5" />
        </svg>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="font-medium text-sm">{label}</h3>
            {isQueued && <Loader2 size={13} className="animate-spin text-text2" />}
          </div>
          <p className="text-xs text-text2 mt-0.5 font-mono">{phaseLabel(run, elapsed, currentPhase)}</p>

          <div className="relative h-1.5 rounded-full bg-surface2 overflow-hidden mt-2.5 shimmer-bar">
            <div className="absolute inset-0 bg-gradient-to-r from-accent/20 via-accent/40 to-accent/20" />
          </div>
        </div>

        <div className="text-right shrink-0">
          <p className="font-mono text-lg font-semibold text-accent tabular-nums">
            {formatDuration(elapsed)}
          </p>
          <p className="text-[11px] text-text2">elapsed</p>
        </div>
      </div>

      {showStepper && (
        <div className="relative mt-4 pt-4 border-t border-border/60">
          <div className="relative pl-1">
            {/* Vertical progress line — the wire motif again, this time
                literally filling as real phases (read from the target's own
                log) complete, not on a timer. */}
            <div className="absolute left-[7px] top-1 bottom-1 w-px bg-border" />
            <div
              className="absolute left-[7px] top-1 w-px bg-accent transition-all duration-700 ease-out"
              style={{
                height:
                  currentIndex >= 0
                    ? `${(currentIndex / (AUDIT_PHASES.length - 1)) * 100}%`
                    : "0%",
              }}
            />
            <div className="flex flex-col gap-2">
              {AUDIT_PHASES.map((phase, i) => {
                const state =
                  currentIndex < 0
                    ? "pending"
                    : i < currentIndex
                    ? "done"
                    : i === currentIndex
                    ? "active"
                    : "pending";
                return (
                  <div key={phase} className="flex items-center gap-2.5 text-xs pl-0">
                    <span
                      className={`relative z-10 h-3.5 w-3.5 rounded-full shrink-0 flex items-center justify-center border transition-colors duration-500 ${
                        state === "done"
                          ? "bg-ok border-ok"
                          : state === "active"
                          ? "bg-accent border-accent"
                          : "bg-surface border-border"
                      }`}
                    >
                      {state === "active" && (
                        <span className="absolute inset-0 rounded-full bg-accent radar-ring" />
                      )}
                      {state === "done" && <Check size={9} className="text-bg" strokeWidth={3} />}
                    </span>
                    <span
                      className={`transition-colors duration-500 ${
                        state === "done"
                          ? "text-text2"
                          : state === "active"
                          ? "text-accent font-medium"
                          : "text-text2/40"
                      }`}
                    >
                      {phase}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
