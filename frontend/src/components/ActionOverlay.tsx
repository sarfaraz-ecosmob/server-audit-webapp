"use client";

import { useEffect, useRef, useState } from "react";
import { Check } from "lucide-react";

export type OverlayStatus = "idle" | "working" | "success" | "error";

/**
 * Shows a brief "AI engine" style overlay while a real request is in flight,
 * then a checkmark flash on success. It never runs on a fake timer —
 * `status` should be derived directly from the actual mutation/request state
 * (e.g. `mutation.isPending ? "working" : mutation.isSuccess ? "success" :
 * mutation.isError ? "error" : "idle"`), so what's shown always matches what
 * the app is actually doing. On error it closes immediately and defers to
 * the page's own inline error message rather than duplicating it here.
 */
export default function ActionOverlay({
  status,
  label,
  successMessage = "Completed successfully",
}: {
  status: OverlayStatus;
  label: string;
  successMessage?: string;
}) {
  const [visible, setVisible] = useState(false);
  const [display, setDisplay] = useState<"working" | "success">("working");
  const prevStatus = useRef<OverlayStatus>("idle");

  useEffect(() => {
    const was = prevStatus.current;
    prevStatus.current = status;

    if (status === "working" && was !== "working") {
      setDisplay("working");
      setVisible(true);
    } else if (status === "success" && was === "working") {
      setDisplay("success");
      const t = setTimeout(() => setVisible(false), 700);
      return () => clearTimeout(t);
    } else if (status === "error" && was === "working") {
      setVisible(false);
    }
  }, [status]);

  if (!visible) return null;

  return (
    <div className="fixed inset-0 z-[60] bg-black/70 backdrop-blur-sm flex items-center justify-center px-4 fade-up">
      <div className="w-full max-w-sm bg-surface border border-accent/30 rounded-2xl p-6 shadow-glow">
        <div className="flex items-center gap-3 mb-5">
          <div className="relative h-10 w-10 rounded-full flex items-center justify-center shrink-0">
            <span
              className={`absolute inset-0 rounded-full ${
                display === "working" ? "bg-accent/20 glow-pulse" : "bg-ok/20"
              }`}
            />
            {display === "success" ? (
              <Check size={18} className="relative text-ok" />
            ) : (
              <span className="relative font-mono text-xs font-bold text-accent">S</span>
            )}
          </div>
          <div>
            <p className="text-sm font-medium">{display === "success" ? "Done" : label}</p>
            <p className="text-xs text-text2 font-mono">
              {display === "success" ? successMessage : "Talking to the server…"}
            </p>
          </div>
        </div>

        <div
          className={`relative h-1.5 rounded-full bg-surface2 overflow-hidden ${
            display === "working" ? "shimmer-bar" : ""
          }`}
        >
          <div
            className={`absolute inset-0 transition-all duration-500 ${
              display === "success"
                ? "bg-ok w-full"
                : "bg-gradient-to-r from-accent/20 via-accent/50 to-accent/20 w-full"
            }`}
          />
        </div>
      </div>
    </div>
  );
}
