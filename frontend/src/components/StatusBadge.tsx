import clsx from "clsx";

const CONFIG: Record<string, { label: string; dot: string; text: string }> = {
  queued: { label: "Queued", dot: "bg-text2", text: "text-text2" },
  running: { label: "Running", dot: "bg-accent animate-pulse", text: "text-accent" },
  completed: { label: "Completed", dot: "bg-ok", text: "text-ok" },
  failed: { label: "Failed", dot: "bg-crit", text: "text-crit" },
  idle: { label: "Not yet run", dot: "bg-text2", text: "text-text2" },
};

export default function StatusBadge({ status }: { status: string }) {
  const cfg = CONFIG[status] ?? CONFIG.idle;
  return (
    <span className={clsx("inline-flex items-center gap-1.5 text-xs font-medium font-mono", cfg.text)}>
      <span className={clsx("h-1.5 w-1.5 rounded-full", cfg.dot)} />
      {cfg.label}
    </span>
  );
}
