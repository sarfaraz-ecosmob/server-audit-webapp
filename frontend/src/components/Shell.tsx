"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { clearToken } from "@/lib/api";
import { LogOut } from "lucide-react";
import NeuronBackground from "@/components/NeuronBackground";

export default function Shell({
  children,
  crumbs,
}: {
  children: React.ReactNode;
  crumbs?: { label: string; href?: string }[];
}) {
  const router = useRouter();

  return (
    <div className="min-h-screen bg-bg">
      <NeuronBackground density={0.35} opacity={0.5} />
      <header className="sticky top-0 z-40 border-b border-border bg-surface/80 backdrop-blur relative">
        <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-accent/40 to-transparent" />
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between relative">
          <div className="flex items-center gap-2">
            <Link href="/projects" className="flex items-center gap-2">
              <div className="relative h-6 w-6 rounded border border-accent/40 flex items-center justify-center text-accent font-mono text-xs font-semibold">
                <span className="absolute inset-0 rounded bg-accent/10 glow-pulse" />
                <span className="relative">S</span>
              </div>
              <span className="font-semibold text-sm tracking-tight">Server Audit</span>
            </Link>
            {crumbs && crumbs.length > 0 && (
              <nav className="flex items-center gap-1.5 text-sm text-text2 ml-3 font-mono">
                {crumbs.map((c, i) => (
                  <span key={i} className="flex items-center gap-1.5">
                    <span className="text-border">/</span>
                    {c.href ? (
                      <Link href={c.href} className="hover:text-accent transition-colors">
                        {c.label}
                      </Link>
                    ) : (
                      <span className="text-text">{c.label}</span>
                    )}
                  </span>
                ))}
              </nav>
            )}
          </div>
          <button
            onClick={() => {
              clearToken();
              router.push("/login");
            }}
            className="flex items-center gap-1.5 text-xs text-text2 hover:text-text transition-colors"
          >
            <LogOut size={14} /> Sign out
          </button>
        </div>
      </header>
      <main className="max-w-6xl mx-auto px-6 py-8">{children}</main>
    </div>
  );
}
