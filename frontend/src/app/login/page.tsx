"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, saveToken } from "@/lib/api";
import NeuronBackground from "@/components/NeuronBackground";
import ActionOverlay, { OverlayStatus } from "@/components/ActionOverlay";

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [status, setStatus] = useState<OverlayStatus>("idle");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setStatus("working");
    try {
      let res;
      if (mode === "login") {
        const form = new URLSearchParams();
        form.set("username", email);
        form.set("password", password);
        res = await api.post("/auth/login", form, {
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });
      } else {
        res = await api.post("/auth/register", { email, password });
      }
      saveToken(res.data.access_token, rememberMe);
      setStatus("success");
      // Brief pause so the success state is actually visible before navigating —
      // purely cosmetic; the login itself has already fully succeeded above.
      setTimeout(() => router.push("/projects"), 550);
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Something went wrong");
      setStatus("error");
    }
  }

  const loading = status === "working" || status === "success";

  return (
    <div className="relative min-h-screen flex items-center justify-center bg-bg px-4 overflow-hidden">
      <NeuronBackground density={1} opacity={1} />
      <div className="relative w-full max-w-sm fade-up">
        <div className="flex items-center gap-2 mb-8 justify-center">
          <div className="h-9 w-9 rounded-full border border-accent/40 bg-accent/10 flex items-center justify-center text-accent font-mono font-semibold shadow-glow">
            S
          </div>
          <span className="text-lg font-semibold tracking-tight">Server Audit</span>
        </div>

        <form
          onSubmit={submit}
          className="bg-white/[0.06] border border-white/[0.12] backdrop-blur-xl rounded-2xl p-6 space-y-4 shadow-glow"
        >
          <h1 className="text-sm text-text2 font-mono uppercase tracking-wide">
            {mode === "login" ? "Sign in" : "Create account"}
          </h1>

          <div className="space-y-1">
            <label className="text-xs text-text2">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white/[0.06] border border-white/[0.1] rounded-lg px-3 py-2.5 text-sm outline-none focus:border-accent transition-colors"
              placeholder="you@ecosmob.com"
            />
          </div>

          <div className="space-y-1">
            <label className="text-xs text-text2">Password</label>
            <input
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-white/[0.06] border border-white/[0.1] rounded-lg px-3 py-2.5 text-sm outline-none focus:border-accent transition-colors"
              placeholder="••••••••"
            />
          </div>

          {mode === "login" && (
            <label className="flex items-center gap-2 text-xs text-text2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="accent-accent"
              />
              Remember me on this device
            </label>
          )}

          {error && <p className="text-xs text-crit">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent text-bg font-medium text-sm rounded-lg py-2.5 hover:opacity-90 disabled:opacity-50 transition active:scale-[0.98]"
          >
            {status === "working"
              ? "Please wait…"
              : status === "success"
              ? "Signed in ✓"
              : mode === "login"
              ? "Sign in"
              : "Create account"}
          </button>

          <button
            type="button"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
            className="w-full text-xs text-text2 hover:text-text transition"
          >
            {mode === "login" ? "Need an account? Register" : "Already have an account? Sign in"}
          </button>
        </form>
      </div>

      <ActionOverlay status={status} label={mode === "login" ? "Signing in…" : "Creating your account…"} />
    </div>
  );
}
