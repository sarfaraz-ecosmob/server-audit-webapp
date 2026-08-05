"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { X } from "lucide-react";

export default function AddServerModal({
  projectId,
  onClose,
}: {
  projectId: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(22);
  const [username, setUsername] = useState("");
  const [authType, setAuthType] = useState<"password" | "private_key">("password");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [webTargets, setWebTargets] = useState("");
  const [error, setError] = useState("");

  const addServer = useMutation({
    mutationFn: async () =>
      (
        await api.post(`/projects/${projectId}/servers`, {
          name,
          host,
          port,
          username,
          auth_type: authType,
          password: authType === "password" ? password : undefined,
          private_key: authType === "private_key" ? privateKey : undefined,
          private_key_passphrase: authType === "private_key" ? passphrase || undefined : undefined,
          web_targets: webTargets
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        })
      ).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["project", projectId] });
      onClose();
    },
    onError: (err: any) => setError(err?.response?.data?.detail || "Could not add server"),
  });

  const field = "w-full bg-surface2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-accent font-mono";

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4 overflow-y-auto py-8">
      <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-medium">Add server</h2>
            <p className="text-xs text-text2 mt-0.5">
              Credentials are encrypted at rest and used only to SSH in and run the approved scripts.
            </p>
          </div>
          <button onClick={onClose} className="text-text2 hover:text-text">
            <X size={18} />
          </button>
        </div>

        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs text-text2">Display name</label>
            <input value={name} onChange={(e) => setName(e.target.value)} className={field.replace(" font-mono", "")} placeholder="opensips-central-01" />
          </div>

          <div className="grid grid-cols-3 gap-2">
            <div className="col-span-2 space-y-1">
              <label className="text-xs text-text2">Host / IP</label>
              <input value={host} onChange={(e) => setHost(e.target.value)} className={field} placeholder="10.0.4.12" />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-text2">Port</label>
              <input type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} className={field} />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-xs text-text2">SSH username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} className={field} placeholder="root" />
          </div>

          <div className="flex gap-2 text-xs">
            {(["password", "private_key"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setAuthType(t)}
                className={`flex-1 rounded border px-3 py-1.5 transition ${
                  authType === t ? "border-accent text-accent bg-accent/10" : "border-border text-text2"
                }`}
              >
                {t === "password" ? "Password" : "Private key"}
              </button>
            ))}
          </div>

          {authType === "password" ? (
            <div className="space-y-1">
              <label className="text-xs text-text2">Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={field} />
            </div>
          ) : (
            <>
              <div className="space-y-1">
                <label className="text-xs text-text2">Private key (PEM)</label>
                <textarea
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  rows={4}
                  className={field}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-text2">Passphrase (optional)</label>
                <input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} className={field} />
              </div>
            </>
          )}

          <div className="space-y-1">
            <label className="text-xs text-text2">Web targets for ZAP scan (comma-separated, optional)</label>
            <input value={webTargets} onChange={(e) => setWebTargets(e.target.value)} className={field} placeholder="https://app.example.com" />
          </div>

          {error && <p className="text-xs text-crit">{error}</p>}

          <button
            onClick={() => {
              setError("");
              addServer.mutate();
            }}
            disabled={!name || !host || !username || addServer.isPending}
            className="w-full bg-accent text-bg font-medium text-sm rounded py-2 hover:opacity-90 disabled:opacity-50 transition"
          >
            {addServer.isPending ? "Adding…" : "Add server"}
          </button>
        </div>
      </div>
    </div>
  );
}
