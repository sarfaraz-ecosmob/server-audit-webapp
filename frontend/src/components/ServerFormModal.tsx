"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Server } from "@/lib/types";
import { X } from "lucide-react";
import ActionOverlay from "@/components/ActionOverlay";

export default function ServerFormModal({
  projectId,
  server,
  onClose,
}: {
  projectId: string;
  server?: Server;
  onClose: () => void;
}) {
  const isEdit = !!server;
  const qc = useQueryClient();
  const [name, setName] = useState(server?.name ?? "");
  const [host, setHost] = useState(server?.host ?? "");
  const [port, setPort] = useState(server?.port ?? 22);
  const [username, setUsername] = useState(server?.username ?? "");
  const [authType, setAuthType] = useState<"password" | "private_key">(server?.auth_type ?? "password");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [webTargets, setWebTargets] = useState((server?.web_targets ?? []).join(", "));
  const [sudoPassword, setSudoPassword] = useState("");
  const [clearSudoPassword, setClearSudoPassword] = useState(false);
  const [error, setError] = useState("");

  const parsedWebTargets = () =>
    webTargets
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

  const save = useMutation({
    mutationFn: async () => {
      const credentialFields =
        authType === "password"
          ? password
            ? { password }
            : {}
          : privateKey
          ? { private_key: privateKey, private_key_passphrase: passphrase || undefined }
          : {};

      if (isEdit) {
        const authChanged = authType !== server!.auth_type;
        if (authChanged && Object.keys(credentialFields).length === 0) {
          throw { response: { data: { detail: "Provide the new credential when changing auth type" } } };
        }
        return (
          await api.patch(`/servers/${server!.id}`, {
            name,
            host,
            port,
            username,
            auth_type: authChanged || Object.keys(credentialFields).length > 0 ? authType : undefined,
            web_targets: parsedWebTargets(),
            sudo_password: sudoPassword || undefined,
            clear_sudo_password: clearSudoPassword,
            ...credentialFields,
          })
        ).data;
      }

      if (Object.keys(credentialFields).length === 0) {
        throw { response: { data: { detail: "A password or private key is required" } } };
      }
      return (
        await api.post(`/projects/${projectId}/servers`, {
          name,
          host,
          port,
          username,
          auth_type: authType,
          web_targets: parsedWebTargets(),
          sudo_password: sudoPassword || undefined,
          ...credentialFields,
        })
      ).data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["project", projectId] });
      if (server) qc.invalidateQueries({ queryKey: ["server", server.id] });
      // Brief pause so the success checkmark is visible before the modal
      // (and this component) unmounts — the save itself already fully
      // succeeded above.
      setTimeout(onClose, 650);
    },
    onError: (err: any) => setError(err?.response?.data?.detail || "Could not save server"),
  });

  const field = "w-full bg-surface2 border border-border rounded px-3 py-2 text-sm outline-none focus:border-accent font-mono";

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 px-4 overflow-y-auto py-8">
      <div className="fade-up bg-surface border border-border rounded-lg p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-medium">{isEdit ? "Edit server" : "Add server"}</h2>
            <p className="text-xs text-text2 mt-0.5">
              {isEdit
                ? "Leave password/key blank to keep the existing credential."
                : "Credentials are encrypted at rest and used only to SSH in and run the approved scripts."}
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
              <label className="text-xs text-text2">
                Password{isEdit && " (leave blank to keep current)"}
              </label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={field} />
            </div>
          ) : (
            <>
              <div className="space-y-1">
                <label className="text-xs text-text2">
                  Private key (PEM){isEdit && " (leave blank to keep current)"}
                </label>
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

          <div className="space-y-1 border-t border-border pt-3">
            <label className="text-xs text-text2">
              Sudo password{isEdit && server?.has_sudo_password && " (currently set — leave blank to keep)"}
            </label>
            <input
              type="password"
              value={sudoPassword}
              onChange={(e) => {
                setSudoPassword(e.target.value);
                if (e.target.value) setClearSudoPassword(false);
              }}
              className={field}
              placeholder={
                authType === "password"
                  ? "Optional — defaults to the SSH password above"
                  : "Required if this account needs a password for sudo"
              }
            />
            <p className="text-[11px] text-text2 leading-snug">
              {authType === "password"
                ? "Used to run install_tools.sh / server_audit.sh with sudo. If left blank, the SSH password above is reused."
                : "Key-based login has no password to reuse for sudo. Leave blank only if this account has passwordless (NOPASSWD) sudo already configured."}
            </p>
            {isEdit && server?.has_sudo_password && (
              <label className="flex items-center gap-1.5 text-[11px] text-text2 pt-1">
                <input
                  type="checkbox"
                  checked={clearSudoPassword}
                  onChange={(e) => {
                    setClearSudoPassword(e.target.checked);
                    if (e.target.checked) setSudoPassword("");
                  }}
                  className="accent-accent"
                />
                Clear stored sudo password (fall back to SSH password / NOPASSWD)
              </label>
            )}
          </div>

          <div className="space-y-1">
            <label className="text-xs text-text2">Web targets for ZAP scan (comma-separated, optional)</label>
            <input value={webTargets} onChange={(e) => setWebTargets(e.target.value)} className={field} placeholder="https://app.example.com" />
          </div>

          {error && <p className="text-xs text-crit">{error}</p>}

          <button
            onClick={() => {
              setError("");
              save.mutate();
            }}
            disabled={!name || !host || !username || save.isPending}
            className="w-full bg-accent text-bg font-medium text-sm rounded py-2 hover:opacity-90 disabled:opacity-50 transition active:scale-[0.98]"
          >
            {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Add server"}
          </button>
        </div>
      </div>

      <ActionOverlay
        status={save.isPending ? "working" : save.isSuccess ? "success" : save.isError ? "error" : "idle"}
        label={isEdit ? "Saving server…" : "Adding server…"}
      />
    </div>
  );
}
