import React, { useState } from "react";
import { loginUser } from "../lib/api";

export default function LoginPage({ onSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const data = await loginUser(username, password);
      onSuccess?.(data);
    } catch (err) {
      setError(err?.response?.data?.detail || "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative grid h-full min-h-screen place-items-center px-6">
      <div className="bg-grid" aria-hidden />
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <div className="mx-auto h-14 w-14 overflow-hidden rounded-2xl border border-emerald-500/40 bg-[#0b1a14] shadow-[0_0_32px_-6px_rgba(52,211,153,0.7)]">
            <img src={`${import.meta.env.BASE_URL}logo.png`} alt="TriNetra" className="h-full w-full object-cover" />
          </div>
          <h1 className="mt-5 text-2xl font-bold tracking-tight">
            Tri<span className="text-grad-emerald">Netra</span>
          </h1>
          <p className="eyebrow mt-2">Universal Log Pre-processing · live console</p>
        </div>

        <form onSubmit={submit} className="glass space-y-4 p-6">
          <label className="block">
            <span className="eyebrow mb-1.5 block">Username</span>
            <input
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="field mono w-full py-2.5 px-3"
              placeholder="admin"
              autoCapitalize="none"
              autoComplete="username"
            />
          </label>
          <label className="block">
            <span className="eyebrow mb-1.5 block">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="field mono w-full py-2.5 px-3"
              placeholder="••••••••"
              autoComplete="current-password"
            />
          </label>

          {error && <p className="text-[12px] text-red-400">{error}</p>}

          <button type="submit" disabled={busy} className="btn-primary w-full">
            {busy ? "AUTHENTICATING…" : "SIGN IN"}
          </button>
        </form>

        <p className="text-center text-[10px] uppercase tracking-widest text-slate-600">
          protected console · sessions expire
        </p>
      </div>
    </div>
  );
}