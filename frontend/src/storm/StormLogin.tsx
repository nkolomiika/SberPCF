/* STORM sign-in screen. Styled in the STORM design language and wired to the
   real backend auth via useAuthStore.signIn (POST /api/v1/auth/login). */

import { useState, type FormEvent } from "react";
import "./storm.css";
import { Icon, SberMark } from "./icons";
import { useAuthStore, useToastStore } from "../store";

export function StormLogin() {
  const signIn = useAuthStore((s) => s.signIn);
  const isLoading = useAuthStore((s) => s.isLoading);
  const pushToast = useToastStore((s) => s.pushToast);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const disabled = isLoading || !username.trim() || !password;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (disabled) return;
    try {
      await signIn(username.trim(), password);
      // On success the auth store sets `user`; StormRoot swaps in the app.
    } catch (err) {
      // Surface the (now status-aware) error as a bottom-right toast.
      const message = err instanceof Error && err.message.trim() ? err.message : "Не удалось выполнить вход";
      pushToast(message, "error");
    }
  };

  return (
    <div className="storm" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "#eef1f6" }}>
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ width: 420, maxWidth: "100%" }}>
          {/* brand */}
          <div style={{ display: "flex", alignItems: "center", gap: 11, justifyContent: "center", marginBottom: 22 }}>
            <SberMark size={30} />
            <div style={{ fontWeight: 800, fontSize: 22, letterSpacing: 3, color: "#1a2431" }}>STORM</div>
          </div>

          <form onSubmit={handleSubmit} style={{ background: "#fff", border: "1px solid #e9edf4", borderRadius: 20, boxShadow: "0 24px 60px rgba(15,27,45,.10)", padding: "32px 34px 30px" }}>
            <h1 style={{ margin: "0 0 22px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "#0F1B2D" }}>Sign in</h1>

            <div style={{ marginBottom: 15 }}>
              <label className="flabel" htmlFor="storm-user">Username</label>
              <input id="storm-user" className="finp" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div style={{ marginBottom: 22 }}>
              <label className="flabel" htmlFor="storm-pass">Password</label>
              <input id="storm-pass" className="finp" type="password" autoComplete="current-password" placeholder="••••••••" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>

            <button
              type="submit"
              className="clk"
              disabled={disabled}
              style={{
                width: "100%",
                height: 46,
                border: "none",
                borderRadius: 12,
                background: disabled ? "#a8c0ea" : "#2E5FBF",
                color: "#fff",
                font: "700 14px Inter,sans-serif",
                cursor: disabled ? "not-allowed" : "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                gap: 9,
                boxShadow: "0 6px 18px rgba(46,95,191,.28)",
              }}
            >
              {isLoading ? "Signing in…" : "Sign in"}
              {!isLoading && <Icon name="chevron-right" size={16} color="#fff" sw={2.4} />}
            </button>
          </form>
        </div>
      </div>

      <footer style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, background: "transparent", fontSize: 12.5, color: "#a0abbd", flexWrap: "wrap" }}>
        <span style={{ fontWeight: 700, color: "#7c8aa0" }}>STORM</span>
        <span>·</span>
        <span>Licensed to SberTech · Copyright © 2026. All rights reserved.</span>
      </footer>
    </div>
  );
}
