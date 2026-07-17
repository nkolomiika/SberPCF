import React, { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { StormApp } from "./storm/StormApp";
import { StormLogin } from "./storm/StormLogin";
import { StormToaster } from "./storm/StormToaster";
import { SberMark } from "./storm/icons";
import { useAuthStore } from "./store";

/** The signed-out URL. Everything else belongs to the authenticated app. */
export const LOGIN_PATH = "/login";

/** Auth gate: initialise the session, then show the login screen or the app. */
export function StormRoot() {
  const initialize = useAuthStore((s) => s.initialize);
  const isInitialized = useAuthStore((s) => s.isInitialized);
  const user = useAuthStore((s) => s.user);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    void initialize();
  }, [initialize]);

  /* The URL has to follow the auth state, not just the rendered component:
     signing out must leave /projects/1 for /login, and signing in must not strand
     the user on /login. `replace` keeps signed-out pages out of the back history.
     Waits for isInitialized, otherwise a reload would bounce to /login before the
     session is known. */
  useEffect(() => {
    if (!isInitialized) return;
    if (!user && location.pathname !== LOGIN_PATH) navigate(LOGIN_PATH, { replace: true });
    else if (user && location.pathname === LOGIN_PATH) navigate("/projects", { replace: true });
  }, [isInitialized, user, location.pathname, navigate]);

  let content: React.ReactNode;
  if (!isInitialized) {
    content = (
      <div className="storm" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, background: "#eef1f6" }}>
        <SberMark size={40} />
        <div className="mono" style={{ fontSize: 11, letterSpacing: 2, color: "#a0abbd", fontWeight: 700 }}>LOADING STORM…</div>
      </div>
    );
  } else if (!user) {
    content = <StormLogin />;
  } else {
    content = <StormApp />;
  }

  return (
    <>
      {content}
      <StormToaster />
    </>
  );
}
