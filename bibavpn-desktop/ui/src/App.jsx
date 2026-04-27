import React, { useCallback, useEffect, useState } from "react";
import { ThemeProvider } from "./ThemeContext.jsx";
import { useVpn } from "./useVpn.jsx";
import { ConnectScreen } from "./screens/ConnectScreen.jsx";
import { ProfilesScreen } from "./screens/ProfilesScreen.jsx";
import { SettingsScreen } from "./screens/SettingsScreen.jsx";

function cloneCfg(c) {
  return JSON.parse(JSON.stringify(c));
}

function AppInner() {
  const { snap, connect, disconnect, saveCfg, applyInvite, clearError } = useVpn();
  const [tab, setTab] = useState("connect");
  /** @type {[import('./vpnTypes').SavedConfig | null, (c: import('./vpnTypes').SavedConfig | null) => void]} */
  const [draft, setDraft] = useState(null);
  const [connectPending, setConnectPending] = useState(false);

  useEffect(() => {
    if (tab === "connect") setDraft(null);
  }, [tab]);

  const setCfg = useCallback((updater) => {
    setDraft((d) => {
      const base = d ?? (snap?.cfg ? cloneCfg(snap.cfg) : null);
      if (!base) return null;
      return typeof updater === "function" ? updater(base) : updater;
    });
  }, [snap]);

  const saveDraft = useCallback(async () => {
    const toSave = draft ?? snap?.cfg;
    if (!toSave) return;
    const s = await saveCfg(toSave);
    if (s?.cfg) setDraft(cloneCfg(s.cfg));
  }, [draft, snap, saveCfg]);

  async function handleToggleConnect() {
    if (!snap) return;
    if (snap.connected) {
      await disconnect();
      return;
    }
    setConnectPending(true);
    try {
      await connect();
    } catch {
      /* error surfaced in snap */
    } finally {
      setConnectPending(false);
    }
  }

  if (!snap) {
    return (
      <div style={{ padding: 24, fontFamily: "IBM Plex Mono", color: "#6a7c78" }}>…</div>
    );
  }

  const boringAvailable = Boolean(snap.capabilities?.boring_tls_available);

  if (tab === "profiles") {
    const cfg = draft ?? snap.cfg;
    return (
      <ProfilesScreen
        cfg={cfg}
        onSave={async (c) => {
          setDraft(c);
          await saveCfg(c);
        }}
        onBack={() => setTab("connect")}
      />
    );
  }

  if (tab === "settings") {
    const cfg = draft ?? snap.cfg;
    return (
      <SettingsScreen
        cfg={cfg}
        setCfg={setCfg}
        boringAvailable={boringAvailable}
        onBack={() => setTab("connect")}
        onSave={saveDraft}
        onApplyInvite={applyInvite}
      />
    );
  }

  return (
    <ConnectScreen
      snap={snap}
      connectPending={connectPending}
      onSettings={() => setTab("settings")}
      onProfiles={() => setTab("profiles")}
      onToggleConnect={handleToggleConnect}
      onClearError={clearError}
    />
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  );
}
