import React, { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { ThemeProvider } from "./ThemeContext.jsx";
import { useVpn } from "./useVpn.jsx";
import { ConnectScreen } from "./screens/ConnectScreen.jsx";
import { ProfilesScreen } from "./screens/ProfilesScreen.jsx";
import { SettingsScreen } from "./screens/SettingsScreen.jsx";
import { BottomNav } from "./components/BottomNav.jsx";

function cloneCfg(c) {
  return JSON.parse(JSON.stringify(c));
}

function AppInner() {
  const { snap, busy, connect, disconnect, saveCfg, applyInvite, refreshFromControlPlane, clearError, refresh } = useVpn();
  const [tab, setTab] = useState("connect");
  /** @type {[import('./vpnTypes').SavedConfig | null, (c: import('./vpnTypes').SavedConfig | null) => void]} */
  const [draft, setDraft] = useState(null);
  /** Ждём VPN после вызова connect (диалог разрешения Android и пока туннель не поднялся). */
  const [tunnelHandshake, setTunnelHandshake] = useState(false);

  useEffect(() => {
    if (tab === "connect") setDraft(null);
  }, [tab]);

  useEffect(() => {
    let unlisten = () => {};
    (async () => {
      unlisten = await listen("control-plane-import", () => {
        setDraft(null);
        setTab("profiles");
      });
    })();
    return () => unlisten();
  }, []);

  useEffect(() => {
    if (tab !== "connect") setTunnelHandshake(false);
  }, [tab]);

  /** Рукопожатие закончилось, когда туннель реально поднялся (ошибки обрабатываются через catch invoke и clear_error). */
  useEffect(() => {
    if (!tunnelHandshake || !snap) return;
    if (snap.connected) setTunnelHandshake(false);
  }, [snap?.connected, tunnelHandshake]);

  /** Туннель на Android поднимается после JNI; без опроса UI зависает в «рукопожатии». */
  useEffect(() => {
    if (!tunnelHandshake) return;
    if (snap?.connected) return;
    const id = setInterval(() => {
      refresh();
    }, 650);
    return () => clearInterval(id);
  }, [tunnelHandshake, snap?.connected, refresh]);

  /** Снимаем зависший «handshake», если туннель так и не попал в snapshot (ошибка JNI и т.п.). */
  useEffect(() => {
    if (!tunnelHandshake) return;
    const id = setTimeout(() => setTunnelHandshake(false), 120000);
    return () => clearTimeout(id);
  }, [tunnelHandshake]);

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

  const goTab = useCallback(
    async (/** @type {"connect" | "profiles" | "settings"} */ next) => {
      if (next === tab) return;
      if (tab === "settings") {
        await saveDraft();
      }
      setTab(next);
    },
    [tab, saveDraft]
  );

  const saveSettingsAndGoConnect = useCallback(async () => {
    await saveDraft();
    setTab("connect");
  }, [saveDraft]);

  /** Показываем «рукопожатие»: пока invoke идёт (busy), или пока ждём появление туннеля после диалога VPN. */
  const connectPhasePending =
    tunnelHandshake || Boolean(busy && snap && !snap.connected);

  async function handleToggleConnect() {
    if (!snap) return;
    if (snap.connected) {
      setTunnelHandshake(false);
      await disconnect();
      return;
    }
    setTunnelHandshake(true);
    try {
      const s = await connect();
      if (s?.connected) setTunnelHandshake(false);
    } catch {
      setTunnelHandshake(false);
    }
  }

  if (!snap) {
    return (
      <div style={{ padding: 24, fontFamily: "IBM Plex Mono", color: "#6a7c78" }}>…</div>
    );
  }

  const boringAvailable = Boolean(snap.capabilities?.boring_tls_available);
  const cfg = draft ?? snap.cfg;

  let main = null;
  if (tab === "profiles") {
    main = (
      <ProfilesScreen
        cfg={cfg}
        onSave={async (c) => {
          setDraft(c);
          await saveCfg(c);
        }}
      />
    );
  } else if (tab === "settings") {
    main = (
      <SettingsScreen
        cfg={cfg}
        setCfg={setCfg}
        boringAvailable={boringAvailable}
        onPersist={saveDraft}
        onSave={saveSettingsAndGoConnect}
        lastError={snap.error}
        onClearError={clearError}
        onApplyInvite={async () => {
          try {
            await applyInvite();
          } finally {
            setDraft(null);
          }
        }}
        onRefreshFromControlPlane={async () => {
          try {
            await refreshFromControlPlane();
          } finally {
            setDraft(null);
          }
        }}
      />
    );
  } else {
    main = (
      <ConnectScreen
        snap={snap}
        connectPending={connectPhasePending}
        refresh={refresh}
        onSettings={() => goTab("settings")}
        onToggleConnect={handleToggleConnect}
        onClearError={clearError}
      />
    );
  }

  return (
    <div
      style={{
        minHeight: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        isolation: "isolate",
        background: `
          radial-gradient(1200px 800px at 20% 10%, rgba(244,244,240,0.025), transparent 60%),
          radial-gradient(1200px 800px at 80% 90%, rgba(244,244,240,0.018), transparent 60%),
          #070809`,
      }}
    >
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          zIndex: 0,
        }}
      >
        {main}
      </div>
      <BottomNav value={tab} onChange={goTab} />
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  );
}
