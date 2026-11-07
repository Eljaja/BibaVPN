import React, { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ThemeProvider, useT } from "./ThemeContext.jsx";
import { useVpn } from "./useVpn.jsx";
import { ConnectScreen } from "./screens/ConnectScreen.jsx";
import { ProfilesScreen } from "./screens/ProfilesScreen.jsx";
import { SettingsScreen } from "./screens/SettingsScreen.jsx";
import { BottomNav } from "./components/BottomNav.jsx";
import { Btn } from "./ui/primitives.jsx";
import { t } from "./i18n.js";
import { MONO, SANS } from "./theme.js";

function cloneCfg(c) {
  return JSON.parse(JSON.stringify(c));
}

function AppInner() {
  const {
    snap,
    busy,
    connect,
    disconnect,
    saveCfg,
    applyInvite,
    refreshFromControlPlane,
    clearError,
    refresh,
    getEditConfig,
  } = useVpn();
  const { theme } = useT();
  const [tab, setTab] = useState("connect");
  /** @type {[import('./vpnTypes').SavedConfig | null, (c: import('./vpnTypes').SavedConfig | null) => void]} */
  const [draft, setDraft] = useState(null);
  /** @type {[null | { controlPlaneHost: string, vpnHost: string, displayName: string, serverName: string }, (v: null | object) => void]} */
  const [pendingImport, setPendingImport] = useState(null);
  const [importBusy, setImportBusy] = useState(false);
  const [meshBusy, setMeshBusy] = useState(false);
  const [meshError, setMeshError] = useState("");
  /** В черновике настроек есть несохранённые правки (уход с вкладки без правок не ходит в бэкенд). */
  const [draftDirty, setDraftDirty] = useState(false);
  /**
   * Ошибка последнего сохранения — показываем в настройках вместо молчаливой «зависшей» навигации.
   * `at` меняется на каждой неудаче, чтобы баннер снова прокручивался в зону видимости.
   */
  const [saveError, setSaveError] = useState(/** @type {{ message: string, at: number } | null} */ (null));
  /** Отсекает устаревшие ответы `get_edit_config` после быстрого переключения вкладок. */
  const draftReqRef = useRef(0);
  /** Номер правки черновика: ответ сохранения не должен затереть более новый ввод. */
  const draftRevRef = useRef(0);

  useEffect(() => {
    let disposed = false;
    let unlisten = () => {};
    (async () => {
      try {
        const pending = await invoke("get_pending_import");
        if (pending && !disposed) setPendingImport(/** @type {typeof pendingImport} */ (pending));
      } catch (e) {
        console.error(e);
      }
      try {
        const un = await listen("control-plane-import-pending", (ev) => {
          setPendingImport(/** @type {typeof pendingImport} */ (ev.payload));
        });
        if (disposed) un();
        else unlisten = un;
      } catch (e) {
        console.error(e);
      }
    })();
    return () => {
      disposed = true;
      unlisten();
    };
  }, []);

  const loadEditDraft = useCallback(async () => {
    const req = ++draftReqRef.current;
    try {
      const c = await getEditConfig();
      if (req !== draftReqRef.current) return;
      draftRevRef.current += 1;
      setDraft(cloneCfg(c));
      setDraftDirty(false);
      setSaveError(null);
    } catch (e) {
      console.error(e);
    }
  }, [getEditConfig]);

  useEffect(() => {
    // Любая загрузка черновика для предыдущей вкладки становится неактуальной.
    draftReqRef.current += 1;
    if (tab === "connect") {
      setDraft(null);
      setDraftDirty(false);
      setSaveError(null);
    } else if (tab === "profiles" || tab === "settings") loadEditDraft();
  }, [tab, loadEditDraft]);

  useEffect(() => {
    let disposed = false;
    let unlisten = () => {};
    (async () => {
      try {
        const un = await listen("control-plane-import", () => {
          setPendingImport(null);
          setTab("profiles");
          loadEditDraft();
        });
        if (disposed) un();
        else unlisten = un;
      } catch (e) {
        console.error(e);
      }
    })();
    return () => {
      disposed = true;
      unlisten();
    };
  }, [loadEditDraft]);

  const confirmPendingImport = useCallback(async () => {
    setImportBusy(true);
    try {
      await invoke("confirm_pending_import_cmd");
      setPendingImport(null);
      setDraft(null);
      setTab("profiles");
      await refresh();
    } catch (e) {
      console.error(e);
    } finally {
      setImportBusy(false);
    }
  }, [refresh]);

  const cancelPendingImport = useCallback(async () => {
    try {
      await invoke("cancel_pending_import_cmd");
    } catch (e) {
      console.error(e);
    }
    setPendingImport(null);
  }, []);

  const setCfg = useCallback((updater) => {
    draftRevRef.current += 1;
    setDraft((d) => {
      if (!d) return null;
      return typeof updater === "function" ? updater(d) : updater;
    });
    setDraftDirty(true);
  }, []);

  /**
   * @returns {Promise<boolean>} `true` — сохранено или сохранять нечего.
   * Ошибку не бросаем: раньше отказ `save_config_cmd` (например, дробь в числовом поле) ронял
   * `goTab` до `setTab`, и из настроек нельзя было уйти ни вкладками, ни кнопкой «Сохранить».
   */
  const saveDraft = useCallback(async () => {
    if (!draft || !draftDirty) return true;
    const rev = draftRevRef.current;
    try {
      await saveCfg(draft);
      const full = await getEditConfig();
      // Пока шло сохранение, пользователь продолжил печатать — не затираем ввод
      // устаревшим снимком и просим сохранить ещё раз.
      if (draftRevRef.current !== rev) {
        setSaveError({ message: t("settings_changed_while_saving"), at: Date.now() });
        return false;
      }
      setDraft(cloneCfg(full));
      setDraftDirty(false);
      setSaveError(null);
      return true;
    } catch (e) {
      console.error(e);
      setSaveError({ message: String(e), at: Date.now() });
      return false;
    }
  }, [draft, draftDirty, saveCfg, getEditConfig]);

  const goTab = useCallback(
    async (/** @type {"connect" | "profiles" | "settings"} */ next) => {
      if (next === tab) return;
      // Не сохранилось — остаёмся: ошибка и «Отменить изменения» видны в настройках.
      if (tab === "settings" && !(await saveDraft())) return;
      setTab(next);
    },
    [tab, saveDraft]
  );

  const saveSettingsAndGoConnect = useCallback(async () => {
    if (await saveDraft()) setTab("connect");
  }, [saveDraft]);

  const sessionPending = snap?.phase === "connecting" || snap?.phase === "reconnecting";
  const transitionBusy = busy || snap?.phase === "disconnecting";
  const connectPhasePending = sessionPending || Boolean(busy && snap && !snap.connected);

  async function handleToggleConnect() {
    if (!snap || transitionBusy) return;
    try {
      if (snap.connected || sessionPending) await disconnect();
      else await connect();
    } catch (e) {
      console.error(e);
      await refresh();
    }
  }

  async function handleToggleMesh(enabled) {
    if (transitionBusy || meshBusy || sessionPending) return;
    setMeshBusy(true);
    setMeshError("");
    try {
      const cfg = await getEditConfig();
      const profile = cfg.profiles.find((p) => p.id === cfg.active_profile_id);
      if (!profile) throw new Error("Profile not found");
      if (snap.connected) await disconnect();
      profile.yb_mesh_enabled = enabled;
      await saveCfg(cfg);
      if (snap.connected) {
        await connect();
      }
    } catch (e) {
      setMeshError(String(e));
    } finally {
      setMeshBusy(false);
    }
  }

  if (!snap) {
    return (
      <div style={{ padding: 24, fontFamily: "IBM Plex Mono", color: "#6a7c78" }}>…</div>
    );
  }

  const boringAvailable = Boolean(snap.capabilities?.boringTlsAvailable);
  const cfg = draft;
  const cpHost = pendingImport?.controlPlaneHost ?? "";
  const vpnHost = pendingImport?.vpnHost ?? "";

  let main = null;
  if (tab === "profiles" && cfg) {
    main = (
      <ProfilesScreen
        cfg={cfg}
        saveError={saveError}
        onSave={async (c) => {
          setDraft(c);
          let failure = null;
          try {
            await saveCfg(c);
          } catch (e) {
            console.error(e);
            failure = e;
          }
          // И после ошибки: экран должен показывать то, что реально сохранено.
          await loadEditDraft();
          setSaveError(failure ? { message: String(failure), at: Date.now() } : null);
        }}
      />
    );
  } else if (tab === "settings" && cfg) {
    main = (
      <SettingsScreen
        cfg={cfg}
        setCfg={setCfg}
        boringAvailable={boringAvailable}
        onPersist={saveDraft}
        onSave={saveSettingsAndGoConnect}
        saveError={saveError}
        onDiscardChanges={loadEditDraft}
        lastError={snap.error}
        onClearError={clearError}
        onApplyInvite={async () => {
          try {
            await applyInvite();
          } catch (e) {
            // Текст ошибки приходит в `snap.error` через vpn-state.
            console.error(e);
          }
          await loadEditDraft();
        }}
        onRefreshFromControlPlane={async () => {
          try {
            await refreshFromControlPlane();
          } catch (e) {
            console.error(e);
          }
          await loadEditDraft();
        }}
      />
    );
  } else if (tab === "profiles" || tab === "settings") {
    main = (
      <div style={{ padding: 24, fontFamily: "IBM Plex Mono", color: "#6a7c78" }}>…</div>
    );
  } else {
    main = (
      <ConnectScreen
        snap={snap}
        connectPending={connectPhasePending}
        busy={transitionBusy || meshBusy}
        cancelable={sessionPending}
        reconnecting={snap.phase === "reconnecting"}
        onSettings={() => goTab("settings")}
        onToggleConnect={handleToggleConnect}
        onToggleMesh={handleToggleMesh}
        meshBusy={meshBusy}
        meshError={meshError}
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
      {pendingImport && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="import-confirm-title"
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 100,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 24,
            background: "rgba(0,0,0,0.72)",
          }}
        >
          <div
            style={{
              width: "100%",
              maxWidth: 420,
              padding: "24px 22px",
              borderRadius: 8,
              border: `1px solid ${theme.line}`,
              background: theme.panel,
              boxShadow: "0 24px 64px rgba(0,0,0,0.55)",
            }}
          >
            <h2
              id="import-confirm-title"
              style={{
                margin: "0 0 14px",
                fontFamily: MONO,
                fontSize: 13,
                fontWeight: 600,
                letterSpacing: 1.2,
                textTransform: "uppercase",
                color: theme.text,
              }}
            >
              {t("import_confirm_title")}
            </h2>
            <p
              style={{
                margin: "0 0 22px",
                fontFamily: SANS,
                fontSize: 14,
                lineHeight: 1.55,
                color: theme.textDim,
              }}
            >
              {t("import_confirm_body", { cp_host: cpHost, vpn_host: vpnHost })}
            </p>
            <div style={{ display: "flex", gap: 10, justifyContent: "flex-end" }}>
              <Btn kind="ghost" onClick={cancelPendingImport} disabled={importBusy}>
                {t("btn_cancel_import")}
              </Btn>
              <Btn kind="primary" onClick={confirmPendingImport} disabled={importBusy}>
                {t("btn_confirm_import")}
              </Btn>
            </div>
          </div>
        </div>
      )}
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
