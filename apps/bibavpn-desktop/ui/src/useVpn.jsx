import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { setLanguageFromCfg } from "./i18n.js";
import { startVisiblePolling } from "./visiblePolling.js";
import { acceptSnapshot, sessionStart, tunnelStatusChanged } from "./vpnState.js";

/**
 * @typedef {import('./vpnTypes').StateSnapshot} StateSnapshot
 * @typedef {import('./vpnTypes').SavedConfig} SavedConfig
 */

export function useVpn() {
  /** @type {[StateSnapshot | null, (s: StateSnapshot | null) => void]} */
  const [snap, setSnap] = useState(null);
  const [busy, setBusy] = useState(false);
  const snapshotRef = useRef(null);
  const mountedRef = useRef(true);
  /** Отсекаем ответы более ранних команд. */
  const mutationSeqRef = useRef(0);
  const pendingOpsRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const commitSnapshot = useCallback((/** @type {StateSnapshot} */ s) => {
    if (!mountedRef.current) return false;
    if (acceptSnapshot(snapshotRef.current, s) !== s) return false;
    const next = { ...s, sessionStartedAt: sessionStart(snapshotRef.current, s, Date.now()) };
    snapshotRef.current = next;
    setSnap(next);
    if (s?.cfg) setLanguageFromCfg(s.cfg);
    return true;
  }, []);

  const refresh = useCallback(async () => {
    try {
      const s = await invoke("get_state");
      commitSnapshot(/** @type {StateSnapshot} */ (s));
      return /** @type {StateSnapshot} */ (s);
    } catch (e) {
      console.error(e);
      return null;
    }
  }, [commitSnapshot]);

  const getTunnelStatus = useCallback(async () => {
    try {
      return await invoke("get_tunnel_status_cmd");
    } catch (e) {
      console.error(e);
      return null;
    }
  }, []);

  useEffect(() => {
    let alive = true;
    let unlisten = () => {};
    (async () => {
      try {
        const un = await listen("vpn-state", (ev) => {
          const p = /** @type {StateSnapshot} */ (ev.payload);
          if (!alive) return;
          commitSnapshot(p);
        });
        // Эффект мог размонтироваться, пока ждали `listen` — не оставляем лишний слушатель.
        if (alive) unlisten = un;
        else un();
      } catch (e) {
        console.error(e);
      }
      if (alive) await refresh();
    })();
    return () => {
      alive = false;
      unlisten();
    };
  }, [refresh, commitSnapshot]);

  // A single observer owns tunnel reconciliation across all screens. It pauses in
  // the background and rechecks immediately on return to the foreground.
  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") refresh();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    const stop = startVisiblePolling({
      intervalMs: 2000,
      task: async () => {
        const status = await getTunnelStatus();
        if (tunnelStatusChanged(snapshotRef.current, status)) await refresh();
      },
    });
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      stop();
    };
  }, [getTunnelStatus, refresh]);

  const getEditConfig = useCallback(async () => {
    const c = await invoke("get_edit_config");
    return /** @type {SavedConfig} */ (c);
  }, []);

  /** Мутация с блокировкой UI (connect/disconnect): последний запрос побеждает. */
  const runBusy = useCallback(
    async (/** @type {string} */ cmd) => {
      const seq = ++mutationSeqRef.current;
      pendingOpsRef.current += 1;
      if (mountedRef.current) setBusy(true);
      try {
        const s = await invoke(cmd);
        if (mountedRef.current && seq === mutationSeqRef.current) {
          commitSnapshot(/** @type {StateSnapshot} */ (s));
        }
        return /** @type {StateSnapshot} */ (s);
      } finally {
        pendingOpsRef.current = Math.max(0, pendingOpsRef.current - 1);
        if (mountedRef.current && pendingOpsRef.current === 0) setBusy(false);
      }
    },
    [commitSnapshot],
  );

  /** Мутация без `busy` (сохранение/инвайт/ошибка). */
  const runSilent = useCallback(
    async (/** @type {string} */ cmd, /** @type {Record<string, unknown> | undefined} */ args) => {
      const seq = ++mutationSeqRef.current;
      const s = await invoke(cmd, args);
      if (mountedRef.current && seq === mutationSeqRef.current) {
        commitSnapshot(/** @type {StateSnapshot} */ (s));
      }
      return /** @type {StateSnapshot} */ (s);
    },
    [commitSnapshot],
  );

  /** @param {SavedConfig} cfg */
  const saveCfg = useCallback(
    async (cfg) => runSilent("save_config_cmd", { cfg }),
    [runSilent],
  );

  const connect = useCallback(() => runBusy("connect_cmd"), [runBusy]);

  const disconnect = useCallback(() => runBusy("disconnect_cmd"), [runBusy]);

  const applyInvite = useCallback(() => runSilent("apply_invite_cmd"), [runSilent]);

  const refreshFromControlPlane = useCallback(
    () => runSilent("open_control_plane_refresh_cmd"),
    [runSilent],
  );

  const clearError = useCallback(async () => {
    try {
      await runSilent("clear_error_cmd");
    } catch (e) {
      console.error(e);
    }
  }, [runSilent]);

  return {
    snap,
    busy,
    refresh,
    getEditConfig,
    saveCfg,
    connect,
    disconnect,
    applyInvite,
    refreshFromControlPlane,
    clearError,
  };
}
