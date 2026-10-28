import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { setLanguageFromCfg } from "./i18n.js";

/**
 * @typedef {import('./vpnTypes').StateSnapshot} StateSnapshot
 * @typedef {import('./vpnTypes').SavedConfig} SavedConfig
 */

export function useVpn() {
  /** @type {[StateSnapshot | null, (s: StateSnapshot | null) => void]} */
  const [snap, setSnap] = useState(null);
  const [busy, setBusy] = useState(false);
  const mountedRef = useRef(true);
  /** Каждая мутация увеличивает счётчик: старый `get_state` не должен затереть её результат. */
  const mutationSeqRef = useRef(0);
  const pendingOpsRef = useRef(0);
  /** Сколько мутаций сейчас в полёте и сколько уже завершилось (для отсева устаревших refresh). */
  const mutationInFlightRef = useRef(0);
  const lastMutationDoneRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const commitSnapshot = useCallback((/** @type {StateSnapshot} */ s) => {
    if (!mountedRef.current) return false;
    setSnap(s);
    if (s?.cfg) setLanguageFromCfg(s.cfg);
    return true;
  }, []);

  const refresh = useCallback(async () => {
    // Снимок, запрошенный во время connect/save, может прийти уже после неё
    // и откатить UI назад. Если мутация была в полёте или завершилась за время
    // запроса — не применяем устаревший снимок.
    const doneAtStart = lastMutationDoneRef.current;
    try {
      const s = await invoke("get_state");
      const stale =
        mutationInFlightRef.current > 0 ||
        lastMutationDoneRef.current !== doneAtStart;
      if (mountedRef.current && !stale) {
        commitSnapshot(/** @type {StateSnapshot} */ (s));
      }
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
      await refresh();
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
    })();
    return () => {
      alive = false;
      unlisten();
    };
  }, [refresh, commitSnapshot]);

  const getEditConfig = useCallback(async () => {
    const c = await invoke("get_edit_config");
    return /** @type {SavedConfig} */ (c);
  }, []);

  /** Мутация с блокировкой UI (connect/disconnect): последний запрос побеждает. */
  const runBusy = useCallback(
    async (/** @type {string} */ cmd) => {
      const seq = ++mutationSeqRef.current;
      pendingOpsRef.current += 1;
      mutationInFlightRef.current += 1;
      if (mountedRef.current) setBusy(true);
      try {
        const s = await invoke(cmd);
        if (mountedRef.current && seq === mutationSeqRef.current) {
          commitSnapshot(/** @type {StateSnapshot} */ (s));
        }
        return /** @type {StateSnapshot} */ (s);
      } finally {
        mutationInFlightRef.current = Math.max(0, mutationInFlightRef.current - 1);
        lastMutationDoneRef.current += 1;
        pendingOpsRef.current = Math.max(0, pendingOpsRef.current - 1);
        if (mountedRef.current && pendingOpsRef.current === 0) setBusy(false);
      }
    },
    [commitSnapshot],
  );

  /** Мутация без `busy` (сохранение/инвайт/ошибка); тоже не даёт старому refresh её затереть. */
  const runSilent = useCallback(
    async (/** @type {string} */ cmd, /** @type {Record<string, unknown> | undefined} */ args) => {
      const seq = ++mutationSeqRef.current;
      mutationInFlightRef.current += 1;
      try {
        const s = await invoke(cmd, args);
        if (mountedRef.current && seq === mutationSeqRef.current) {
          commitSnapshot(/** @type {StateSnapshot} */ (s));
        }
        return /** @type {StateSnapshot} */ (s);
      } finally {
        mutationInFlightRef.current = Math.max(0, mutationInFlightRef.current - 1);
        lastMutationDoneRef.current += 1;
      }
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
    getTunnelStatus,
    getEditConfig,
    saveCfg,
    connect,
    disconnect,
    applyInvite,
    refreshFromControlPlane,
    clearError,
  };
}
