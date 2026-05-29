import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { setLanguageFromCfg } from "./i18n.js";

/**
 * @typedef {import('./vpnTypes').StateSnapshot} StateSnapshot
 */

export function useVpn() {
  /** @type {[StateSnapshot | null, (s: StateSnapshot | null) => void]} */
  const [snap, setSnap] = useState(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const s = await invoke("get_state");
      setSnap(/** @type {StateSnapshot} */ (s));
      const st = /** @type {StateSnapshot} */ (s);
      if (st?.cfg) setLanguageFromCfg(st.cfg);
      return /** @type {StateSnapshot} */ (s);
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
      unlisten = await listen("vpn-state", (ev) => {
        const p = /** @type {StateSnapshot} */ (ev.payload);
        if (!alive) return;
        setSnap(p);
        if (p?.cfg) setLanguageFromCfg(p.cfg);
      });
    })();
    return () => {
      alive = false;
      unlisten();
    };
  }, [refresh]);

  /** @param {import('./vpnTypes').SavedConfig} cfg */
  const saveCfg = useCallback(async (cfg) => {
    const s = await invoke("save_config_cmd", { cfg });
    setSnap(/** @type {StateSnapshot} */ (s));
    return /** @type {StateSnapshot} */ (s);
  }, []);

  const connect = useCallback(async () => {
    setBusy(true);
    try {
      const s = await invoke("connect_cmd");
      setSnap(/** @type {StateSnapshot} */ (s));
      return /** @type {StateSnapshot} */ (s);
    } finally {
      setBusy(false);
    }
  }, []);

  const disconnect = useCallback(async () => {
    setBusy(true);
    try {
      const s = await invoke("disconnect_cmd");
      setSnap(/** @type {StateSnapshot} */ (s));
      return /** @type {StateSnapshot} */ (s);
    } finally {
      setBusy(false);
    }
  }, []);

  const applyInvite = useCallback(async () => {
    const s = await invoke("apply_invite_cmd");
    setSnap(/** @type {StateSnapshot} */ (s));
    return /** @type {StateSnapshot} */ (s);
  }, []);

  const refreshFromControlPlane = useCallback(async () => {
    const s = await invoke("open_control_plane_refresh_cmd");
    setSnap(/** @type {StateSnapshot} */ (s));
    return /** @type {StateSnapshot} */ (s);
  }, []);

  const clearError = useCallback(async () => {
    const s = await invoke("clear_error_cmd");
    setSnap(/** @type {StateSnapshot} */ (s));
  }, []);

  return {
    snap,
    busy,
    refresh,
    saveCfg,
    connect,
    disconnect,
    applyInvite,
    refreshFromControlPlane,
    clearError,
  };
}
