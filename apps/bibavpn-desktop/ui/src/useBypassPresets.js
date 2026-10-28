import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

/**
 * @typedef {Object} BypassPreset
 * @property {string} id
 * @property {string} label
 * @property {string[] | undefined} [domains]
 * @property {string[] | undefined} [androidPackages]
 * @property {string | undefined} [source]
 */

/**
 * @typedef {Object} BypassPresetsState
 * @property {BypassPreset[]} presets
 * @property {boolean} loading
 * @property {boolean} configured
 * @property {string | null} error
 * @property {() => Promise<void>} refresh
 */

/** @returns {BypassPresetsState} */
export function useBypassPresets() {
  const [presets, setPresets] = useState(/** @type {BypassPreset[]} */ ([]));
  const [loading, setLoading] = useState(true);
  const [configured, setConfigured] = useState(false);
  const [error, setError] = useState(/** @type {string | null} */ (null));
  const mountedRef = useRef(true);
  const requestRef = useRef(0);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async (refresh = false) => {
    const request = ++requestRef.current;
    if (mountedRef.current) setLoading(true);
    try {
      /** @type {{ presets: BypassPreset[], configured: boolean, error?: string | null }} */
      const res = await invoke("get_bypass_presets_cmd", { refresh });
      // Более новый запрос (или размонтирование) — этот ответ уже неактуален.
      if (!mountedRef.current || request !== requestRef.current) return;
      setPresets(Array.isArray(res.presets) ? res.presets : []);
      setConfigured(Boolean(res.configured));
      setError(res.error || null);
    } catch (e) {
      if (!mountedRef.current || request !== requestRef.current) return;
      setPresets([]);
      setError(String(e));
    } finally {
      if (mountedRef.current && request === requestRef.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(false);
  }, [load]);

  const refresh = useCallback(() => load(true), [load]);

  return {
    presets,
    loading,
    configured,
    error,
    refresh,
  };
}

/**
 * @param {BypassPreset[]} presets
 * @param {string[]} presetIds
 */
export function packagesFromApiPresets(presets, presetIds) {
  const byId = new Map(presets.map((p) => [p.id, p]));
  const s = new Set();
  for (const id of presetIds || []) {
    const p = byId.get(id);
    if (!p?.androidPackages) continue;
    for (const pkg of p.androidPackages) {
      const k = String(pkg || "").trim();
      if (k) s.add(k);
    }
  }
  return [...s];
}

/** @param {BypassPreset[]} presets @param {string[]} presetIds @param {string[]} manualPkgs */
export function mergedAndroidSplitPackagesFromApi(presets, presetIds, manualPkgs) {
  const s = new Set(packagesFromApiPresets(presets, presetIds));
  for (const m of manualPkgs || []) {
    const k = String(m || "").trim();
    if (k) s.add(k);
  }
  return [...s].sort();
}

/** @param {BypassPreset[]} presets @param {string} id */
export function presetLabel(presets, id) {
  const p = presets.find((x) => x.id === id);
  return p?.label || id;
}
