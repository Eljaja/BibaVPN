import { useCallback, useEffect, useState } from "react";
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

  const load = useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      /** @type {{ presets: BypassPreset[], configured: boolean, error?: string | null }} */
      const res = await invoke("get_bypass_presets_cmd", { refresh });
      setPresets(Array.isArray(res.presets) ? res.presets : []);
      setConfigured(Boolean(res.configured));
      setError(res.error || null);
    } catch (e) {
      setPresets([]);
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(false);
  }, [load]);

  return {
    presets,
    loading,
    configured,
    error,
    refresh: () => load(true),
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
