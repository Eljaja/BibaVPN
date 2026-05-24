/**
 * Android split-tunnel package helpers (preset packages resolved from API via useBypassPresets).
 */

import {
  mergedAndroidSplitPackagesFromApi,
  packagesFromApiPresets,
} from "./useBypassPresets.js";

/** @deprecated use packagesFromApiPresets with API presets */
export const ANDROID_PRESET_PACKAGES = {};

/** @param {import('./useBypassPresets').BypassPreset[]} presets @param {string[]} presetIds */
export function packagesFromPresetIds(presets, presetIds) {
  return packagesFromApiPresets(presets, presetIds);
}

/** @param {import('./useBypassPresets').BypassPreset[]} presets @param {string[]} presetIds @param {string[]} manualPkgs */
export function mergedAndroidSplitPackages(presets, presetIds, manualPkgs) {
  return mergedAndroidSplitPackagesFromApi(presets, presetIds, manualPkgs);
}

/**
 * @param {import('./vpnTypes').TunnelProfile | null} p
 * @param {import('./useBypassPresets').BypassPreset[]} presets
 * @returns {Partial<import('./vpnTypes').TunnelProfile> | null}
 */
export function migrateAndroidSplitFields(p, presets) {
  if (!p) return null;
  const manualExisting = p.android_manual_split_packages;
  if (Array.isArray(manualExisting) && manualExisting.length > 0) return null;

  const pkgs = p.android_split_tunnel_packages || [];
  if (pkgs.length === 0) return null;

  const presetIds = p.split_tunnel_preset_ids || [];
  const presetPkgs = packagesFromPresetIds(presets, presetIds);
  const presetSet = new Set(presetPkgs);

  if (presetIds.length === 0) {
    return {
      android_manual_split_packages: [...pkgs],
      android_split_tunnel_packages: mergedAndroidSplitPackages(presets, [], [...pkgs]),
    };
  }

  const inferredManual = pkgs.filter((x) => !presetSet.has(x));
  const merged = mergedAndroidSplitPackages(presets, presetIds, inferredManual);
  const same =
    inferredManual.length === 0 &&
    [...merged].sort().join("\n") === [...pkgs].sort().join("\n");
  if (same) return null;

  return {
    android_manual_split_packages: inferredManual,
    android_split_tunnel_packages: merged,
  };
}
