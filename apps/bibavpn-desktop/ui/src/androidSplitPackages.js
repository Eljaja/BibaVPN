/** Пакеты приложений под пресеты — как в android/.../SplitTunnelCatalog.kt */

export const ANDROID_PRESET_PACKAGES = {
  gosuslugi: ["ru.rostel"],
  max: ["ru.oneme.app"],
  vk: ["com.vkontakte.android"],
  tinkoff: ["com.idamob.tinkoff.android"],
  sber: ["ru.sberbankmobile"],
  yandex_bank: ["com.yandex.bank"],
  banki: ["ru.banki.banki"],
  bog: ["ge.bog.mobilebank"],
  vtb: ["ru.vtb24.mobilebanking.android"],
  alfa: ["ru.alfabank.mobile.android"],
  ozon: ["ru.ozon.app.android"],
  yandex_market: ["ru.beru.android"],
  steam: ["com.valvesoftware.android.steam.community"],
  yandex_taxi: ["ru.yandex.taxi"],
  yandex_vezet: ["ru.yandex.vezet"],
  deliveryclub: ["com.deliveryclub"],
  yandex_eda: ["ru.yandex.eda"],
  yandex_lavka: ["com.yandex.lavka"],
  samokat: ["ru.sbcs.store"],
};

/** @param {string[]} presetIds */
export function packagesFromPresetIds(presetIds) {
  const s = new Set();
  for (const id of presetIds || []) {
    const arr = ANDROID_PRESET_PACKAGES[id];
    if (arr) for (const p of arr) s.add(p);
  }
  return [...s];
}

/** @param {string[]} presetIds @param {string[]} manualPkgs */
export function mergedAndroidSplitPackages(presetIds, manualPkgs) {
  const s = new Set(packagesFromPresetIds(presetIds));
  for (const m of manualPkgs || []) {
    const k = String(m || "").trim();
    if (k) s.add(k);
  }
  return [...s].sort();
}

/**
 * Разбор старых конфигов: только merged android_split_tunnel_packages без manual.
 * @param {import('./vpnTypes').TunnelProfile | null} p
 * @returns {Partial<import('./vpnTypes').TunnelProfile> | null}
 */
export function migrateAndroidSplitFields(p) {
  if (!p) return null;
  const manualExisting = p.android_manual_split_packages;
  if (Array.isArray(manualExisting) && manualExisting.length > 0) return null;

  const pkgs = p.android_split_tunnel_packages || [];
  if (pkgs.length === 0) return null;

  const presetIds = p.split_tunnel_preset_ids || [];
  const presetPkgs = packagesFromPresetIds(presetIds);
  const presetSet = new Set(presetPkgs);

  if (presetIds.length === 0) {
    return {
      android_manual_split_packages: [...pkgs],
      android_split_tunnel_packages: mergedAndroidSplitPackages([], [...pkgs]),
    };
  }

  const inferredManual = pkgs.filter((x) => !presetSet.has(x));
  const merged = mergedAndroidSplitPackages(presetIds, inferredManual);
  const same =
    inferredManual.length === 0 &&
    [...merged].sort().join("\n") === [...pkgs].sort().join("\n");
  if (same) return null;

  return {
    android_manual_split_packages: inferredManual,
    android_split_tunnel_packages: merged,
  };
}
