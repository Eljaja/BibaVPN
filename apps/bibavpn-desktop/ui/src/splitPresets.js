/** UI grouping for split-tunnel preset ids (labels come from API). */

export const SPLIT_TUNNEL_GROUP_IDS = [
  {
    groupKey: "split_group_government",
    ids: ["gosuslugi", "gov"],
  },
  {
    groupKey: "split_group_social",
    ids: ["max", "vk", "media", "entertainment"],
  },
  {
    groupKey: "split_group_banks",
    ids: [
      "banks",
      "tinkoff",
      "sber",
      "yandex_bank",
      "banki",
      "bog",
      "vtb",
      "alfa",
    ],
  },
  {
    groupKey: "split_group_shops",
    ids: ["ecommerce", "retail", "ozon", "yandex_market", "steam", "games"],
  },
  {
    groupKey: "split_group_delivery",
    ids: [
      "yandex_taxi",
      "yandex_vezet",
      "deliveryclub",
      "yandex_eda",
      "yandex_lavka",
      "samokat",
      "travel",
    ],
  },
  {
    groupKey: "split_group_other",
    ids: ["yandex", "medicine", "ru_all"],
  },
];

/**
 * @param {import('./useBypassPresets').BypassPreset[]} presets
 * @returns {{ groupKey: string, presets: import('./useBypassPresets').BypassPreset[] }[]}
 */
export function groupBypassPresets(presets) {
  const byId = new Map(presets.map((p) => [p.id, p]));
  const used = new Set();
  const groups = [];
  /** @type {{ groupKey: string, presets: import('./useBypassPresets').BypassPreset[] } | null} */
  let otherGroup = null;

  for (const g of SPLIT_TUNNEL_GROUP_IDS) {
    const items = [];
    for (const id of g.ids) {
      const p = byId.get(id);
      if (p) {
        items.push(p);
        used.add(id);
      }
    }
    if (items.length === 0) continue;
    const entry = { groupKey: g.groupKey, presets: items };
    if (g.groupKey === "split_group_other") {
      otherGroup = entry;
    }
    groups.push(entry);
  }

  const rest = presets.filter((p) => !used.has(p.id));
  if (rest.length > 0) {
    if (otherGroup) {
      otherGroup.presets.push(...rest);
    } else {
      groups.push({ groupKey: "split_group_other", presets: rest });
    }
  }

  return groups;
}

/** @param {import('./useBypassPresets').BypassPreset[]} presets */
export function allSplitPresetIds(presets) {
  return presets.map((p) => p.id);
}
