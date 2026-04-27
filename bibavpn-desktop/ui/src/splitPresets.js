/** Preset ids must match `split_tunnel.rs` SPLIT_TUNNEL_PRESETS. */

export const SPLIT_TUNNEL_GROUPS = [
  {
    groupKey: "split_group_government",
    ids: ["gosuslugi"],
  },
  {
    groupKey: "split_group_social",
    ids: ["max", "vk"],
  },
  {
    groupKey: "split_group_banks",
    ids: ["tinkoff", "sber", "yandex_bank", "banki", "bog", "vtb", "alfa"],
  },
  {
    groupKey: "split_group_shops",
    ids: ["ozon", "yandex_market", "steam"],
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
    ],
  },
];

export function allSplitPresetIds() {
  const s = new Set();
  for (const g of SPLIT_TUNNEL_GROUPS) for (const id of g.ids) s.add(id);
  return [...s];
}
