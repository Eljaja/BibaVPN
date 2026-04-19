//! Пресеты split-tunnel: домены в обход системного HTTP-прокси (Windows ProxyOverride / macOS bypass).

use crate::config::SavedConfig;

#[derive(Debug, Clone, Copy)]
pub struct SplitTunnelPreset {
    pub id: &'static str,
    pub domains: &'static [&'static str],
}

/// Соответствуют логике Android [SplitTunnelCatalog] + отдельный пресет Steam (серверы клиента/магазина).
pub static SPLIT_TUNNEL_PRESETS: &[SplitTunnelPreset] = &[
    SplitTunnelPreset {
        id: "gosuslugi",
        domains: &["gosuslugi.ru", "*.gosuslugi.ru"],
    },
    SplitTunnelPreset {
        id: "max",
        domains: &["one.me", "*.one.me", "max.ru", "*.max.ru"],
    },
    SplitTunnelPreset {
        id: "vk",
        domains: &[
            "vk.com",
            "*.vk.com",
            "vk.ru",
            "*.vk.ru",
            "userapi.com",
            "*.userapi.com",
        ],
    },
    SplitTunnelPreset {
        id: "tinkoff",
        domains: &["tinkoff.ru", "*.tinkoff.ru"],
    },
    SplitTunnelPreset {
        id: "sber",
        domains: &["sberbank.ru", "*.sberbank.ru", "online.sberbank.ru"],
    },
    SplitTunnelPreset {
        id: "yandex_bank",
        domains: &["bank.yandex.ru", "*.bank.yandex.ru"],
    },
    SplitTunnelPreset {
        id: "banki",
        domains: &["banki.ru", "*.banki.ru"],
    },
    SplitTunnelPreset {
        id: "bog",
        domains: &["bog.ge", "*.bog.ge", "mobilebanking.bog.ge"],
    },
    SplitTunnelPreset {
        id: "vtb",
        domains: &["vtb.ru", "*.vtb.ru", "online.vtb.ru"],
    },
    SplitTunnelPreset {
        id: "alfa",
        domains: &["alfabank.ru", "*.alfabank.ru", "online.alfabank.ru"],
    },
    SplitTunnelPreset {
        id: "ozon",
        domains: &["ozon.ru", "*.ozon.ru", "api.ozon.ru"],
    },
    SplitTunnelPreset {
        id: "yandex_market",
        domains: &["market.yandex.ru", "*.market.yandex.ru", "beru.ru"],
    },
    SplitTunnelPreset {
        id: "steam",
        domains: &[
            "steampowered.com",
            "*.steampowered.com",
            "steamcommunity.com",
            "*.steamcommunity.com",
            "steamstatic.com",
            "*.steamstatic.com",
            "steamusercontent.com",
            "*.steamusercontent.com",
            "steam-chat.com",
            "*.steam-chat.com",
            "steamgames.com",
            "*.steamgames.com",
            "steamserver.net",
            "*.steamserver.net",
            "steamcontent.com",
            "*.steamcontent.com",
            "valvesoftware.com",
            "*.valvesoftware.com",
            "steam-api.com",
            "*.steam-api.com",
        ],
    },
    SplitTunnelPreset {
        id: "yandex_taxi",
        domains: &["taxi.yandex.ru", "*.taxi.yandex.ru", "yango.yandex.ru"],
    },
    SplitTunnelPreset {
        id: "yandex_vezet",
        domains: &["vezet.yandex.ru", "*.vezet.yandex.ru"],
    },
    SplitTunnelPreset {
        id: "deliveryclub",
        domains: &["delivery-club.ru", "*.delivery-club.ru", "dc.ru"],
    },
    SplitTunnelPreset {
        id: "yandex_eda",
        domains: &["eda.yandex.ru", "*.eda.yandex.ru"],
    },
    SplitTunnelPreset {
        id: "yandex_lavka",
        domains: &["lavka.yandex.ru", "*.lavka.yandex.ru"],
    },
    SplitTunnelPreset {
        id: "samokat",
        domains: &["samokat.ru", "*.samokat.ru"],
    },
];

/// Домены для WinInet ProxyOverride / macOS bypass (без обязательных loopback — их добавляет платформа).
pub fn bypass_domains_for_cfg(cfg: &SavedConfig) -> Vec<String> {
    if !cfg.split_tunnel_enabled {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for id in &cfg.split_tunnel_preset_ids {
        let id = id.trim();
        if id.is_empty() {
            continue;
        }
        if let Some(p) = SPLIT_TUNNEL_PRESETS.iter().find(|p| p.id == id) {
            for d in p.domains {
                if !out.iter().any(|x| x.eq_ignore_ascii_case(d)) {
                    out.push((*d).to_string());
                }
            }
        }
    }
    out
}
