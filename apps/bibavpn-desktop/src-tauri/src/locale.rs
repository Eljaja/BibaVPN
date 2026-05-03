//! Локаль трея и подсказок (ru / en / auto по системе).

use crate::config::SavedConfig;

pub fn resolved_tray_lang(cfg: &SavedConfig) -> &'static str {
    let s = cfg.ui_locale.trim();
    if s.eq_ignore_ascii_case("en") {
        return "en";
    }
    if s.eq_ignore_ascii_case("ru") {
        return "ru";
    }
    if sys_locale::get_locale()
        .map(|loc| loc.to_lowercase().starts_with("en"))
        .unwrap_or(false)
    {
        "en"
    } else {
        "ru"
    }
}

pub struct TrayStrings {
    pub show: &'static str,
    pub on: &'static str,
    pub off: &'static str,
    pub logs: &'static str,
    pub quit: &'static str,
    pub tip_connected: &'static str,
    pub tip_disconnected: &'static str,
}

pub fn tray_strings(lang: &str) -> TrayStrings {
    if lang == "en" {
        TrayStrings {
            show: "Open window",
            on: "Connect VPN",
            off: "Disconnect VPN",
            logs: "Logs folder…",
            quit: "Quit",
            tip_connected: "BibaVPN — connected",
            tip_disconnected: "BibaVPN — disconnected",
        }
    } else {
        TrayStrings {
            show: "Открыть окно",
            on: "Включить VPN",
            off: "Отключить VPN",
            logs: "Папка с логами…",
            quit: "Выход",
            tip_connected: "BibaVPN — подключено",
            tip_disconnected: "BibaVPN — отключено",
        }
    }
}
