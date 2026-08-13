//! Сохранённая конфигурация (multi-profile) и JSON для `local_client`.
// Поля профиля под Android не читаются на десктопе; rustc 1.94 иногда падает (ICE)
// при выводе множественных dead_code-предупреждений для этого модуля.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bibavpn::local_client::DEFAULT_CLIENT_MAX_WS_BINARY;
use bibavpn::invite_uri::InviteV1;
use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 2;

/// Secret profile fields omitted from poll snapshots (`get_state` / `vpn-state`).
const PROFILE_SECRET_KEYS: &[&str] = &[
    "token",
    "psk",
    "from_invite",
    "invite_passphrase",
    "pin_cert_pem",
];

/// Публичный профиль для poll snapshot — без секретов, с флагами наличия.
#[derive(Serialize, Clone)]
pub struct PublicTunnelProfile {
    pub id: String,
    pub name: String,
    pub server: String,
    pub sni: String,
    pub insecure: bool,
    pub max_pad: u8,
    pub decoy_max: u8,
    pub max_ws_binary: usize,
    pub tls_profile: String,
    pub junk_frames: u32,
    pub early_ws_frames: u8,
    pub ws_ping_secs: u64,
    pub ws_headers: String,
    pub use_tcp_mux: bool,
    pub ws_path: String,
    pub pad_mode: String,
    pub ws_ping_jitter_percent: u8,
    pub ws_binary_send_jitter_ms: u8,
    pub udp_max_pad: String,
    pub udp_max_ws_binary: String,
    pub udp_mux_reply_timeout_secs: String,
    pub dummy_interval_secs: u64,
    pub decoy_gets: bool,
    pub decoy_gets_interval_secs: u64,
    pub decoy_gets_paths: String,
    pub split_tunnel_enabled: bool,
    pub split_tunnel_preset_ids: Vec<String>,
    pub proto: u8,
    pub proto_domain: String,
    pub stealth_profile: String,
    pub decoy_mode: String,
    pub desync_mode: String,
    pub tcp_fooling: String,
    pub tls_fragment: bool,
    pub ws_parallel: u8,
    pub idle_decoy_secs: u64,
    pub tls_stack: String,
    pub fingerprint: String,
    pub reality_target: String,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub ws_host: String,
    pub ws_origin: String,
    pub ws_user_agent: String,
    pub ws_accept_language: String,
    pub ws_jitter_min_ms: u8,
    pub ws_jitter_max_ms: u8,
    pub control_plane_instance_id: u64,
    pub control_plane_config_version: String,
    pub control_plane_base_url: String,
    pub android_socks_bind: String,
    pub android_split_tunnel_packages: Vec<String>,
    pub android_manual_split_packages: Vec<String>,
    pub android_vpn_routing_mode: String,
    pub android_screen_off_battery_saver: bool,
    pub has_token: bool,
    pub has_psk: bool,
    pub has_from_invite: bool,
    pub has_invite_passphrase: bool,
    pub has_invite: bool,
    pub has_pin_cert: bool,
}

/// Публичный корневой конфиг для poll snapshot.
#[derive(Serialize, Clone)]
pub struct PublicSavedConfig {
    pub version: u32,
    pub ui_locale: String,
    pub local_http_port: u16,
    pub local_socks_port: u16,
    pub active_profile_id: String,
    pub profiles: Vec<PublicTunnelProfile>,
}

pub fn to_public_profile(p: &TunnelProfile) -> PublicTunnelProfile {
    let has_token = !p.token.trim().is_empty();
    let has_psk = !p.psk.trim().is_empty();
    let has_from_invite = !p.from_invite.trim().is_empty();
    let has_invite_passphrase = !p.invite_passphrase.trim().is_empty();
    let has_invite = has_from_invite && has_invite_passphrase;
    let has_pin_cert = !p.pin_cert_pem.trim().is_empty();
    PublicTunnelProfile {
        id: p.id.clone(),
        name: p.name.clone(),
        server: p.server.clone(),
        sni: p.sni.clone(),
        insecure: p.insecure,
        max_pad: p.max_pad,
        decoy_max: p.decoy_max,
        max_ws_binary: p.max_ws_binary,
        tls_profile: p.tls_profile.clone(),
        junk_frames: p.junk_frames,
        early_ws_frames: p.early_ws_frames,
        ws_ping_secs: p.ws_ping_secs,
        ws_headers: p.ws_headers.clone(),
        use_tcp_mux: p.use_tcp_mux,
        ws_path: p.ws_path.clone(),
        pad_mode: p.pad_mode.clone(),
        ws_ping_jitter_percent: p.ws_ping_jitter_percent,
        ws_binary_send_jitter_ms: p.ws_binary_send_jitter_ms,
        udp_max_pad: p.udp_max_pad.clone(),
        udp_max_ws_binary: p.udp_max_ws_binary.clone(),
        udp_mux_reply_timeout_secs: p.udp_mux_reply_timeout_secs.clone(),
        dummy_interval_secs: p.dummy_interval_secs,
        decoy_gets: p.decoy_gets,
        decoy_gets_interval_secs: p.decoy_gets_interval_secs,
        decoy_gets_paths: p.decoy_gets_paths.clone(),
        split_tunnel_enabled: p.split_tunnel_enabled,
        split_tunnel_preset_ids: p.split_tunnel_preset_ids.clone(),
        proto: p.proto,
        proto_domain: p.proto_domain.clone(),
        stealth_profile: p.stealth_profile.clone(),
        decoy_mode: p.decoy_mode.clone(),
        desync_mode: p.desync_mode.clone(),
        tcp_fooling: p.tcp_fooling.clone(),
        tls_fragment: p.tls_fragment,
        ws_parallel: p.ws_parallel,
        idle_decoy_secs: p.idle_decoy_secs,
        tls_stack: p.tls_stack.clone(),
        fingerprint: p.fingerprint.clone(),
        reality_target: p.reality_target.clone(),
        reality_public_key: p.reality_public_key.clone(),
        reality_short_id: p.reality_short_id.clone(),
        ws_host: p.ws_host.clone(),
        ws_origin: p.ws_origin.clone(),
        ws_user_agent: p.ws_user_agent.clone(),
        ws_accept_language: p.ws_accept_language.clone(),
        ws_jitter_min_ms: p.ws_jitter_min_ms,
        ws_jitter_max_ms: p.ws_jitter_max_ms,
        control_plane_instance_id: p.control_plane_instance_id,
        control_plane_config_version: p.control_plane_config_version.clone(),
        control_plane_base_url: p.control_plane_base_url.clone(),
        android_socks_bind: p.android_socks_bind.clone(),
        android_split_tunnel_packages: p.android_split_tunnel_packages.clone(),
        android_manual_split_packages: p.android_manual_split_packages.clone(),
        android_vpn_routing_mode: p.android_vpn_routing_mode.clone(),
        android_screen_off_battery_saver: p.android_screen_off_battery_saver,
        has_token,
        has_psk,
        has_from_invite,
        has_invite_passphrase,
        has_invite,
        has_pin_cert,
    }
}

pub fn to_public_saved_config(cfg: &SavedConfig) -> PublicSavedConfig {
    PublicSavedConfig {
        version: cfg.version,
        ui_locale: cfg.ui_locale.clone(),
        local_http_port: cfg.local_http_port,
        local_socks_port: cfg.local_socks_port,
        active_profile_id: cfg.active_profile_id.clone(),
        profiles: cfg.profiles.iter().map(to_public_profile).collect(),
    }
}

fn merge_profile_secrets(
    stored: Option<&TunnelProfile>,
    incoming: &mut TunnelProfile,
    raw: &serde_json::Value,
) {
    let obj = raw.as_object();
    for key in PROFILE_SECRET_KEYS {
        let present = obj.map(|m| m.contains_key(*key)).unwrap_or(false);
        if present {
            continue;
        }
        if let Some(s) = stored {
            match *key {
                "token" => incoming.token = s.token.clone(),
                "psk" => incoming.psk = s.psk.clone(),
                "from_invite" => incoming.from_invite = s.from_invite.clone(),
                "invite_passphrase" => incoming.invite_passphrase = s.invite_passphrase.clone(),
                "pin_cert_pem" => incoming.pin_cert_pem = s.pin_cert_pem.clone(),
                _ => {}
            }
        }
    }
}

/// Merge UI `save_config_cmd` payload into stored config: omitted secret keys keep disk values.
pub fn merge_saved_config(stored: &SavedConfig, incoming: &serde_json::Value) -> Result<SavedConfig, String> {
    let incoming_cfg: SavedConfig =
        serde_json::from_value(incoming.clone()).map_err(|e| e.to_string())?;
    let profiles_raw = incoming
        .get("profiles")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut merged = incoming_cfg;
    for (i, profile) in merged.profiles.iter_mut().enumerate() {
        let raw = profiles_raw.get(i).cloned().unwrap_or(serde_json::Value::Null);
        let stored_profile = stored.profiles.iter().find(|p| p.id == profile.id);
        merge_profile_secrets(stored_profile, profile, &raw);
    }
    Ok(merged)
}

/// Один профиль туннеля (как один «сервер» в Android).
#[derive(Serialize, Deserialize, Clone)]
pub struct TunnelProfile {
    pub id: String,
    pub name: String,
    pub server: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub psk: String,
    pub sni: String,
    pub insecure: bool,
    #[serde(default = "default_max_pad_cfg")]
    pub max_pad: u8,
    #[serde(default = "default_decoy_max_cfg")]
    pub decoy_max: u8,
    #[serde(default = "default_max_ws_binary_cfg")]
    pub max_ws_binary: usize,
    #[serde(default = "default_tls_profile_cfg")]
    pub tls_profile: String,
    #[serde(default)]
    pub from_invite: String,
    #[serde(default)]
    pub invite_passphrase: String,
    #[serde(default)]
    pub junk_frames: u32,
    #[serde(default)]
    pub early_ws_frames: u8,
    #[serde(default = "default_ws_ping_secs_cfg")]
    pub ws_ping_secs: u64,
    #[serde(default)]
    pub ws_headers: String,
    #[serde(default = "default_use_tcp_mux_cfg")]
    pub use_tcp_mux: bool,
    #[serde(default)]
    pub ws_path: String,
    #[serde(default)]
    pub pad_mode: String,
    #[serde(default)]
    pub ws_ping_jitter_percent: u8,
    #[serde(default)]
    pub ws_binary_send_jitter_ms: u8,
    #[serde(default)]
    pub udp_max_pad: String,
    #[serde(default)]
    pub udp_max_ws_binary: String,
    #[serde(default)]
    pub udp_mux_reply_timeout_secs: String,
    #[serde(default)]
    pub dummy_interval_secs: u64,
    #[serde(default)]
    pub decoy_gets: bool,
    #[serde(default = "default_decoy_gets_interval_cfg")]
    pub decoy_gets_interval_secs: u64,
    #[serde(default)]
    pub decoy_gets_paths: String,
    #[serde(default)]
    pub pin_cert_pem: String,
    #[serde(default)]
    pub split_tunnel_enabled: bool,
    #[serde(default)]
    pub split_tunnel_preset_ids: Vec<String>,

    // Extended protocol (v3 / stealth)
    #[serde(default = "default_proto")]
    pub proto: u8,
    #[serde(default)]
    pub proto_domain: String,
    #[serde(default)]
    pub stealth_profile: String,
    #[serde(default)]
    pub decoy_mode: String,
    #[serde(default)]
    pub desync_mode: String,
    #[serde(default)]
    pub tcp_fooling: String,
    #[serde(default)]
    pub tls_fragment: bool,
    #[serde(default = "default_ws_parallel")]
    pub ws_parallel: u8,
    #[serde(default)]
    pub idle_decoy_secs: u64,
    #[serde(default = "default_tls_stack_str")]
    pub tls_stack: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub reality_target: String,
    #[serde(default)]
    pub reality_public_key: String,
    #[serde(default)]
    pub reality_short_id: String,
    #[serde(default)]
    pub ws_host: String,
    #[serde(default)]
    pub ws_origin: String,
    #[serde(default)]
    pub ws_user_agent: String,
    #[serde(default)]
    pub ws_accept_language: String,
    #[serde(default)]
    pub ws_jitter_min_ms: u8,
    #[serde(default)]
    pub ws_jitter_max_ms: u8,

    /// Control plane metadata (portal import).
    #[serde(default)]
    pub control_plane_instance_id: u64,
    #[serde(default)]
    pub control_plane_config_version: String,
    #[serde(default)]
    pub control_plane_base_url: String,

    // Android-only (сохраняются в профиле; в tunnel JSON не попадают, кроме socks_bind)
    /// Локальный SOCKS для `local_client` на Android. Пусто → `127.0.0.1:1080` как в `BibaVpnService::SOCKS_LOCAL`.
    /// Не показываем в UI как «настройки прокси» — поле для миграции/внутренних сценариев.
    #[serde(default)]
    pub android_socks_bind: String,
    /// Пакеты в обход VPN (`addDisallowedApplication`), по одному в элементе вектора.
    #[serde(default)]
    pub android_split_tunnel_packages: Vec<String>,
    /// Добавленные вручную / через список приложений (не из пресетов UI).
    #[serde(default)]
    pub android_manual_split_packages: Vec<String>,
    /// Режим маршрутизации (`system_vpn` — текущее поведение VpnService).
    #[serde(default = "default_android_vpn_routing_mode")]
    pub android_vpn_routing_mode: String,
    /// Экономия при выключенном экране (аналог `KEY_SCREEN_OFF_BATTERY_SAVER` в Compose).
    #[serde(default)]
    pub android_screen_off_battery_saver: bool,
}

fn default_proto() -> u8 {
    3
}

fn default_ws_parallel() -> u8 {
    1
}

fn default_tls_stack_str() -> String {
    "rustls".to_string()
}

fn default_android_vpn_routing_mode() -> String {
    "system_vpn".to_string()
}

/// Значение по умолчанию для `socks_bind` в JSON на Android (см. `BibaVpnService.SOCKS_LOCAL`).
pub const ANDROID_DEFAULT_SOCKS_BIND: &str = "127.0.0.1:1080";

/// Copy decoded invite fields into a saved profile (UI + tunnel JSON hints).
pub fn apply_invite_fields(p: &mut TunnelProfile, inv: &InviteV1) {
    p.server = inv.server.clone();
    p.sni = inv.sni.clone();
    p.token = inv.token.clone();
    p.psk = inv.psk.clone().unwrap_or_default();
    p.proto = inv.proto;
    p.proto_domain = inv
        .proto_domain
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());
    p.decoy_max = inv.decoy_max;
    p.max_pad = inv.max_pad;
    p.max_ws_binary = inv.max_ws_binary;
    p.ws_ping_secs = inv.ws_ping_secs;
    p.insecure = inv.insecure;
    p.tls_profile = inv.tls_profile.clone();
    p.ws_path = inv.ws_path.clone().unwrap_or_default();
    p.pad_mode = inv.pad_mode.clone().unwrap_or_default();
    p.dummy_interval_secs = inv.dummy_interval_secs.unwrap_or(0);
    p.ws_ping_jitter_percent = inv.ws_ping_jitter_percent;
    p.ws_binary_send_jitter_ms = inv.ws_binary_send_jitter_ms;
    p.ws_jitter_min_ms = inv.ws_jitter_min_ms;
    p.ws_jitter_max_ms = inv.ws_jitter_max_ms;
    p.udp_max_pad = inv.udp_max_pad.map(|x| x.to_string()).unwrap_or_default();
    p.udp_max_ws_binary = inv
        .udp_max_ws_binary
        .map(|x| x.to_string())
        .unwrap_or_default();
    p.udp_mux_reply_timeout_secs = inv.udp_mux_reply_timeout_secs.to_string();
    p.junk_frames = inv.junk_frames;
    p.early_ws_frames = inv.early_ws_frames;
    p.use_tcp_mux = inv.use_tcp_mux;
    p.decoy_gets = inv.decoy_gets;
    p.decoy_gets_interval_secs = inv.decoy_gets_interval_secs;
    p.decoy_gets_paths = inv.decoy_gets_paths.clone().unwrap_or_default();
    p.ws_host = inv.ws_host.clone().unwrap_or_default();
    p.ws_origin = inv.ws_origin.clone().unwrap_or_default();
    p.ws_user_agent = inv.ws_user_agent.clone().unwrap_or_default();
    p.ws_accept_language = inv.ws_accept_language.clone().unwrap_or_default();
    p.ws_headers = inv.ws_headers.join("\n");
    p.fingerprint = inv.fingerprint.clone().unwrap_or_default();
    p.stealth_profile = inv.stealth_profile.clone().unwrap_or_default();
    p.decoy_mode = inv.decoy_mode.clone().unwrap_or_default();
    p.desync_mode = inv.desync_mode.clone().unwrap_or_default();
    p.tcp_fooling = inv.tcp_fooling.clone().unwrap_or_default();
    p.tls_fragment = inv.tls_fragment;
    p.ws_parallel = inv.ws_parallel.max(1).min(4);
    p.idle_decoy_secs = inv.idle_decoy_secs.unwrap_or(0);
    p.tls_stack = inv.tls_stack.clone();
    p.reality_target = inv.reality_target.clone().unwrap_or_default();
    p.reality_public_key = inv.reality_public_key.clone().unwrap_or_default();
    p.reality_short_id = inv.reality_short_id.clone().unwrap_or_default();
    p.pin_cert_pem = inv.pin_cert_pem.clone().unwrap_or_default();
}

/// Import or update a profile from control plane redeem payload.
pub fn import_control_plane_payload(
    cfg: &mut SavedConfig,
    payload: &crate::control_plane_client::ImportPayload,
    base_url: &str,
) -> Result<(), String> {
    use bibavpn::decode_invite_v1;

    let inst_id = payload.instance_id.max(0) as u64;
    let profile_idx = cfg
        .profiles
        .iter()
        .position(|p| p.control_plane_instance_id == inst_id && inst_id > 0);
    if profile_idx.is_none() {
        let id = new_profile_id();
        cfg.profiles.push(TunnelProfile {
            id: id.clone(),
            name: payload.display_name.clone(),
            control_plane_instance_id: inst_id,
            ..TunnelProfile::default()
        });
        cfg.active_profile_id = id;
    } else if let Some(i) = profile_idx {
        cfg.active_profile_id = cfg.profiles[i].id.clone();
    }

    let p = cfg
        .active_profile_mut()
        .ok_or_else(|| "нет активного профиля".to_string())?;
    p.from_invite = payload.invite_uri.trim().to_string();
    p.invite_passphrase = payload.invite_passphrase.clone();
    p.control_plane_instance_id = inst_id;
    p.control_plane_config_version = payload.config_version.clone();
    p.control_plane_base_url = base_url.trim().trim_end_matches('/').to_string();
    if !payload.display_name.trim().is_empty() {
        p.name = payload.display_name.trim().to_string();
    } else if !payload.server_name.trim().is_empty() {
        p.name = payload.server_name.trim().to_string();
    }
    let inv = decode_invite_v1(&p.from_invite, &p.invite_passphrase)
        .map_err(|e| format!("Ключ: {e:#}"))?;
    apply_invite_fields(p, &inv);
    Ok(())
}

impl Default for TunnelProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: "Profile".to_string(),
            server: String::new(),
            token: String::new(),
            psk: String::new(),
            sni: String::new(),
            insecure: false,
            max_pad: default_max_pad_cfg(),
            decoy_max: default_decoy_max_cfg(),
            max_ws_binary: default_max_ws_binary_cfg(),
            tls_profile: default_tls_profile_cfg(),
            from_invite: String::new(),
            invite_passphrase: String::new(),
            junk_frames: 0,
            early_ws_frames: 0,
            ws_ping_secs: default_ws_ping_secs_cfg(),
            ws_headers: String::new(),
            use_tcp_mux: default_use_tcp_mux_cfg(),
            ws_path: String::new(),
            pad_mode: String::new(),
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            udp_max_pad: String::new(),
            udp_max_ws_binary: String::new(),
            udp_mux_reply_timeout_secs: String::new(),
            dummy_interval_secs: 0,
            decoy_gets: false,
            decoy_gets_interval_secs: default_decoy_gets_interval_cfg(),
            decoy_gets_paths: String::new(),
            pin_cert_pem: String::new(),
            split_tunnel_enabled: false,
            split_tunnel_preset_ids: Vec::new(),
            proto: default_proto(),
            proto_domain: String::new(),
            stealth_profile: String::new(),
            decoy_mode: String::new(),
            desync_mode: String::new(),
            tcp_fooling: String::new(),
            tls_fragment: false,
            ws_parallel: default_ws_parallel(),
            idle_decoy_secs: 0,
            tls_stack: default_tls_stack_str(),
            fingerprint: String::new(),
            reality_target: String::new(),
            reality_public_key: String::new(),
            reality_short_id: String::new(),
            ws_host: String::new(),
            ws_origin: String::new(),
            ws_user_agent: String::new(),
            ws_accept_language: String::new(),
            ws_jitter_min_ms: 0,
            ws_jitter_max_ms: 0,
            control_plane_instance_id: 0,
            control_plane_config_version: String::new(),
            control_plane_base_url: String::new(),
            android_socks_bind: String::new(),
            android_split_tunnel_packages: Vec::new(),
            android_manual_split_packages: Vec::new(),
            android_vpn_routing_mode: default_android_vpn_routing_mode(),
            android_screen_off_battery_saver: false,
        }
    }
}

/// Корневой сохранённый конфиг (десктоп): язык, локальные порты, список профилей.
#[derive(Serialize, Deserialize, Clone)]
pub struct SavedConfig {
    #[serde(default)]
    pub version: u32,
    #[serde(default = "default_ui_locale")]
    pub ui_locale: String,
    #[serde(default = "default_http_port")]
    pub local_http_port: u16,
    #[serde(default)]
    pub local_socks_port: u16,
    #[serde(default)]
    pub active_profile_id: String,
    #[serde(default)]
    pub profiles: Vec<TunnelProfile>,
}

fn default_http_port() -> u16 {
    17_890
}

fn default_decoy_gets_interval_cfg() -> u64 {
    30
}

impl Default for SavedConfig {
    fn default() -> Self {
        let id = new_profile_id();
        Self {
            version: CONFIG_VERSION,
            ui_locale: default_ui_locale(),
            local_http_port: default_http_port(),
            local_socks_port: 0,
            active_profile_id: id.clone(),
            profiles: vec![TunnelProfile {
                id,
                name: "Default".to_string(),
                ..TunnelProfile::default()
            }],
        }
    }
}

fn default_ui_locale() -> String {
    "auto".to_string()
}

fn default_use_tcp_mux_cfg() -> bool {
    true
}

fn new_profile_id() -> String {
    let us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    format!("p-{us}")
}

impl SavedConfig {
    pub fn active_profile(&self) -> Option<&TunnelProfile> {
        self.profiles
            .iter()
            .find(|p| p.id == self.active_profile_id)
            .or_else(|| self.profiles.first())
    }

    pub fn active_profile_mut(&mut self) -> Option<&mut TunnelProfile> {
        let id = self.active_profile_id.clone();
        let idx = self.profiles.iter().position(|p| p.id == id);
        match idx {
            Some(i) => self.profiles.get_mut(i),
            None => self.profiles.first_mut(),
        }
    }

    pub fn can_connect(&self) -> bool {
        self.active_profile()
            .map(|p| {
                let invite_ok = !p.from_invite.trim().is_empty() && !p.invite_passphrase.is_empty();
                let manual_ok = !p.server.trim().is_empty() && !p.token.trim().is_empty();
                invite_ok || manual_ok
            })
            .unwrap_or(false)
    }

    /// JSON для `local_client_options_from_json_str_with_binds` (только активный профиль).
    pub fn start_config_json(&self) -> Result<String, String> {
        let p = self
            .active_profile()
            .ok_or_else(|| "no active profile".to_string())?;
        p.start_config_json()
    }
}

impl TunnelProfile {
    pub fn can_connect(&self) -> bool {
        let invite_ok = !self.from_invite.trim().is_empty() && !self.invite_passphrase.is_empty();
        let manual_ok = !self.server.trim().is_empty() && !self.token.trim().is_empty();
        invite_ok || manual_ok
    }

    pub fn start_config_json(&self) -> Result<String, String> {
        use serde_json::{json, Map, Value};
        let use_invite = !self.from_invite.trim().is_empty() && !self.invite_passphrase.is_empty();
        let mut o = Map::new();
        if use_invite {
            o.insert("from_invite".to_string(), json!(self.from_invite.trim()));
            o.insert(
                "invite_passphrase".to_string(),
                json!(self.invite_passphrase.clone()),
            );
            o.insert("server".to_string(), json!(""));
            // Do not set `token`: it must come from the decoded invite. A placeholder like
            // "change-me" breaks `start_json_config` validation (JSON token must match invite).
        } else {
            o.insert("server".to_string(), json!(self.server.trim()));
            o.insert("token".to_string(), json!(self.token.clone()));
            let tp = self.tls_profile.trim();
            if !tp.is_empty() && tp != "default" {
                o.insert("tls_profile".to_string(), json!(tp));
            }
        }
        // Invite: не передаём пустой sni (как Android).
        if !use_invite {
            if !self.sni.trim().is_empty() {
                o.insert("sni".to_string(), json!(self.sni.trim()));
            }
        } else if !self.sni.trim().is_empty() {
            o.insert("sni".to_string(), json!(self.sni.trim()));
        }

        #[cfg(target_os = "android")]
        let socks_bind: String = {
            let s = self.android_socks_bind.trim();
            if s.is_empty() {
                ANDROID_DEFAULT_SOCKS_BIND.to_string()
            } else {
                s.to_string()
            }
        };
        #[cfg(not(target_os = "android"))]
        let socks_bind = "127.0.0.1:0".to_string();
        o.insert("socks_bind".to_string(), json!(socks_bind));
        o.insert("insecure".to_string(), json!(self.insecure));
        o.insert("max_pad".to_string(), json!(self.max_pad));
        o.insert("decoy_max".to_string(), json!(self.decoy_max.min(255)));
        o.insert("junk_frames".to_string(), json!(self.junk_frames));
        o.insert("early_ws_frames".to_string(), json!(self.early_ws_frames));
        o.insert("max_ws_binary".to_string(), json!(self.max_ws_binary));
        o.insert("ws_ping_secs".to_string(), json!(self.ws_ping_secs));
        o.insert("use_tcp_mux".to_string(), json!(self.use_tcp_mux));
        let wp = self.ws_path.trim();
        if !wp.is_empty() {
            o.insert("ws_path".to_string(), json!(wp));
        }
        let pm = self.pad_mode.trim();
        if !pm.is_empty() {
            o.insert("pad_mode".to_string(), json!(pm));
        }
        let j_ping = self.ws_ping_jitter_percent.min(50);
        if j_ping > 0 {
            o.insert("ws_ping_jitter_percent".to_string(), json!(j_ping));
        }
        let j_bin = self.ws_binary_send_jitter_ms.min(255);
        if j_bin > 0 {
            o.insert("ws_binary_send_jitter_ms".to_string(), json!(j_bin));
        }
        let jmin = self.ws_jitter_min_ms.min(255);
        if jmin > 0 {
            o.insert("ws_jitter_min_ms".to_string(), json!(jmin));
        }
        let jmax = self.ws_jitter_max_ms.min(255);
        if jmax > 0 {
            o.insert("ws_jitter_max_ms".to_string(), json!(jmax));
        }
        let udp_pad = self.udp_max_pad.trim();
        if !udp_pad.is_empty() {
            let v: u8 = udp_pad
                .parse()
                .map_err(|_| "udp_max_pad: нужно число 0–255".to_string())?;
            o.insert("udp_max_pad".to_string(), json!(v.min(255)));
        }
        let udp_bin = self.udp_max_ws_binary.trim();
        if !udp_bin.is_empty() {
            let v: usize = udp_bin
                .parse()
                .map_err(|_| "udp_max_ws_binary: нужно число".to_string())?;
            if v > 0 {
                o.insert("udp_max_ws_binary".to_string(), json!(v));
            }
        }
        let udp_to = self.udp_mux_reply_timeout_secs.trim();
        if !udp_to.is_empty() {
            let v: u64 = udp_to
                .parse()
                .map_err(|_| "udp_mux_reply_timeout_secs: нужно число (сек)".to_string())?;
            o.insert("udp_mux_reply_timeout_secs".to_string(), json!(v));
        }
        if self.dummy_interval_secs > 0 {
            o.insert(
                "dummy_interval_secs".to_string(),
                json!(self.dummy_interval_secs),
            );
        }
        if self.decoy_gets {
            o.insert("decoy_gets".to_string(), json!(true));
            o.insert(
                "decoy_gets_interval_secs".to_string(),
                json!(self.decoy_gets_interval_secs.max(1)),
            );
            let dp = self.decoy_gets_paths.trim();
            if !dp.is_empty() {
                o.insert("decoy_gets_paths".to_string(), json!(dp));
            }
        }
        let pin = self.pin_cert_pem.trim();
        if !pin.is_empty() {
            o.insert("pin_cert_pem".to_string(), json!(pin));
        }
        if !self.psk.trim().is_empty() {
            o.insert("psk".to_string(), json!(self.psk.trim()));
        }
        let lines: Vec<String> = self
            .ws_headers
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(std::string::ToString::to_string)
            .collect();
        if !lines.is_empty() {
            o.insert("ws_headers".to_string(), json!(lines));
        }

        let pr = self.proto.max(1).min(255);
        if pr != 3 {
            o.insert("proto".to_string(), json!(pr));
        }
        // Как Android `buildJson`: proto_domain только в ручном режиме (не инвайт).
        let pd = self.proto_domain.trim();
        if !use_invite {
            if pd.is_empty() {
                o.insert("proto_domain".to_string(), json!("default"));
            } else {
                o.insert("proto_domain".to_string(), json!(pd));
            }
        } else if !pd.is_empty() {
            o.insert("proto_domain".to_string(), json!(pd));
        }
        let sp = self.stealth_profile.trim();
        if !sp.is_empty() {
            o.insert("stealth_profile".to_string(), json!(sp));
        }
        let dm = self.decoy_mode.trim();
        if !dm.is_empty() {
            o.insert("decoy_mode".to_string(), json!(dm));
        }
        let dsm = self.desync_mode.trim();
        if !dsm.is_empty() {
            o.insert("desync_mode".to_string(), json!(dsm));
        }
        let tf = self.tcp_fooling.trim();
        if !tf.is_empty() {
            o.insert("tcp_fooling".to_string(), json!(tf));
        }
        if self.tls_fragment {
            o.insert("tls_fragment".to_string(), json!(true));
        }
        let wsp = self.ws_parallel.max(1).min(4);
        o.insert("ws_parallel".to_string(), json!(wsp));
        if self.idle_decoy_secs > 0 {
            o.insert("idle_decoy_secs".to_string(), json!(self.idle_decoy_secs));
        }
        let tst = self.tls_stack.trim().to_lowercase();
        if !tst.is_empty() && tst != "rustls" {
            o.insert("tls_stack".to_string(), json!(tst));
        }
        let fp = self.fingerprint.trim();
        if !fp.is_empty() {
            o.insert("fingerprint".to_string(), json!(fp));
        }
        let rt = self.reality_target.trim();
        let rpk = self.reality_public_key.trim();
        let rsid = self.reality_short_id.trim();
        if !rt.is_empty() && !rpk.is_empty() {
            o.insert("reality_target".to_string(), json!(rt));
            o.insert("reality_public_key".to_string(), json!(rpk));
            if !rsid.is_empty() {
                o.insert("reality_short_id".to_string(), json!(rsid));
            }
        }
        let wh = self.ws_host.trim();
        if !wh.is_empty() {
            o.insert("ws_host".to_string(), json!(wh));
        }
        let wo = self.ws_origin.trim();
        if !wo.is_empty() {
            o.insert("ws_origin".to_string(), json!(wo));
        }
        let wua = self.ws_user_agent.trim();
        if !wua.is_empty() {
            o.insert("ws_user_agent".to_string(), json!(wua));
        }
        let wal = self.ws_accept_language.trim();
        if !wal.is_empty() {
            o.insert("ws_accept_language".to_string(), json!(wal));
        }

        // Domain split routing handled inside the tunnel client (`bibavpn::domain_route`):
        // the DNS snoop learns IP -> domain from answers flowing through the UDP relay, so a
        // SOCKS CONNECT that only carries an IP (full-TUN on mobile) still matches. Unlike the
        // Android `excludeRoute` path this works on every API level, covers IPv6, re-learns CDN
        // addresses live, and is not capped at 128 routes. Empty when split tunnel is off.
        //
        // Reads the in-memory preset cache, so callers must `bypass_domains::ensure_loaded()`
        // *before* building this JSON or the list comes back empty.
        let split_domains = crate::split_tunnel::bypass_domains_for_profile(self);
        if !split_domains.is_empty() {
            o.insert("split_bypass_domains".to_string(), json!(split_domains));
        }

        serde_json::to_string(&Value::Object(o)).map_err(|e| e.to_string())
    }
}

/// Старый формат `config.json` (один плоский профиль).
#[derive(Deserialize)]
struct LegacyFlatConfig {
    server: String,
    token: String,
    psk: String,
    sni: String,
    insecure: bool,
    #[serde(default = "default_http_port")]
    local_http_port: u16,
    #[serde(default)]
    local_socks_port: u16,
    #[serde(default = "default_max_pad_cfg")]
    max_pad: u8,
    #[serde(default = "default_decoy_max_cfg")]
    decoy_max: u8,
    #[serde(default = "default_max_ws_binary_cfg")]
    max_ws_binary: usize,
    #[serde(default = "default_tls_profile_cfg")]
    tls_profile: String,
    #[serde(default)]
    from_invite: String,
    #[serde(default)]
    invite_passphrase: String,
    #[serde(default)]
    junk_frames: u32,
    #[serde(default)]
    early_ws_frames: u8,
    #[serde(default = "default_ws_ping_secs_cfg")]
    ws_ping_secs: u64,
    #[serde(default)]
    ws_headers: String,
    #[serde(default = "default_use_tcp_mux_cfg")]
    use_tcp_mux: bool,
    #[serde(default)]
    ws_path: String,
    #[serde(default)]
    pad_mode: String,
    #[serde(default)]
    ws_ping_jitter_percent: u8,
    #[serde(default)]
    ws_binary_send_jitter_ms: u8,
    #[serde(default)]
    udp_max_pad: String,
    #[serde(default)]
    udp_max_ws_binary: String,
    #[serde(default)]
    udp_mux_reply_timeout_secs: String,
    #[serde(default)]
    dummy_interval_secs: u64,
    #[serde(default)]
    decoy_gets: bool,
    #[serde(default = "default_decoy_gets_interval_cfg")]
    decoy_gets_interval_secs: u64,
    #[serde(default)]
    decoy_gets_paths: String,
    #[serde(default)]
    pin_cert_pem: String,
    #[serde(default = "default_ui_locale")]
    ui_locale: String,
    #[serde(default)]
    split_tunnel_enabled: bool,
    #[serde(default)]
    split_tunnel_preset_ids: Vec<String>,
}

fn migrate_legacy(l: LegacyFlatConfig) -> SavedConfig {
    let id = new_profile_id();
    let profile = TunnelProfile {
        id: id.clone(),
        name: "Default".to_string(),
        server: l.server,
        token: l.token,
        psk: l.psk,
        sni: l.sni,
        insecure: l.insecure,
        max_pad: l.max_pad,
        decoy_max: l.decoy_max,
        max_ws_binary: l.max_ws_binary,
        tls_profile: l.tls_profile,
        from_invite: l.from_invite,
        invite_passphrase: l.invite_passphrase,
        junk_frames: l.junk_frames,
        early_ws_frames: l.early_ws_frames,
        ws_ping_secs: l.ws_ping_secs,
        ws_headers: l.ws_headers,
        use_tcp_mux: l.use_tcp_mux,
        ws_path: l.ws_path,
        pad_mode: l.pad_mode,
        ws_ping_jitter_percent: l.ws_ping_jitter_percent,
        ws_binary_send_jitter_ms: l.ws_binary_send_jitter_ms,
        udp_max_pad: l.udp_max_pad,
        udp_max_ws_binary: l.udp_max_ws_binary,
        udp_mux_reply_timeout_secs: l.udp_mux_reply_timeout_secs,
        dummy_interval_secs: l.dummy_interval_secs,
        decoy_gets: l.decoy_gets,
        decoy_gets_interval_secs: l.decoy_gets_interval_secs,
        decoy_gets_paths: l.decoy_gets_paths,
        pin_cert_pem: l.pin_cert_pem,
        split_tunnel_enabled: l.split_tunnel_enabled,
        split_tunnel_preset_ids: l.split_tunnel_preset_ids,
        ..TunnelProfile::default()
    };
    SavedConfig {
        version: CONFIG_VERSION,
        ui_locale: l.ui_locale,
        local_http_port: l.local_http_port,
        local_socks_port: l.local_socks_port,
        active_profile_id: id,
        profiles: vec![profile],
    }
}

/// Десктоп / общий путь: `%LOCALAPPDATA%/BibaVPN/config.json` и аналоги.
pub fn desktop_config_json_path() -> PathBuf {
    let root = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("BibaVPN");
    let _ = std::fs::create_dir_all(&root);
    root.join("config.json")
}

pub fn config_path() -> PathBuf {
    desktop_config_json_path()
}

pub fn load_config_from_path(path: &Path) -> SavedConfig {
    let Ok(s) = std::fs::read_to_string(path) else {
        return SavedConfig::default();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&s) else {
        return SavedConfig::default();
    };
    if val
        .get("profiles")
        .and_then(|x| x.as_array())
        .is_some_and(|a| !a.is_empty())
    {
        serde_json::from_value(val).unwrap_or_default()
    } else {
        serde_json::from_value::<LegacyFlatConfig>(val)
            .map(migrate_legacy)
            .unwrap_or_default()
    }
}

pub fn save_config_to_path(cfg: &SavedConfig, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let s = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(path, s).map_err(|e| e.to_string())
}

pub fn load_config_disk() -> SavedConfig {
    #[cfg(not(target_os = "android"))]
    {
        load_config_from_path(&desktop_config_json_path())
    }
    #[cfg(target_os = "android")]
    {
        SavedConfig::default()
    }
}

#[cfg(not(target_os = "android"))]
pub fn save_config_disk(cfg: &SavedConfig) {
    let _ = save_config_to_path(cfg, &desktop_config_json_path());
}

#[cfg(target_os = "android")]
pub fn save_config_disk(_cfg: &SavedConfig) {
    // На Android путь задаётся через AppHandle (`app.path()`); см. `persist_cfg` в lib.rs.
}

pub fn normalize_loaded(cfg: &mut SavedConfig) {
    if cfg.version < CONFIG_VERSION {
        cfg.version = CONFIG_VERSION;
    }
    if cfg.local_http_port == 0 {
        cfg.local_http_port = default_http_port();
    }
    if cfg.profiles.is_empty() {
        let id = new_profile_id();
        cfg.active_profile_id = id.clone();
        cfg.profiles.push(TunnelProfile {
            id,
            name: "Default".to_string(),
            ..TunnelProfile::default()
        });
    }
    if !cfg
        .profiles
        .iter()
        .any(|p| p.id == cfg.active_profile_id)
    {
        cfg.active_profile_id = cfg.profiles[0].id.clone();
    }
    for p in &mut cfg.profiles {
        if p.id.trim().is_empty() {
            p.id = new_profile_id();
        }
        if p.max_ws_binary < 1024 {
            p.max_ws_binary = DEFAULT_CLIENT_MAX_WS_BINARY;
        }
        if p.android_vpn_routing_mode.trim().is_empty() {
            p.android_vpn_routing_mode = default_android_vpn_routing_mode();
        }
        let mut seen_pkg = std::collections::HashSet::<String>::new();
        p.android_split_tunnel_packages = std::mem::take(&mut p.android_split_tunnel_packages)
            .into_iter()
            .filter_map(|pkg| {
                let k = pkg.trim().to_string();
                if k.is_empty() {
                    return None;
                }
                seen_pkg.insert(k.clone()).then_some(k)
            })
            .collect();
        let mut seen_m = std::collections::HashSet::<String>::new();
        p.android_manual_split_packages = std::mem::take(&mut p.android_manual_split_packages)
            .into_iter()
            .filter_map(|pkg| {
                let k = pkg.trim().to_string();
                if k.is_empty() {
                    return None;
                }
                seen_m.insert(k.clone()).then_some(k)
            })
            .collect();
    }
    let l = cfg.ui_locale.trim().to_lowercase();
    cfg.ui_locale = match l.as_str() {
        "" | "auto" => "auto".to_string(),
        "ru" | "rus" => "ru".to_string(),
        "en" | "eng" => "en".to_string(),
        _ => "auto".to_string(),
    };
}

fn default_max_pad_cfg() -> u8 {
    64
}

fn default_decoy_max_cfg() -> u8 {
    32
}

fn default_max_ws_binary_cfg() -> usize {
    DEFAULT_CLIENT_MAX_WS_BINARY
}

fn default_ws_ping_secs_cfg() -> u64 {
    25
}

fn default_tls_profile_cfg() -> String {
    "default".to_string()
}

pub fn display_host_line(cfg: &SavedConfig) -> String {
    let Some(p) = cfg.active_profile() else {
        return "—".to_string();
    };
    let server = p.server.trim();
    let sni = p.sni.trim();
    let invite = p.from_invite.trim();
    if !server.is_empty() && !sni.is_empty() {
        sni.to_string()
    } else if !server.is_empty() {
        server
            .split(':')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(server)
            .to_string()
    } else if !invite.is_empty() {
        "Ключ Biba".to_string()
    } else {
        "—".to_string()
    }
}

pub fn server_card_subtitle(cfg: &SavedConfig) -> String {
    let Some(p) = cfg.active_profile() else {
        return "Не задан сервер".to_string();
    };
    let server = p.server.trim();
    let invite = p.from_invite.trim();
    if !server.is_empty() {
        server.to_string()
    } else if !invite.is_empty() {
        "Ключ Biba".to_string()
    } else {
        "Не задан сервер".to_string()
    }
}

#[cfg(test)]
mod split_bypass_json_tests {
    use super::TunnelProfile;

    fn profile() -> TunnelProfile {
        TunnelProfile {
            server: "vpn.example.com:8443".to_string(),
            token: "t".to_string(),
            ..TunnelProfile::default()
        }
    }

    /// The tunnel client treats an absent `split_bypass_domains` as "domain split off", so the
    /// key must never appear just because the section exists in the profile.
    #[test]
    fn omitted_when_split_tunnel_disabled() {
        let mut p = profile();
        p.split_tunnel_enabled = false;
        p.split_tunnel_preset_ids = vec!["banks".to_string()];
        let json = p.start_config_json().expect("build start json");
        assert!(!json.contains("split_bypass_domains"), "got: {json}");
    }

    /// Enabled but nothing selected resolves to an empty list — emit no key rather than `[]`,
    /// so the client takes its cheap "bypass disabled" path.
    #[test]
    fn omitted_when_no_presets_selected() {
        let mut p = profile();
        p.split_tunnel_enabled = true;
        p.split_tunnel_preset_ids = Vec::new();
        let json = p.start_config_json().expect("build start json");
        assert!(!json.contains("split_bypass_domains"), "got: {json}");
    }
}

#[cfg(test)]
mod public_snapshot_tests {
    use super::{
        merge_saved_config, server_card_subtitle, to_public_saved_config, SavedConfig,
        TunnelProfile,
    };
    use serde_json::{json, Value};

    fn secret_profile() -> TunnelProfile {
        TunnelProfile {
            id: "p-test".to_string(),
            name: "Secret".to_string(),
            server: "vpn.example.com:8443".to_string(),
            token: "super-secret-token".to_string(),
            psk: "super-secret-psk".to_string(),
            from_invite: "biba://invite-body-secret".to_string(),
            invite_passphrase: "passphrase-secret".to_string(),
            pin_cert_pem: "-----BEGIN CERTIFICATE-----SECRET-----END CERTIFICATE-----".to_string(),
            ..TunnelProfile::default()
        }
    }

    #[test]
    fn public_snapshot_omits_secret_keys_and_substrings() {
        let mut cfg = SavedConfig::default();
        let p = secret_profile();
        cfg.profiles = vec![p];
        cfg.active_profile_id = "p-test".to_string();
        let public = to_public_saved_config(&cfg);
        let val = serde_json::to_value(&public).expect("serialize public cfg");
        let text = serde_json::to_string(&val).expect("stringify");
        for key in ["token", "psk", "from_invite", "invite_passphrase", "pin_cert_pem"] {
            assert!(
                !val.get("profiles")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.first())
                    .and_then(|p| p.as_object())
                    .map(|m| m.contains_key(key))
                    .unwrap_or(false),
                "key {key} must not appear in public profile JSON"
            );
        }
        assert!(!text.contains("super-secret-token"));
        assert!(!text.contains("super-secret-psk"));
        assert!(!text.contains("biba://"));
        assert!(!text.contains("invite-body-secret"));
        assert!(!text.contains("passphrase-secret"));
        assert!(!text.contains("SECRET"));
    }

    #[test]
    fn public_has_flags_reflect_nonempty_secrets() {
        let mut cfg = SavedConfig::default();
        cfg.profiles = vec![secret_profile()];
        cfg.active_profile_id = "p-test".to_string();
        let public = to_public_saved_config(&cfg);
        let p = &public.profiles[0];
        assert!(p.has_token);
        assert!(p.has_psk);
        assert!(p.has_from_invite);
        assert!(p.has_invite_passphrase);
        assert!(p.has_invite);
        assert!(p.has_pin_cert);
    }

    #[test]
    fn public_has_flags_false_when_secrets_empty() {
        let mut cfg = SavedConfig::default();
        let p = TunnelProfile {
            id: "p-empty".to_string(),
            server: "host:443".to_string(),
            ..TunnelProfile::default()
        };
        cfg.profiles = vec![p];
        cfg.active_profile_id = "p-empty".to_string();
        let public = to_public_saved_config(&cfg);
        let pr = &public.profiles[0];
        assert!(!pr.has_token);
        assert!(!pr.has_psk);
        assert!(!pr.has_from_invite);
        assert!(!pr.has_invite_passphrase);
        assert!(!pr.has_invite);
        assert!(!pr.has_pin_cert);
    }

    #[test]
    fn server_card_subtitle_invite_profile_no_uri() {
        let mut cfg = SavedConfig::default();
        let p = TunnelProfile {
            id: "p-inv".to_string(),
            from_invite: "biba://should-not-leak".to_string(),
            invite_passphrase: "hidden".to_string(),
            ..TunnelProfile::default()
        };
        cfg.profiles = vec![p];
        cfg.active_profile_id = "p-inv".to_string();
        let sub = server_card_subtitle(&cfg);
        assert!(!sub.contains("biba://"));
        assert!(!sub.contains("should-not-leak"));
        assert_eq!(sub, "Ключ Biba");
    }

    #[test]
    fn merge_preserves_secrets_when_keys_omitted() {
        let mut stored = SavedConfig::default();
        stored.profiles = vec![secret_profile()];
        stored.active_profile_id = "p-test".to_string();
        let public = to_public_saved_config(&stored);
        let incoming: Value = serde_json::to_value(public).expect("public value");
        let merged = merge_saved_config(&stored, &incoming).expect("merge");
        let m = &merged.profiles[0];
        assert_eq!(m.token, "super-secret-token");
        assert_eq!(m.psk, "super-secret-psk");
        assert_eq!(m.from_invite, "biba://invite-body-secret");
        assert_eq!(m.invite_passphrase, "passphrase-secret");
        assert!(m.pin_cert_pem.contains("SECRET"));
    }

    #[test]
    fn merge_honors_present_empty_string_to_clear() {
        let mut stored = SavedConfig::default();
        stored.profiles = vec![secret_profile()];
        stored.active_profile_id = "p-test".to_string();
        let mut incoming = serde_json::to_value(stored.clone()).expect("full cfg");
        incoming["profiles"][0]["token"] = json!("");
        incoming["profiles"][0]["psk"] = json!("");
        let merged = merge_saved_config(&stored, &incoming).expect("merge");
        assert_eq!(merged.profiles[0].token, "");
        assert_eq!(merged.profiles[0].psk, "");
        assert_eq!(merged.profiles[0].from_invite, "biba://invite-body-secret");
    }

    #[test]
    fn merge_new_profile_does_not_copy_other_secrets() {
        let mut stored = SavedConfig::default();
        stored.profiles = vec![secret_profile()];
        stored.active_profile_id = "p-test".to_string();
        let mut new_p = TunnelProfile::default();
        new_p.id = "p-new".to_string();
        new_p.name = "New".to_string();
        new_p.server = "other.example.com:8443".to_string();
        let mut new_val = serde_json::to_value(&new_p).expect("new profile value");
        if let Some(obj) = new_val.as_object_mut() {
            for key in super::PROFILE_SECRET_KEYS {
                obj.remove(*key);
            }
        }
        let incoming = json!({
            "version": stored.version,
            "ui_locale": stored.ui_locale,
            "local_http_port": stored.local_http_port,
            "local_socks_port": stored.local_socks_port,
            "active_profile_id": "p-new",
            "profiles": [
                serde_json::to_value(secret_profile()).expect("p1"),
                new_val,
            ]
        });
        let merged = merge_saved_config(&stored, &incoming).expect("merge");
        let new_p = merged
            .profiles
            .iter()
            .find(|p| p.id == "p-new")
            .expect("new profile");
        assert_eq!(new_p.token, "");
        assert_eq!(new_p.psk, "");
        assert_eq!(new_p.from_invite, "");
        assert_eq!(new_p.invite_passphrase, "");
        assert_eq!(new_p.pin_cert_pem, "");
    }
}
