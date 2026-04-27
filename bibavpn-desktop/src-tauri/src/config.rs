//! Сохранённая конфигурация (multi-profile) и JSON для `local_client`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use bibavpn::local_client::DEFAULT_CLIENT_MAX_WS_BINARY;
use serde::{Deserialize, Serialize};

pub const CONFIG_VERSION: u32 = 2;

/// Один профиль туннеля (как один «сервер» в Android).
#[derive(Serialize, Deserialize, Clone)]
pub struct TunnelProfile {
    pub id: String,
    pub name: String,
    pub server: String,
    pub token: String,
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

    // Android-only (сохраняются в профиле; в tunnel JSON не попадают, кроме socks_bind)
    /// Локальный SOCKS для `local_client` на Android. Пусто → `127.0.0.1:1080` как в `BibaVpnService::SOCKS_LOCAL`.
    /// Не показываем в UI как «настройки прокси» — поле для миграции/внутренних сценариев.
    #[serde(default)]
    pub android_socks_bind: String,
    /// Пакеты в обход VPN (`addDisallowedApplication`), по одному в элементе вектора.
    #[serde(default)]
    pub android_split_tunnel_packages: Vec<String>,
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
            android_socks_bind: String::new(),
            android_split_tunnel_packages: Vec::new(),
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
            o.insert("token".to_string(), json!("change-me"));
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
        if !use_invite && !pd.is_empty() {
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

pub fn config_path() -> PathBuf {
    let root = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("BibaVPN");
    let _ = std::fs::create_dir_all(&root);
    root.join("config.json")
}

pub fn load_config_disk() -> SavedConfig {
    let p = config_path();
    let Ok(s) = std::fs::read_to_string(&p) else {
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

pub fn save_config_disk(cfg: &SavedConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(config_path(), s);
    }
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
        let max = 36usize;
        if invite.len() > max {
            format!("{}…", &invite[..max])
        } else {
            invite.to_string()
        }
    } else {
        "Не задан сервер".to_string()
    }
}
