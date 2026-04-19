//! Сохранённая конфигурация и JSON для `local_client` (как в Android / старый egui-клиент).

use std::path::PathBuf;

use bibavpn::local_client::DEFAULT_CLIENT_MAX_WS_BINARY;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct SavedConfig {
    pub server: String,
    pub token: String,
    pub psk: String,
    pub sni: String,
    pub insecure: bool,
    pub local_http_port: u16,
    #[serde(default)]
    pub local_socks_port: u16,
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
    /// `auto` | `ru` | `en` — язык UI и меню в трее (десктоп).
    #[serde(default = "default_ui_locale")]
    pub ui_locale: String,
    /// Раздельный туннель (Windows/macOS): выбранные пресеты идут в обход системного HTTP-прокси.
    #[serde(default)]
    pub split_tunnel_enabled: bool,
    #[serde(default)]
    pub split_tunnel_preset_ids: Vec<String>,
}

fn default_decoy_gets_interval_cfg() -> u64 {
    30
}

impl Default for SavedConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            token: String::new(),
            psk: String::new(),
            sni: String::new(),
            insecure: false,
            local_http_port: 17_890,
            local_socks_port: 0,
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
            ui_locale: default_ui_locale(),
            split_tunnel_enabled: false,
            split_tunnel_preset_ids: Vec::new(),
        }
    }
}

fn default_ui_locale() -> String {
    "auto".to_string()
}

fn default_use_tcp_mux_cfg() -> bool {
    true
}

impl SavedConfig {
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
            if !tp.is_empty() {
                o.insert("tls_profile".to_string(), json!(tp));
            }
        }
        if !self.sni.trim().is_empty() {
            o.insert("sni".to_string(), json!(self.sni.trim()));
        }
        o.insert("socks_bind".to_string(), json!("127.0.0.1:0"));
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
        serde_json::to_string(&Value::Object(o)).map_err(|e| e.to_string())
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
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config_disk(cfg: &SavedConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(config_path(), s);
    }
}

pub fn normalize_loaded(cfg: &mut SavedConfig) {
    if cfg.local_http_port == 0 {
        cfg.local_http_port = 17_890;
    }
    if cfg.max_ws_binary < 1024 {
        cfg.max_ws_binary = DEFAULT_CLIENT_MAX_WS_BINARY;
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
    let server = cfg.server.trim();
    let sni = cfg.sni.trim();
    let invite = cfg.from_invite.trim();
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
    let server = cfg.server.trim();
    let invite = cfg.from_invite.trim();
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
