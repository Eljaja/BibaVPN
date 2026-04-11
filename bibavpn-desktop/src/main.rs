#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod proxy_win;
#[cfg(target_os = "macos")]
mod proxy_mac;
#[cfg(not(any(windows, target_os = "macos")))]
mod proxy_stub;

#[cfg(windows)]
use proxy_win::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(target_os = "macos")]
use proxy_mac::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(not(any(windows, target_os = "macos")))]
use proxy_stub::{apply_proxy, read_backup, restore, ProxyBackup};

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bibavpn::local_client::DEFAULT_CLIENT_MAX_WS_BINARY;
use bibavpn::local_client_options_from_json_str_with_binds;
use bibavpn::tls_util::install_ring_crypto;
use bibavpn::decode_invite_v1;
use eframe::egui::{self, Color32, Margin, RichText, Rounding, Stroke, Vec2, Visuals};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, TrayIcon, TrayIconBuilder, TrayIconEvent};

#[derive(Serialize, Deserialize, Clone)]
struct SavedConfig {
    server: String,
    token: String,
    psk: String,
    sni: String,
    insecure: bool,
    local_http_port: u16,
    /// 0 = автоматически `local_http_port + 1` (SOCKS5: TCP + UDP через системный прокси).
    #[serde(default)]
    local_socks_port: u16,

    /// Как `--max-pad` в bibavpn-client.
    #[serde(default = "default_max_pad_cfg")]
    max_pad: u8,
    /// Как `--decoy-max` (PSK / v2).
    #[serde(default = "default_decoy_max_cfg")]
    decoy_max: u8,
    /// Как `--max-ws-binary`, верхняя граница размера WS binary.
    #[serde(default = "default_max_ws_binary_cfg")]
    max_ws_binary: usize,
    /// Как `--tls-profile` у bibavpn-client.
    #[serde(default = "default_tls_profile_cfg")]
    tls_profile: String,

    /// `biba://…` и passphrase — тот же формат, что в Android.
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
    /// По строке на заголовок, как `ws_headers` в JSON (`Name: value`).
    #[serde(default)]
    ws_headers: String,

    /// Как в Android `buildJson` / `bibavpn-client`.
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
    /// Пусто = не слать в JSON (дефолты библиотеки).
    #[serde(default)]
    udp_max_pad: String,
    #[serde(default)]
    udp_max_ws_binary: String,
    #[serde(default)]
    udp_mux_reply_timeout_secs: String,
    #[serde(default)]
    dummy_interval_secs: u64,

    /// Параллельные decoy HTTPS GET (как `bibavpn-client --decoy-gets`).
    #[serde(default)]
    decoy_gets: bool,
    #[serde(default = "default_decoy_gets_interval_cfg")]
    decoy_gets_interval_secs: u64,
    #[serde(default)]
    decoy_gets_paths: String,

    /// PEM цепочка для pin (как `pin_cert_pem` в JSON / `--pin-cert`).
    #[serde(default)]
    pin_cert_pem: String,
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
        }
    }
}

fn default_use_tcp_mux_cfg() -> bool {
    true
}

impl SavedConfig {
    fn can_connect(&self) -> bool {
        let invite_ok = !self.from_invite.trim().is_empty() && !self.invite_passphrase.is_empty();
        let manual_ok = !self.server.trim().is_empty() && !self.token.trim().is_empty();
        invite_ok || manual_ok
    }

    /// JSON для `local_client_options_from_json_str*` (как Android `buildJson`).
    fn start_config_json(&self) -> Result<String, String> {
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
        o.insert(
            "decoy_max".to_string(),
            json!(self.decoy_max.min(255)),
        );
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

fn config_path() -> PathBuf {
    let root = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("BibaVPN");
    let _ = std::fs::create_dir_all(&root);
    root.join("config.json")
}

fn load_config() -> SavedConfig {
    let p = config_path();
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(cfg: &SavedConfig) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        let _ = std::fs::write(config_path(), s);
    }
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

/// Токены из `DESIGN.md` §2–5 (BibaVPN cross-platform).
#[derive(Clone, Copy)]
struct Theme {
    bg_root: Color32,
    bg_screen: Color32,
    card_bg: Color32,
    field_inset: Color32,
    border_subtle: Color32,
    text_primary: Color32,
    text_muted: Color32,
    label_sky: Color32,
    mint: Color32,
    mint_soft: Color32,
    /// Низ основной кнопки (градиент CTA).
    cta_bottom: Color32,
    /// Верх градиента CTA (`DESIGN.md` §2.5).
    cta_top: Color32,
    main_btn_border: Color32,
    state_warning: Color32,
    state_danger: Color32,
    radius_window: f32,
    radius_card: f32,
    radius_control: f32,
}

impl Theme {
    fn dark() -> Self {
        Self {
            bg_root: Color32::from_rgb(0x07, 0x0B, 0x14),
            bg_screen: Color32::from_rgb(0x0B, 0x0F, 0x1A),
            card_bg: Color32::from_rgb(0x12, 0x18, 0x26),
            field_inset: Color32::from_rgba_unmultiplied(0x02, 0x06, 0x17, 140),
            border_subtle: Color32::from_rgba_unmultiplied(255, 255, 255, 20),
            text_primary: Color32::from_rgb(0xF8, 0xFA, 0xFC),
            text_muted: Color32::from_rgb(0x94, 0xA3, 0xB8),
            label_sky: Color32::from_rgb(0x60, 0xA5, 0xFA),
            mint: Color32::from_rgb(0x00, 0xFF, 0xA3),
            mint_soft: Color32::from_rgb(0x34, 0xD3, 0x99),
            cta_bottom: Color32::from_rgb(0x14, 0x20, 0x3C),
            cta_top: Color32::from_rgb(0x1A, 0x29, 0x50),
            main_btn_border: Color32::from_rgba_unmultiplied(0x60, 0xA5, 0xFA, 0x33),
            state_warning: Color32::from_rgb(251, 191, 36),
            state_danger: Color32::from_rgb(251, 113, 133),
            radius_window: 12.0,
            radius_card: 26.0,
            radius_control: 16.0,
        }
    }

    fn apply(self, ctx: &egui::Context) {
        let mut visuals = Visuals::dark();
        visuals.window_fill = self.bg_root;
        visuals.panel_fill = self.bg_screen;
        visuals.extreme_bg_color = self.bg_root;
        visuals.faint_bg_color = self.card_bg;
        visuals.widgets.noninteractive.bg_fill = self.card_bg;
        visuals.widgets.noninteractive.fg_stroke.color = self.text_muted;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.border_subtle);
        visuals.widgets.inactive.bg_fill = self.field_inset;
        visuals.widgets.inactive.weak_bg_fill = self.card_bg;
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x1A, 0x22, 0x35);
        visuals.widgets.active.bg_fill = Color32::from_rgb(0x22, 0x2d, 0x44);
        visuals.widgets.open.bg_fill = self.card_bg;
        visuals.selection.bg_fill = self.label_sky;
        visuals.hyperlink_color = self.label_sky;
        visuals.window_stroke = Stroke::new(1.0, self.border_subtle);
        ctx.set_visuals(visuals);

        let r = Rounding::same(self.radius_control);
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(12.0, 10.0);
        style.spacing.window_margin = Margin::same(20.0);
        style.spacing.button_padding = Vec2::new(24.0, 14.0);
        style.visuals.widgets.noninteractive.rounding = r;
        style.visuals.widgets.inactive.rounding = r;
        style.visuals.widgets.hovered.rounding = r;
        style.visuals.widgets.active.rounding = r;
        style.visuals.window_rounding = Rounding::same(self.radius_window);
        ctx.set_style(style);
    }
}

/// Радиальный фон главного экрана (`DESIGN.md` §2.6).
fn paint_radial_home_bg(painter: &egui::Painter, rect: egui::Rect) {
    use egui::emath::{pos2, vec2};
    use std::f32::consts::TAU;
    let center = pos2(rect.center().x, rect.top());
    let r = rect.width().max(rect.height()) * 1.35;
    let c0 = Color32::from_rgb(0x16, 0x20, 0x3B);
    let c1 = Color32::from_rgb(0x07, 0x0B, 0x14);
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(center, c0);
    const N: usize = 48;
    for i in 0..=N {
        let t = i as f32 / N as f32 * TAU;
        mesh.colored_vertex(center + r * vec2(t.cos(), t.sin()), c1);
    }
    for i in 1..=N {
        mesh.add_triangle(0, i as u32, (i + 1) as u32);
    }
    painter.add(egui::Shape::mesh(mesh));
}

fn paint_vertical_gradient_rect(painter: &egui::Painter, rect: egui::Rect, top: Color32, bottom: Color32) {
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(rect.left_top(), top);
    mesh.colored_vertex(rect.right_top(), top);
    mesh.colored_vertex(rect.right_bottom(), bottom);
    mesh.colored_vertex(rect.left_bottom(), bottom);
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(0, 2, 3);
    painter.add(egui::Shape::mesh(mesh));
}

fn display_host_line(cfg: &SavedConfig) -> String {
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

fn server_card_subtitle(cfg: &SavedConfig) -> String {
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

fn field_heading(ui: &mut egui::Ui, _theme: Theme, label: &str) {
    ui.label(
        RichText::new(label)
            .size(12.0)
            .strong()
            .color(Color32::from_rgba_unmultiplied(0x60, 0xA5, 0xFA, 230)),
    );
    ui.add_space(6.0);
}

fn group_heading(ui: &mut egui::Ui, theme: Theme, label: &str) {
    ui.add_space(4.0);
    ui.label(
        RichText::new(label)
            .size(11.0)
            .strong()
            .color(theme.text_muted),
    );
    ui.add_space(8.0);
}

fn load_wordmark(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let bytes = include_bytes!("../../branding/biba-vpn-logo.png");
    let img = image::load_from_memory(bytes).ok()?;
    let img = img.into_rgba8();
    let size = [img.width() as usize, img.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw());
    Some(ctx.load_texture("biba_wordmark", color, egui::TextureOptions::LINEAR))
}

struct ActiveVpn {
    shutdown: watch::Sender<bool>,
    join: JoinHandle<anyhow::Result<()>>,
}

impl ActiveVpn {
    fn stop(self, rt: &tokio::runtime::Runtime) {
        let _ = self.shutdown.send(true);
        let _ = rt.block_on(self.join);
    }
}

#[derive(Clone)]
struct TrayMenuIds {
    open: MenuId,
    on: MenuId,
    off: MenuId,
    quit: MenuId,
}

struct BibaApp {
    cfg: SavedConfig,
    wordmark: Option<egui::TextureHandle>,
    rt: Arc<tokio::runtime::Runtime>,
    err: Option<String>,
    proxy_backup: Option<ProxyBackup>,
    vpn: Option<ActiveVpn>,
    /// Фактический `host:port` удалённого сервера для текущего туннеля (может отличаться от полей формы).
    tunnel_server: Option<String>,
    exiting: bool,
    tray: Option<TrayIcon>,
    tray_ids: Option<TrayMenuIds>,
    /// macOS: несколько кадров без трея, пока поднимется NSApplication / run loop (см. tray-icon + winit).
    tray_frames_until_icon: u8,
    /// Один раз после ожидания; при ошибке сборки трея не долбим build() каждый кадр.
    tray_icon_attempted: bool,
    /// Главный экран vs настройки (как Android Home / Settings).
    show_settings: bool,
}

impl BibaApp {
    fn new(cc: &eframe::CreationContext<'_>, rt: Arc<tokio::runtime::Runtime>) -> Self {
        setup_style(&cc.egui_ctx);
        let mut cfg = load_config();
        if cfg.local_http_port == 0 {
            cfg.local_http_port = 17_890;
        }
        if cfg.max_ws_binary < 1024 {
            cfg.max_ws_binary = DEFAULT_CLIENT_MAX_WS_BINARY;
        }
        let tray_frames_until_icon = if cfg!(target_os = "macos") { 6 } else { 0 };
        let wordmark = load_wordmark(&cc.egui_ctx);
        Self {
            cfg,
            wordmark,
            rt,
            err: None,
            proxy_backup: None,
            vpn: None,
            tunnel_server: None,
            exiting: false,
            tray: None,
            tray_ids: None,
            tray_frames_until_icon,
            tray_icon_attempted: false,
            show_settings: false,
        }
    }

    fn ensure_tray_icon(&mut self) {
        if self.tray.is_some() {
            return;
        }
        let tray_menu = Menu::new();
        let open_i = MenuItem::new("Открыть окно", true, None);
        let on_i = MenuItem::new("Включить VPN", true, None);
        let off_i = MenuItem::new("Отключить VPN", true, None);
        let quit_i = MenuItem::new("Выход", true, None);
        let tray_ids = TrayMenuIds {
            open: open_i.id().clone(),
            on: on_i.id().clone(),
            off: off_i.id().clone(),
            quit: quit_i.id().clone(),
        };
        let _ = tray_menu.append_items(&[
            &open_i,
            &PredefinedMenuItem::separator(),
            &on_i,
            &off_i,
            &PredefinedMenuItem::separator(),
            &quit_i,
        ]);
        let icon = build_tray_icon();
        let tray_build = TrayIconBuilder::new()
            .with_menu_on_left_click(false)
            .with_tooltip("BibaVPN")
            .with_menu(Box::new(tray_menu))
            .with_icon(icon);
        #[cfg(target_os = "macos")]
        let tray_build = tray_build.with_icon_as_template(false);
        match tray_build.build() {
            Ok(tray) => {
                self.tray = Some(tray);
                self.tray_ids = Some(tray_ids);
                self.sync_tray_tooltip();
            }
            Err(e) => {
                self.err = Some(format!("Трей: {e}"));
            }
        }
    }

    fn sync_tray_tooltip(&self) {
        let Some(ref tray) = self.tray else {
            return;
        };
        let tip = if self.vpn.is_some() {
            "BibaVPN — подключено"
        } else {
            "BibaVPN — отключено"
        };
        let _ = tray.set_tooltip(Some(tip));
    }

    fn show_window(ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    fn poll_tray(&mut self, ctx: &egui::Context) {
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                ..
            } = ev
            {
                Self::show_window(ctx);
            }
        }
        let Some(ids) = self.tray_ids.clone() else {
            return;
        };
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id() == &ids.quit {
                self.tray.take();
                self.shutdown_app();
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            if ev.id() == &ids.open {
                Self::show_window(ctx);
            } else if ev.id() == &ids.on {
                match self.connect() {
                    Ok(()) => {}
                    Err(e) => {
                        self.err = Some(e);
                        Self::show_window(ctx);
                    }
                }
            } else if ev.id() == &ids.off {
                self.disconnect();
            }
        }
    }

    fn apply_invite(&mut self) {
        self.err = None;
        let uri = self.cfg.from_invite.trim();
        let pass = self.cfg.invite_passphrase.as_str();
        if uri.is_empty() || pass.trim().is_empty() {
            self.err = Some("Укажите ключ biba:// и passphrase.".into());
            return;
        }
        match decode_invite_v1(uri, pass) {
            Ok(inv) => {
                self.cfg.server = inv.server;
                self.cfg.sni = inv.sni;
                self.cfg.token = inv.token;
                self.cfg.psk = inv.psk.unwrap_or_default();
                self.cfg.decoy_max = inv.decoy_max;
                self.cfg.max_pad = inv.max_pad;
                self.cfg.max_ws_binary = inv.max_ws_binary;
                self.cfg.ws_ping_secs = inv.ws_ping_secs;
                self.cfg.insecure = inv.insecure;
                self.cfg.tls_profile = inv.tls_profile;
                self.cfg.ws_path = inv.ws_path.clone().unwrap_or_default();
                self.cfg.pad_mode = inv.pad_mode.clone().unwrap_or_default();
                self.cfg.dummy_interval_secs = inv.dummy_interval_secs.unwrap_or(0);
                self.cfg.ws_ping_jitter_percent = inv.ws_ping_jitter_percent;
                self.cfg.ws_binary_send_jitter_ms = inv.ws_binary_send_jitter_ms;
                self.cfg.udp_max_pad = inv
                    .udp_max_pad
                    .map(|x| x.to_string())
                    .unwrap_or_default();
                self.cfg.udp_max_ws_binary = inv
                    .udp_max_ws_binary
                    .map(|x| x.to_string())
                    .unwrap_or_default();
                self.cfg.udp_mux_reply_timeout_secs =
                    inv.udp_mux_reply_timeout_secs.to_string();
                save_config(&self.cfg);
            }
            Err(e) => self.err = Some(format!("Ключ: {e:#}")),
        }
    }

    fn disconnect(&mut self) {
        self.err = None;
        self.tunnel_server = None;
        if let Some(backup) = self.proxy_backup.take() {
            if let Err(e) = restore(&backup) {
                self.err = Some(format!("Прокси: восстановление: {e}"));
            }
        }
        if let Some(vpn) = self.vpn.take() {
            vpn.stop(&self.rt);
        }
        self.sync_tray_tooltip();
    }

    fn connect(&mut self) -> Result<(), String> {
        // Сначала рвём старый туннель — иначе в форме новый сервер, а трафик всё ещё через старый.
        if self.vpn.is_some() {
            self.disconnect();
            // Дождаться снятия HTTP-listener (см. local_client: цикл accept завершается по shutdown).
            std::thread::sleep(Duration::from_millis(300));
        }
        self.err = None;

        if !self.cfg.can_connect() {
            return Err(
                "Укажите сервер и токен или ключ biba:// и passphrase (как в приложении Android)."
                    .into(),
            );
        }

        let http_port = self.cfg.local_http_port;
        let socks_port = if self.cfg.local_socks_port == 0 {
            http_port.saturating_add(1)
        } else {
            self.cfg.local_socks_port
        };
        if socks_port == http_port {
            return Err(
                "Порт SOCKS5 должен отличаться от HTTP (или оставьте SOCKS = 0 для HTTP+1)."
                    .into(),
            );
        }
        let http_bind = format!("127.0.0.1:{http_port}");
        let socks_bind = format!("127.0.0.1:{socks_port}");

        save_config(&self.cfg);

        let backup = read_backup().map_err(|e| e.to_string())?;
        let json = self.cfg.start_config_json()?;
        let opts = local_client_options_from_json_str_with_binds(
            &json,
            socks_bind,
            Some(http_bind.clone()),
        )
        .map_err(|e| format!("{e:#}"))?;
        let remote_label = format!("{}:{}", opts.server_host, opts.server_port);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join = self.rt.spawn(async move {
            bibavpn::local_client::run_local_client(opts, shutdown_rx, None).await
        });

        std::thread::sleep(Duration::from_millis(220));

        let http_hp = format!("127.0.0.1:{http_port}");
        let socks_hp = format!("127.0.0.1:{socks_port}");
        if let Err(e) = apply_proxy(&http_hp, &socks_hp) {
            let _ = shutdown_tx.send(true);
            let _ = self.rt.block_on(join);
            return Err(format!("Системный прокси: {e}"));
        }

        self.proxy_backup = Some(backup);
        self.vpn = Some(ActiveVpn {
            shutdown: shutdown_tx,
            join,
        });
        self.tunnel_server = Some(remote_label);
        self.sync_tray_tooltip();
        Ok(())
    }

    fn shutdown_app(&mut self) {
        self.disconnect();
        self.exiting = true;
    }

    fn round_glyph_btn(&self, ui: &mut egui::Ui, t: Theme, glyph: &str) -> egui::Response {
        ui.add(
            egui::Button::new(
                RichText::new(glyph)
                    .size(18.0)
                    .color(Color32::from_rgba_unmultiplied(0xE2, 0xE8, 0xF0, 225)),
            )
            .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 8))
            .stroke(Stroke::new(1.0, t.border_subtle))
            .min_size(Vec2::splat(40.0))
            .rounding(Rounding::same(20.0)),
        )
    }

    fn status_dot(&self, ui: &mut egui::Ui, t: Theme, active: bool) {
        let (rect, _resp) = ui.allocate_exact_size(Vec2::splat(18.0), egui::Sense::hover());
        let c = rect.center();
        let p = ui.painter();
        if active {
            p.circle_filled(
                c,
                9.0,
                Color32::from_rgba_unmultiplied(0x00, 0xFF, 0xA3, 90),
            );
        }
        p.circle_filled(
            c,
            5.0,
            if active { t.mint_soft } else { t.text_muted },
        );
    }

    /// Главный экран по `DESIGN.md` / Android `HomeScreen`.
    fn draw_home_screen(&mut self, ui: &mut egui::Ui, t: Theme, r_card: Rounding) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if self.round_glyph_btn(ui, t, "\u{2699}").clicked() {
                self.show_settings = true;
            }
            if let Some(ref tex) = self.wordmark {
                ui.add(
                    egui::Image::new((tex.id(), tex.size_vec2()))
                        .max_height(36.0)
                        .maintain_aspect_ratio(true),
                );
            } else {
                ui.label(
                    RichText::new("BibaVPN")
                        .size(22.0)
                        .strong()
                        .color(t.text_primary),
                );
            }
            ui.add_space(40.0);
        });

        ui.add_space(24.0);

        egui::Frame::none()
            .fill(t.card_bg)
            .rounding(r_card)
            .stroke(Stroke::new(1.0, t.border_subtle))
            .inner_margin(Margin::same(20.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    self.status_dot(ui, t, self.vpn.is_some());
                    ui.add_space(8.0);
                    ui.vertical(|ui| {
                        let on = self.vpn.is_some();
                        ui.label(
                            RichText::new(if on {
                                "Подключено"
                            } else {
                                "Не подключено"
                            })
                            .size(20.0)
                            .strong()
                            .color(Color32::WHITE),
                        );
                        ui.add_space(12.0);
                        let sub = if on {
                            format!(
                                "{} · системный прокси",
                                display_host_line(&self.cfg)
                            )
                        } else {
                            "Нажмите «Подключить», чтобы включить прокси".to_string()
                        };
                        ui.label(
                            RichText::new(sub)
                                .size(14.0)
                                .color(Color32::from_rgba_unmultiplied(0xE2, 0xE8, 0xF0, 215)),
                        );
                    });
                });
            });

        ui.add_space(40.0);

        let can_disconnect = self.vpn.is_some();
        let config_ok = self.cfg.can_connect();
        let cta_enabled = can_disconnect || config_ok;
        let cta_alpha = if cta_enabled { 1.0 } else { 0.55 };

        let row_h = 72.0;
        let full_w = ui.available_width();
        let (rect, response) =
            ui.allocate_exact_size(Vec2::new(full_w, row_h), egui::Sense::click());
        let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
        if ui.is_rect_visible(rect) {
            let mut top = t.cta_top;
            let mut bot = t.cta_bottom;
            if !cta_enabled {
                top = top.gamma_multiply(cta_alpha);
                bot = bot.gamma_multiply(cta_alpha);
            }
            paint_vertical_gradient_rect(ui.painter(), rect, top, bot);
            ui.painter().rect_stroke(
                rect,
                Rounding::same(28.0),
                Stroke::new(1.0, t.main_btn_border),
            );
        }
        if cta_enabled && response.clicked() {
            if can_disconnect {
                self.disconnect();
            } else {
                match self.connect() {
                    Ok(()) => {}
                    Err(e) => self.err = Some(e),
                }
            }
        }
        ui.allocate_ui_at_rect(rect, |ui| {
            ui.set_min_size(rect.size());
            ui.horizontal_centered(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (sq_rect, _) =
                        ui.allocate_exact_size(Vec2::splat(48.0), egui::Sense::hover());
                    let p = ui.painter_at(sq_rect);
                    p.rect_stroke(
                        sq_rect,
                        Rounding::same(16.0),
                        Stroke::new(1.0, Color32::from_rgba_unmultiplied(0x00, 0xFF, 0xA3, 90)),
                    );
                    p.rect_filled(
                        sq_rect.shrink(1.0),
                        Rounding::same(15.0),
                        Color32::from_rgba_unmultiplied(0x00, 0xFF, 0xA3, 30),
                    );
                    p.circle_filled(
                        sq_rect.center(),
                        6.0,
                        t.mint_soft.linear_multiply(cta_alpha),
                    );
                    ui.add_space(16.0);
                    ui.vertical(|ui| {
                        ui.add_space(10.0);
                        let title = if can_disconnect {
                            "Отключить"
                        } else {
                            "Подключить"
                        };
                        ui.label(
                            RichText::new(title)
                                .size(22.0)
                                .strong()
                                .color(Color32::WHITE.linear_multiply(cta_alpha)),
                        );
                        ui.add_space(8.0);
                        let sub = if can_disconnect {
                            "Защищено · отключить прокси"
                        } else {
                            "Трафик через локальный HTTP + SOCKS и системный прокси"
                        };
                        ui.label(
                            RichText::new(sub)
                                .size(14.0)
                                .color(Color32::from_rgba_unmultiplied(0x60, 0xA5, 0xFA, 190)
                                    .linear_multiply(cta_alpha)),
                        );
                    });
                    ui.add_space(24.0);
                });
            });
        });

        ui.add_space(32.0);

        let server_click = egui::Frame::none()
            .fill(t.card_bg)
            .rounding(Rounding::same(24.0))
            .stroke(Stroke::new(1.0, t.border_subtle))
            .inner_margin(Margin::same(16.0))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("SERVER")
                            .size(11.0)
                            .strong()
                            .color(t.text_muted),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(display_host_line(&self.cfg))
                                    .size(18.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(server_card_subtitle(&self.cfg))
                                    .size(14.0)
                                    .color(t.text_muted),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new("›")
                                    .size(22.0)
                                    .color(Color32::from_rgba_unmultiplied(0x94, 0xA3, 0xB8, 140)),
                            );
                        });
                    });
                });
            })
            .response;
        if server_click.clicked() {
            self.show_settings = true;
        }

        if self.vpn.is_some() {
            if let Some(ref active) = self.tunnel_server {
                let invite_mode = !self.cfg.from_invite.trim().is_empty()
                    && !self.cfg.invite_passphrase.trim().is_empty();
                if !invite_mode && self.cfg.server.trim() != active.trim() {
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new("Адрес сервера изменился — нажмите «Отключить», затем «Подключить».")
                            .size(12.0)
                            .color(t.state_warning),
                    );
                }
            }
        }

        if let Some(ref active) = self.tunnel_server {
            if self.vpn.is_some() {
                ui.add_space(12.0);
                ui.label(
                    RichText::new(format!("Активный сервер: {active}"))
                        .size(13.0)
                        .color(t.mint_soft),
                );
            }
        }

        if let Some(ref e) = self.err {
            ui.add_space(12.0);
            ui.label(RichText::new(e).color(t.state_danger).size(13.0));
        }
        ui.add_space(24.0);
    }

    /// Экран настроек (поля + дополнительно), как Android `SettingsScreen`.
    fn draw_settings_screen(&mut self, ui: &mut egui::Ui, t: Theme) {
        let r_settings = Rounding::same(28.0);
        ui.horizontal(|ui| {
            if self.round_glyph_btn(ui, t, "←").clicked() {
                self.show_settings = false;
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new("Настройки")
                    .size(18.0)
                    .strong()
                    .color(t.text_primary),
            );
        });
        ui.add_space(20.0);

        egui::Frame::none()
            .fill(Color32::from_rgba_unmultiplied(0x12, 0x18, 0x26, 235))
            .rounding(r_settings)
            .stroke(Stroke::new(1.0, t.border_subtle))
            .inner_margin(Margin::same(20.0))
            .show(ui, |ui| {
                group_heading(ui, t, "Ключ Biba (как в Android)");
                field_heading(ui, t, "biba://…");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cfg.from_invite).desired_width(f32::INFINITY),
                );
                field_heading(ui, t, "Passphrase");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cfg.invite_passphrase)
                        .desired_width(f32::INFINITY)
                        .password(true),
                );
                ui.add_space(6.0);
                let inv_btn = egui::Button::new(
                    RichText::new("Применить к полям").size(14.0).color(t.mint),
                )
                .fill(Color32::from_rgba_unmultiplied(0x00, 0xFF, 0xA3, 50))
                .rounding(Rounding::same(14.0));
                let w = ui.available_width();
                if ui.add_sized(egui::vec2(w, 40.0), inv_btn).clicked() {
                    self.apply_invite();
                }

                group_heading(ui, t, "Подключение");
                field_heading(ui, t, "Сервер");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cfg.server).desired_width(f32::INFINITY),
                );

                group_heading(ui, t, "Учётные данные");
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        field_heading(ui, t, "Токен");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.token)
                                .desired_width(f32::INFINITY),
                        );
                    });
                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        field_heading(ui, t, "SNI");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.sni)
                                .desired_width(f32::INFINITY),
                        );
                    });
                });
                ui.add_space(4.0);
                field_heading(ui, t, "PSK");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cfg.psk)
                        .desired_width(f32::INFINITY)
                        .password(true),
                );
                ui.add_space(4.0);
                ui.checkbox(&mut self.cfg.insecure, "Без проверки TLS (insecure)");

                group_heading(ui, t, "Локальные порты");
                ui.horizontal(|ui| {
                    ui.label(RichText::new("HTTP").size(12.0).color(t.text_muted));
                    ui.add(
                        egui::DragValue::new(&mut self.cfg.local_http_port).range(1024..=65533),
                    );
                    ui.add_space(16.0);
                    ui.label(RichText::new("SOCKS").size(12.0).color(t.text_muted));
                    ui.add(
                        egui::DragValue::new(&mut self.cfg.local_socks_port).range(0..=65535),
                    );
                    ui.add_space(8.0);
                    ui.label(RichText::new("0 = HTTP+1").size(11.0).color(t.text_muted));
                });
            });

        ui.add_space(16.0);

        egui::CollapsingHeader::new(RichText::new("Дополнительно").strong().color(t.label_sky))
            .default_open(false)
            .show(ui, |ui| {
                egui::Frame::none()
                    .fill(Color32::from_rgba_unmultiplied(0x12, 0x18, 0x26, 235))
                    .rounding(r_settings)
                    .stroke(Stroke::new(1.0, t.border_subtle))
                    .inner_margin(Margin::same(20.0))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("Параметры обмена (как в Android / bibavpn-client)")
                                .size(12.0)
                                .color(t.text_muted),
                        );
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("max-pad").size(12.0).color(t.text_muted));
                            ui.add(egui::DragValue::new(&mut self.cfg.max_pad).range(0..=255));
                            ui.add_space(12.0);
                            ui.label(RichText::new("decoy-max").size(12.0).color(t.text_muted));
                            ui.add(egui::DragValue::new(&mut self.cfg.decoy_max).range(0..=255));
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("junk-frames").size(12.0).color(t.text_muted));
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.junk_frames).range(0..=1_000_000),
                            );
                            ui.add_space(12.0);
                            ui.label(RichText::new("early-ws").size(12.0).color(t.text_muted));
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.early_ws_frames).range(0..=255),
                            );
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("max-ws-binary")
                                    .size(12.0)
                                    .color(t.text_muted),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.max_ws_binary)
                                    .range(1024..=4_194_304)
                                    .speed(1024),
                            );
                            ui.add_space(12.0);
                            ui.label(RichText::new("ws-ping, с").size(12.0).color(t.text_muted));
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.ws_ping_secs).range(0..=3600),
                            );
                        });
                        ui.add_space(10.0);
                        ui.checkbox(&mut self.cfg.use_tcp_mux, "TCP multiplex (use_tcp_mux)");
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("ws_path").size(12.0).color(t.text_muted));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.ws_path)
                                    .hint_text("/ws")
                                    .desired_width(200.0),
                            );
                            ui.add_space(12.0);
                            ui.label(RichText::new("pad_mode").size(12.0).color(t.text_muted));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.pad_mode)
                                    .hint_text("random / http-buckets")
                                    .desired_width(180.0),
                            );
                        });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("ping jitter %")
                                    .size(12.0)
                                    .color(t.text_muted),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.ws_ping_jitter_percent)
                                    .range(0..=50),
                            );
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new("binary jitter ms")
                                    .size(12.0)
                                    .color(t.text_muted),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.ws_binary_send_jitter_ms)
                                    .range(0..=255),
                            );
                            ui.add_space(12.0);
                            ui.label(
                                RichText::new("dummy interval, с")
                                    .size(12.0)
                                    .color(t.text_muted),
                            );
                            ui.add(
                                egui::DragValue::new(&mut self.cfg.dummy_interval_secs)
                                    .range(0..=86_400),
                            );
                        });
                        ui.add_space(10.0);
                        ui.checkbox(&mut self.cfg.decoy_gets, "Decoy HTTPS GET (decoy_gets)");
                        if self.cfg.decoy_gets {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("interval, с")
                                        .size(12.0)
                                        .color(t.text_muted),
                                );
                                ui.add(
                                    egui::DragValue::new(&mut self.cfg.decoy_gets_interval_secs)
                                        .range(1..=3600),
                                );
                            });
                            field_heading(ui, t, "decoy_gets_paths (через запятую)");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.decoy_gets_paths)
                                    .desired_width(f32::INFINITY),
                            );
                        }
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("UDP mux (пусто = по умолчанию)")
                                .size(12.0)
                                .color(t.text_muted),
                        );
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("udp_max_pad").size(12.0).color(t.text_muted));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.udp_max_pad)
                                    .desired_width(72.0),
                            );
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new("udp_max_ws_binary")
                                    .size(12.0)
                                    .color(t.text_muted),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.udp_max_ws_binary)
                                    .desired_width(96.0),
                            );
                            ui.add_space(10.0);
                            ui.label(
                                RichText::new("udp_mux_timeout")
                                    .size(12.0)
                                    .color(t.text_muted),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.udp_mux_reply_timeout_secs)
                                    .desired_width(96.0),
                            );
                        });
                        ui.add_space(8.0);
                        field_heading(ui, t, "pin_cert_pem (один или несколько PEM)");
                        ui.add(
                            egui::TextEdit::multiline(&mut self.cfg.pin_cert_pem)
                                .desired_width(f32::INFINITY)
                                .desired_rows(4),
                        );
                        ui.add_space(8.0);
                        field_heading(ui, t, "ws_headers (строка: Header: value)");
                        ui.add(
                            egui::TextEdit::multiline(&mut self.cfg.ws_headers)
                                .desired_width(f32::INFINITY)
                                .desired_rows(3),
                        );
                        ui.add_space(8.0);
                        ui.label(RichText::new("tls-profile").size(12.0).color(t.text_muted));
                        ui.add_space(6.0);
                        egui::ComboBox::from_id_salt("tls_profile_set")
                            .width(320.0)
                            .selected_text(match self.cfg.tls_profile.as_str() {
                                "default" => "По умолчанию (rustls)",
                                "chrome70" => "Chrome 70",
                                "firefox65" => "Firefox 65",
                                "firefox63" => "Firefox 63",
                                "randomized" => "Randomized",
                                "randomized-alpn" => "Randomized + ALPN",
                                "randomized-no-alpn" => "Randomized без ALPN",
                                other => other,
                            })
                            .show_ui(ui, |ui| {
                                for (val, label) in [
                                    ("default", "По умолчанию (rustls)"),
                                    ("chrome70", "Chrome 70"),
                                    ("firefox65", "Firefox 65"),
                                    ("firefox63", "Firefox 63"),
                                    ("randomized", "Randomized"),
                                    ("randomized-alpn", "Randomized + ALPN"),
                                    ("randomized-no-alpn", "Randomized без ALPN"),
                                ] {
                                    ui.selectable_value(
                                        &mut self.cfg.tls_profile,
                                        val.to_string(),
                                        label,
                                    );
                                }
                            });
                    });
            });

        if let Some(ref e) = self.err {
            ui.add_space(12.0);
            ui.label(RichText::new(e).color(t.state_danger).size(13.0));
        }
        ui.add_space(24.0);
    }
}

fn setup_style(ctx: &egui::Context) {
    Theme::dark().apply(ctx);
}

impl eframe::App for BibaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.tray_frames_until_icon > 0 {
            self.tray_frames_until_icon -= 1;
        } else if self.tray.is_none() && !self.tray_icon_attempted {
            self.tray_icon_attempted = true;
            self.ensure_tray_icon();
        }
        self.poll_tray(ctx);

        if ctx.input(|i| i.viewport().close_requested()) && !self.exiting {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }

        if self.exiting {
            return;
        }

        let t = Theme::dark();
        let r_card = Rounding::same(t.radius_card);

        egui::CentralPanel::default().show(ctx, |ui| {
            let full = ui.max_rect();
            if self.show_settings {
                ui.painter().rect_filled(full, Rounding::ZERO, t.bg_screen);
            } else {
                paint_radial_home_bg(ui.painter(), full);
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Frame::none()
                        .inner_margin(Margin::symmetric(20.0, 0.0))
                        .show(ui, |ui| {
                            if self.show_settings {
                                self.draw_settings_screen(ui, t);
                            } else {
                                self.draw_home_screen(ui, t, r_card);
                            }
                        });
                });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_app();
    }
}

fn build_tray_icon() -> tray_icon::Icon {
    let bytes = include_bytes!("../../branding/biba-vpn-app-icon.png");
    let icon = eframe::icon_data::from_png_bytes(bytes).expect("tray png");
    tray_icon::Icon::from_rgba(icon.rgba, icon.width, icon.height).expect("tray icon")
}

/// Не завершаться при закрытии вкладки Terminal (SIGHUP), не ронять запись в сокеты (SIGPIPE).
#[cfg(unix)]
fn unix_ignore_shell_signals() {
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("BibaVPN panic: {info}");
    }));
    if let Err(e) = run_app() {
        eprintln!("BibaVPN failed to start: {e}");
        std::process::exit(1);
    }
}

fn run_app() -> eframe::Result<()> {
    install_ring_crypto();
    #[cfg(unix)]
    unix_ignore_shell_signals();
    #[cfg(target_os = "macos")]
    proxy_mac::init_process_limits();

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );

    let app_icon = eframe::icon_data::from_png_bytes(include_bytes!(
        "../../branding/biba-vpn-app-icon.png"
    ))
    .expect("window icon");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 720.0])
            .with_min_inner_size([440.0, 580.0])
            .with_title("BibaVPN")
            .with_icon(app_icon),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };

    eframe::run_native(
        "BibaVPN",
        options,
        Box::new(move |cc| Ok(Box::new(BibaApp::new(cc, rt)) as Box<dyn eframe::App>)),
    )
}
