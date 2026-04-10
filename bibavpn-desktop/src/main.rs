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

use bibavpn::local_client::{
    parse_host_port, LocalClientOptions, DEFAULT_CLIENT_MAX_WS_BINARY,
    DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
};
use bibavpn::tls_util::install_ring_crypto;
use bibavpn::TlsClientProfile;
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
    #[serde(default)]
    decoy_max: u8,
    /// Как `--max-ws-binary`, верхняя граница размера WS binary.
    #[serde(default = "default_max_ws_binary_cfg")]
    max_ws_binary: usize,
    /// Как `--tls-profile` у bibavpn-client.
    #[serde(default = "default_tls_profile_cfg")]
    tls_profile: String,
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
            decoy_max: 0,
            max_ws_binary: default_max_ws_binary_cfg(),
            tls_profile: default_tls_profile_cfg(),
        }
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

fn default_max_ws_binary_cfg() -> usize {
    DEFAULT_CLIENT_MAX_WS_BINARY
}

fn default_tls_profile_cfg() -> String {
    "default".to_string()
}

/// Токены из `DESIGN.md` §3–4 (тёмная тема, один акцент).
#[derive(Clone, Copy)]
struct Theme {
    bg_app: Color32,
    bg_surface: Color32,
    bg_elevated: Color32,
    border_subtle: Color32,
    text_primary: Color32,
    text_secondary: Color32,
    text_accent: Color32,
    accent_primary: Color32,
    accent_active: Color32,
    state_success: Color32,
    state_warning: Color32,
    state_danger: Color32,
    radius_window: f32,
    radius_card: f32,
    radius_control: f32,
}

impl Theme {
    fn dark() -> Self {
        Self {
            bg_app: Color32::from_rgb(13, 15, 21),
            bg_surface: Color32::from_rgb(21, 24, 32),
            bg_elevated: Color32::from_rgb(30, 34, 45),
            border_subtle: Color32::from_rgba_unmultiplied(255, 255, 255, 14),
            text_primary: Color32::from_rgb(236, 238, 245),
            text_secondary: Color32::from_rgb(145, 150, 168),
            text_accent: Color32::from_rgb(165, 180, 252),
            accent_primary: Color32::from_rgb(99, 102, 241),
            accent_active: Color32::from_rgb(79, 70, 229),
            state_success: Color32::from_rgb(52, 211, 153),
            state_warning: Color32::from_rgb(251, 191, 36),
            state_danger: Color32::from_rgb(251, 113, 133),
            radius_window: 12.0,
            radius_card: 12.0,
            radius_control: 8.0,
        }
    }

    fn apply(self, ctx: &egui::Context) {
        let mut visuals = Visuals::dark();
        visuals.window_fill = self.bg_app;
        visuals.panel_fill = self.bg_surface;
        visuals.extreme_bg_color = self.bg_app;
        visuals.faint_bg_color = self.bg_elevated;
        visuals.widgets.noninteractive.bg_fill = self.bg_elevated;
        visuals.widgets.noninteractive.fg_stroke.color = self.text_secondary;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, self.border_subtle);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(37, 41, 54);
        visuals.widgets.inactive.weak_bg_fill = self.bg_elevated;
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(44, 49, 64);
        visuals.widgets.active.bg_fill = self.accent_active;
        visuals.widgets.open.bg_fill = Color32::from_rgb(40, 44, 60);
        visuals.selection.bg_fill = self.accent_primary;
        visuals.hyperlink_color = self.text_accent;
        visuals.window_stroke = Stroke::new(1.0, self.border_subtle);
        ctx.set_visuals(visuals);

        let r = Rounding::same(self.radius_control);
        let mut style = (*ctx.style()).clone();
        // Масштаб отступов DESIGN.md §2: 8 / 12 / 16 / 20 / 24
        style.spacing.item_spacing = Vec2::new(12.0, 10.0);
        style.spacing.window_margin = Margin::same(20.0);
        style.spacing.button_padding = Vec2::new(20.0, 14.0);
        style.visuals.widgets.noninteractive.rounding = r;
        style.visuals.widgets.inactive.rounding = r;
        style.visuals.widgets.hovered.rounding = r;
        style.visuals.widgets.active.rounding = r;
        style.visuals.window_rounding = Rounding::same(self.radius_window);
        ctx.set_style(style);
    }
}

fn field_heading(ui: &mut egui::Ui, theme: Theme, label: &str) {
    ui.label(
        RichText::new(label)
            .size(12.0)
            .strong()
            .color(theme.text_primary),
    );
    ui.add_space(6.0);
}

fn group_heading(ui: &mut egui::Ui, theme: Theme, label: &str) {
    ui.add_space(4.0);
    ui.label(
        RichText::new(label)
            .size(11.0)
            .strong()
            .color(theme.text_secondary),
    );
    ui.add_space(8.0);
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
        Self {
            cfg,
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

        if self.cfg.server.trim().is_empty() {
            return Err("Укажите адрес сервера (host:port).".into());
        }

        let (host, port) =
            parse_host_port(&self.cfg.server).map_err(|e| format!("Сервер: {e}"))?;
        let sni = if self.cfg.sni.trim().is_empty() {
            host.clone()
        } else {
            self.cfg.sni.trim().to_string()
        };
        let psk = if self.cfg.psk.trim().is_empty() {
            None
        } else {
            Some(self.cfg.psk.trim().to_string())
        };

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
        let remote_label = format!("{host}:{port}");

        let tls_profile: TlsClientProfile = self
            .cfg
            .tls_profile
            .parse()
            .map_err(|e| e.to_string())?;

        let opts = LocalClientOptions {
            server_host: host,
            server_port: port,
            sni,
            token: self.cfg.token.clone(),
            socks_bind,
            http_proxy_bind: Some(http_bind.clone()),
            insecure_tls: self.cfg.insecure,
            max_pad: self.cfg.max_pad,
            junk_frames: 0,
            early_ws_frames: 0,
            psk,
            decoy_max: self.cfg.decoy_max,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_extra_headers: Arc::new(Vec::new()),
            max_ws_binary: self.cfg.max_ws_binary,
            ws_ping_secs: 25,
            ws_ping_jitter_percent: 0,
            ws_binary_send_jitter_ms: 0,
            udp_max_pad: None,
            udp_max_ws_binary: None,
            udp_mux_reply_timeout_secs: DEFAULT_UDP_MUX_REPLY_TIMEOUT_SECS,
            tls_profile,
            pinned_certs_pem: None,
        };

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
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("BibaVPN")
                                    .size(24.0)
                                    .strong()
                                    .color(t.text_primary),
                            );
                            let online = self.vpn.is_some();
                            ui.label(
                                RichText::new(if online {
                                    "Подключено · системный прокси активен"
                                } else {
                                    "Не подключено"
                                })
                                .size(13.0)
                                .color(if online {
                                    t.state_success
                                } else {
                                    t.text_secondary
                                }),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (glyph, color) = if self.vpn.is_some() {
                                ("●", t.state_success)
                            } else {
                                ("○", t.text_secondary)
                            };
                            ui.label(RichText::new(glyph).size(20.0).color(color));
                        });
                    });

                    ui.add_space(20.0);

                    egui::Frame::none()
                        .fill(t.bg_elevated)
                        .rounding(r_card)
                        .stroke(Stroke::new(1.0, t.border_subtle))
                        .inner_margin(Margin::same(20.0))
                        .show(ui, |ui| {
                            group_heading(ui, t, "Подключение");
                            field_heading(ui, t, "Сервер");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.server)
                                    .desired_width(f32::INFINITY),
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
                                ui.label(
                                    RichText::new("HTTP")
                                        .size(12.0)
                                        .color(t.text_secondary),
                                );
                                ui.add(
                                    egui::DragValue::new(&mut self.cfg.local_http_port)
                                        .range(1024..=65533),
                                );
                                ui.add_space(16.0);
                                ui.label(
                                    RichText::new("SOCKS")
                                        .size(12.0)
                                        .color(t.text_secondary),
                                );
                                ui.add(
                                    egui::DragValue::new(&mut self.cfg.local_socks_port)
                                        .range(0..=65535),
                                );
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("0 = HTTP+1")
                                        .size(11.0)
                                        .color(t.text_secondary),
                                );
                            });
                        });

                    ui.add_space(16.0);

                    egui::CollapsingHeader::new(
                        RichText::new("Дополнительно")
                            .strong()
                            .color(t.text_accent),
                    )
                    .default_open(false)
                    .show(ui, |ui| {
                        egui::Frame::none()
                            .fill(t.bg_elevated)
                            .rounding(r_card)
                            .stroke(Stroke::new(1.0, t.border_subtle))
                            .inner_margin(Margin::same(20.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("Параметры обмена (как в bibavpn-client)")
                                        .size(12.0)
                                        .color(t.text_secondary),
                                );
                                ui.add_space(12.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("max-pad")
                                            .size(12.0)
                                            .color(t.text_secondary),
                                    );
                                    ui.add(egui::DragValue::new(&mut self.cfg.max_pad).range(0..=255));
                                    ui.add_space(12.0);
                                    ui.label(
                                        RichText::new("decoy-max")
                                            .size(12.0)
                                            .color(t.text_secondary),
                                    );
                                    ui.add(
                                        egui::DragValue::new(&mut self.cfg.decoy_max).range(0..=255),
                                    );
                                });
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("max-ws-binary")
                                            .size(12.0)
                                            .color(t.text_secondary),
                                    );
                                    ui.add(
                                        egui::DragValue::new(&mut self.cfg.max_ws_binary)
                                            .range(1024..=4_194_304)
                                            .speed(1024),
                                    );
                                });
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("tls-profile — шифры и ALPN (biba)")
                                        .size(12.0)
                                        .color(t.text_secondary),
                                );
                                ui.add_space(6.0);
                                egui::ComboBox::from_id_salt("tls_profile")
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

                    ui.add_space(20.0);

                    if self.vpn.is_some() {
                        if let Some(ref active) = self.tunnel_server {
                            if self.cfg.server.trim() != active.trim() {
                                ui.label(
                                    RichText::new(
                                        "Адрес сервера изменился. Нажмите «Переподключить».",
                                    )
                                    .size(12.0)
                                    .color(t.state_warning),
                                );
                                ui.add_space(8.0);
                            }
                        }
                    }

                    ui.horizontal(|ui| {
                        let can_disconnect = self.vpn.is_some();
                        let primary = if can_disconnect {
                            "Переподключить"
                        } else {
                            "Подключить"
                        };
                        let btn = egui::Button::new(RichText::new(primary).size(15.0).strong())
                            .fill(t.accent_primary)
                            .min_size(Vec2::new(168.0, 48.0))
                            .rounding(Rounding::same(t.radius_control));
                        if ui.add(btn).clicked() {
                            match self.connect() {
                                Ok(()) => {}
                                Err(e) => self.err = Some(e),
                            }
                        }
                        let stop = egui::Button::new(RichText::new("Стоп").size(15.0))
                            .fill(t.bg_surface)
                            .stroke(Stroke::new(1.0, t.border_subtle))
                            .min_size(Vec2::new(112.0, 48.0))
                            .rounding(Rounding::same(t.radius_control));
                        if ui.add_enabled(can_disconnect, stop).clicked() {
                            self.disconnect();
                        }
                    });

                    ui.add_space(16.0);
                    if let Some(ref active) = self.tunnel_server {
                        if self.vpn.is_some() {
                            ui.label(
                                RichText::new(format!("Активный сервер: {active}"))
                                    .size(13.0)
                                    .color(t.state_success),
                            );
                        }
                    }

                    if let Some(ref e) = self.err {
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new(e).color(t.state_danger).size(13.0),
                        );
                    }

                    ui.add_space(24.0);
                });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_app();
    }
}

fn build_tray_icon() -> tray_icon::Icon {
    const S: u32 = 64;
    let center = S as f32 * 0.5;
    let r_core = 15.0_f32;
    let r_feather = 5.0_f32;
    let mut rgba = Vec::with_capacity((S * S * 4) as usize);
    for y in 0..S {
        for x in 0..S {
            let cx = x as f32 + 0.5 - center;
            let cy = y as f32 + 0.5 - center;
            let d = (cx * cx + cy * cy).sqrt();
            let a = if d <= r_core {
                255u8
            } else if d <= r_core + r_feather {
                ((1.0 - (d - r_core) / r_feather).clamp(0.0, 1.0) * 255.0) as u8
            } else {
                0u8
            };
            if a == 0 {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
                continue;
            }
            // Яркий розово-малиновый диск, заметный на тёмной полосе меню
            let h = 1.0 - (d / (r_core + r_feather)).min(1.0);
            let r = (255.0 - 10.0 * h) as u8;
            let g = (35.0 + 70.0 * h) as u8;
            let b = (140.0 + 90.0 * (1.0 - h)) as u8;
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    tray_icon::Icon::from_rgba(rgba, S, S).expect("tray icon")
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

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 660.0])
            .with_min_inner_size([440.0, 560.0])
            .with_title("BibaVPN"),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };

    eframe::run_native(
        "BibaVPN",
        options,
        Box::new(move |cc| Ok(Box::new(BibaApp::new(cc, rt)) as Box<dyn eframe::App>)),
    )
}
