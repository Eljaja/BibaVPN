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
};
use bibavpn::tls_util::install_ring_crypto;
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
            }
            Err(e) => {
                self.err = Some(format!("Трей: {e}"));
            }
        }
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
        Ok(())
    }

    fn shutdown_app(&mut self) {
        self.disconnect();
        self.exiting = true;
    }
}

fn setup_style(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    let ink = Color32::from_rgb(11, 14, 20);
    let surface = Color32::from_rgb(19, 23, 32);
    let elevated = Color32::from_rgb(28, 33, 45);
    let accent = Color32::from_rgb(99, 102, 241);
    let accent_dim = Color32::from_rgb(67, 71, 182);

    visuals.window_fill = ink;
    visuals.panel_fill = surface;
    visuals.extreme_bg_color = ink;
    visuals.faint_bg_color = elevated;
    visuals.widgets.noninteractive.bg_fill = elevated;
    visuals.widgets.noninteractive.fg_stroke.color = Color32::from_rgb(186, 192, 210);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(38, 43, 58);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(32, 37, 50);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(48, 54, 72);
    visuals.widgets.active.bg_fill = accent_dim;
    visuals.widgets.open.bg_fill = Color32::from_rgb(48, 52, 78);
    visuals.selection.bg_fill = accent;
    visuals.hyperlink_color = Color32::from_rgb(165, 180, 252);
    visuals.window_stroke = Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 20));
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(12.0, 10.0);
    style.spacing.window_margin = Margin::same(20.0);
    style.spacing.button_padding = Vec2::new(18.0, 11.0);
    let r = Rounding::same(10.0);
    style.visuals.widgets.noninteractive.rounding = r;
    style.visuals.widgets.inactive.rounding = r;
    style.visuals.widgets.hovered.rounding = r;
    style.visuals.widgets.active.rounding = r;
    style.visuals.window_rounding = Rounding::same(12.0);
    ctx.set_style(style);
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

        let card_fill = Color32::from_rgb(28, 33, 45);
        let card_line = Color32::from_rgba_unmultiplied(129, 140, 248, 45);
        let accent = Color32::from_rgb(129, 140, 248);
        let muted = Color32::from_rgb(140, 148, 168);

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("BibaVPN")
                                    .size(28.0)
                                    .strong()
                                    .color(Color32::from_rgb(238, 241, 255)),
                            );
                            let online = self.vpn.is_some();
                            ui.label(
                                RichText::new(if online {
                                    "прокси включён"
                                } else {
                                    "офлайн"
                                })
                                .size(13.0)
                                .color(if online {
                                    Color32::from_rgb(134, 239, 172)
                                } else {
                                    muted
                                }),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(if self.vpn.is_some() { "●" } else { "○" })
                                    .size(22.0)
                                    .color(if self.vpn.is_some() {
                                        Color32::from_rgb(74, 222, 128)
                                    } else {
                                        Color32::from_rgb(100, 110, 130)
                                    }),
                            );
                        });
                    });

                    ui.add_space(18.0);

                    egui::Frame::none()
                        .fill(card_fill)
                        .rounding(Rounding::same(14.0))
                        .stroke(Stroke::new(1.0, card_line))
                        .inner_margin(Margin::same(18.0))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("Сервер")
                                    .strong()
                                    .color(Color32::from_rgb(210, 215, 235)),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.server)
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_space(12.0);

                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new("Токен")
                                            .strong()
                                            .color(Color32::from_rgb(210, 215, 235)),
                                    );
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.cfg.token)
                                            .desired_width(f32::INFINITY),
                                    );
                                });
                                ui.add_space(12.0);
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new("SNI")
                                            .strong()
                                            .color(Color32::from_rgb(210, 215, 235)),
                                    );
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.cfg.sni)
                                            .desired_width(f32::INFINITY),
                                    );
                                });
                            });

                            ui.add_space(12.0);
                            ui.label(
                                RichText::new("PSK")
                                    .strong()
                                    .color(Color32::from_rgb(210, 215, 235)),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.cfg.psk)
                                    .desired_width(f32::INFINITY)
                                    .password(true),
                            );
                            ui.add_space(8.0);
                            ui.checkbox(&mut self.cfg.insecure, "insecure TLS");

                            ui.add_space(14.0);
                            ui.label(
                                RichText::new("Порты")
                                    .strong()
                                    .color(Color32::from_rgb(210, 215, 235)),
                            );
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("HTTP").small().color(muted));
                                ui.add(
                                    egui::DragValue::new(&mut self.cfg.local_http_port)
                                        .range(1024..=65533),
                                );
                                ui.label(RichText::new("SOCKS").small().color(muted));
                                ui.add(
                                    egui::DragValue::new(&mut self.cfg.local_socks_port)
                                        .range(0..=65535),
                                );
                                ui.label(RichText::new("(0 = +1)").small().color(muted));
                            });
                        });

                    ui.add_space(12.0);

                    egui::CollapsingHeader::new(RichText::new("Расширенные").strong().color(accent))
                        .default_open(true)
                        .show(ui, |ui| {
                            egui::Frame::none()
                                .fill(card_fill)
                                .rounding(Rounding::same(14.0))
                                .stroke(Stroke::new(1.0, card_line))
                                .inner_margin(Margin::same(16.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("max-pad").small().color(muted));
                                        ui.add(egui::DragValue::new(&mut self.cfg.max_pad).range(0..=255));
                                        ui.add_space(8.0);
                                        ui.label(RichText::new("decoy-max").small().color(muted));
                                        ui.add(egui::DragValue::new(&mut self.cfg.decoy_max).range(0..=255));
                                    });
                                    ui.add_space(8.0);
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("max-ws-binary").small().color(muted));
                                        ui.add(
                                            egui::DragValue::new(&mut self.cfg.max_ws_binary)
                                                .range(1024..=4_194_304)
                                                .speed(1024),
                                        );
                                    });
                                });
                        });

                    ui.add_space(16.0);

                    if self.vpn.is_some() {
                        if let Some(ref active) = self.tunnel_server {
                            if self.cfg.server.trim() != active.trim() {
                                ui.label(
                                    RichText::new("Адрес изменён — жми переподключить.")
                                        .size(12.0)
                                        .color(Color32::from_rgb(251, 191, 36)),
                                );
                                ui.add_space(6.0);
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
                            .fill(accent)
                            .min_size(Vec2::new(152.0, 44.0))
                            .rounding(Rounding::same(11.0));
                        if ui.add(btn).clicked() {
                            match self.connect() {
                                Ok(()) => {}
                                Err(e) => self.err = Some(e),
                            }
                        }
                        if ui
                            .add_enabled(
                                can_disconnect,
                                egui::Button::new(RichText::new("Стоп").size(15.0))
                                    .min_size(Vec2::new(100.0, 44.0))
                                    .rounding(Rounding::same(11.0)),
                            )
                            .clicked()
                        {
                            self.disconnect();
                        }
                    });

                    ui.add_space(12.0);
                    if let Some(ref active) = self.tunnel_server {
                        if self.vpn.is_some() {
                            ui.label(
                                RichText::new(format!("туннель · {active}"))
                                    .size(13.0)
                                    .color(Color32::from_rgb(167, 243, 208)),
                            );
                        }
                    }

                    if let Some(ref e) = self.err {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(e)
                                .color(Color32::from_rgb(252, 165, 165))
                                .size(13.0),
                        );
                    }
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
            .with_inner_size([460.0, 620.0])
            .with_min_inner_size([420.0, 540.0])
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
