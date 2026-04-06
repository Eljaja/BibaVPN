#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod proxy_win;

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use bibavpn::local_client::{
    parse_host_port, LocalClientOptions, DEFAULT_CLIENT_MAX_WS_BINARY,
};
use bibavpn::tls_util::install_ring_crypto;
use eframe::egui::{self, Color32, Margin, RichText, Rounding, Stroke, Vec2, Visuals};
use proxy_win::{restore, apply_proxy, read_backup, ProxyBackup};
use serde::{Deserialize, Serialize};
use tao::event::Event;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, TrayIconBuilder, TrayIconEvent};

#[derive(Debug)]
enum TraySignal {
    Show,
    Exit,
}

#[derive(Debug)]
enum UserEvent {
    Tray(TrayIconEvent),
    Menu(MenuEvent),
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct SavedConfig {
    server: String,
    token: String,
    psk: String,
    sni: String,
    insecure: bool,
    local_http_port: u16,
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

struct BibaApp {
    cfg: SavedConfig,
    rt: Arc<tokio::runtime::Runtime>,
    tray_rx: Receiver<TraySignal>,
    status: String,
    err: Option<String>,
    proxy_backup: Option<ProxyBackup>,
    vpn: Option<ActiveVpn>,
    exiting: bool,
}

impl BibaApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        rt: Arc<tokio::runtime::Runtime>,
        tray_rx: Receiver<TraySignal>,
    ) -> Self {
        setup_style(&cc.egui_ctx);
        let mut cfg = load_config();
        if cfg.local_http_port == 0 {
            cfg.local_http_port = 17_890;
        }
        Self {
            cfg,
            rt,
            tray_rx,
            status: "Не подключено".into(),
            err: None,
            proxy_backup: None,
            vpn: None,
            exiting: false,
        }
    }

    fn disconnect(&mut self) {
        self.err = None;
        if let Some(backup) = self.proxy_backup.take() {
            if let Err(e) = restore(&backup) {
                self.err = Some(format!("Прокси: восстановление: {e}"));
            }
        }
        if let Some(vpn) = self.vpn.take() {
            vpn.stop(&self.rt);
        }
        self.status = "Не подключено".into();
    }

    fn connect(&mut self) -> Result<(), String> {
        self.err = None;
        if self.vpn.is_some() {
            return Ok(());
        }
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
        let socks_port = http_port.saturating_add(1);
        let http_bind = format!("127.0.0.1:{http_port}");
        let socks_bind = format!("127.0.0.1:{socks_port}");

        let backup = read_backup().map_err(|e| e.to_string())?;

        let opts = LocalClientOptions {
            server_host: host,
            server_port: port,
            sni,
            token: self.cfg.token.clone(),
            socks_bind,
            http_proxy_bind: Some(http_bind.clone()),
            insecure_tls: self.cfg.insecure,
            max_pad: 64,
            junk_frames: 0,
            early_ws_frames: 0,
            psk,
            decoy_max: 0,
            ws_host: None,
            ws_origin: None,
            ws_user_agent: None,
            ws_accept_language: None,
            ws_extra_headers: Arc::new(Vec::new()),
            max_ws_binary: DEFAULT_CLIENT_MAX_WS_BINARY,
            ws_ping_secs: 25,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let join = self.rt.spawn(async move {
            bibavpn::local_client::run_local_client(opts, shutdown_rx, None).await
        });

        std::thread::sleep(Duration::from_millis(220));

        let proxy_addr = format!("127.0.0.1:{http_port}");
        if let Err(e) = apply_proxy(&proxy_addr) {
            let _ = shutdown_tx.send(true);
            let _ = self.rt.block_on(join);
            return Err(format!("Системный прокси: {e}"));
        }

        self.proxy_backup = Some(backup);
        self.vpn = Some(ActiveVpn {
            shutdown: shutdown_tx,
            join,
        });
        self.status = format!("Подключено · локальный HTTP {http_bind}");
        save_config(&self.cfg);
        Ok(())
    }

    fn shutdown_app(&mut self) {
        self.disconnect();
        self.exiting = true;
    }
}

fn setup_style(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    let bg = Color32::from_rgb(18, 20, 28);
    let panel = Color32::from_rgb(28, 32, 44);
    visuals.panel_fill = panel;
    visuals.window_fill = bg;
    visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(36, 40, 54);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(44, 50, 68);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(55, 62, 86);
    visuals.widgets.active.bg_fill = Color32::from_rgb(65, 75, 115);
    visuals.selection.bg_fill = Color32::from_rgb(72, 118, 255);
    visuals.hyperlink_color = Color32::from_rgb(130, 175, 255);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(10.0, 10.0);
    style.spacing.window_margin = Margin::same(18.0);
    style.spacing.button_padding = Vec2::new(16.0, 10.0);
    style.visuals.widgets.noninteractive.rounding = Rounding::same(8.0);
    style.visuals.widgets.inactive.rounding = Rounding::same(8.0);
    style.visuals.widgets.hovered.rounding = Rounding::same(8.0);
    style.visuals.widgets.active.rounding = Rounding::same(8.0);
    ctx.set_style(style);
}

impl eframe::App for BibaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(sig) = self.tray_rx.try_recv() {
            match sig {
                TraySignal::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TraySignal::Exit => {
                    self.shutdown_app();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        if ctx.input(|i| i.viewport().close_requested()) && !self.exiting {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }

        if self.exiting {
            return;
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("BibaVPN")
                        .size(26.0)
                        .strong()
                        .color(Color32::from_rgb(200, 210, 245)),
                );
                ui.label(
                    RichText::new("Подключение к вашему серверу и системный HTTP-прокси")
                        .size(13.0)
                        .color(Color32::from_rgb(160, 168, 190)),
                );
                ui.add_space(16.0);

                egui::Frame::none()
                    .fill(Color32::from_rgb(32, 36, 50))
                    .rounding(Rounding::same(12.0))
                    .stroke(Stroke::new(
                        1.0,
                        Color32::from_rgba_unmultiplied(80, 100, 160, 80),
                    ))
                    .inner_margin(Margin::same(16.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("Параметры сервера").strong());
                        ui.add_space(8.0);

                        ui.label("Адрес (host:port)");
                        ui.text_edit_singleline(&mut self.cfg.server);

                        ui.label("Токен");
                        ui.text_edit_singleline(&mut self.cfg.token);

                        ui.label("PSK (если включён на сервере)");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.cfg.psk).password(true),
                        );

                        ui.label("SNI (пусто = как host)");
                        ui.text_edit_singleline(&mut self.cfg.sni);

                        ui.checkbox(&mut self.cfg.insecure, "Insecure TLS (только для тестов)");

                        ui.label("Локальный порт HTTP CONNECT");
                        ui.add(
                            egui::DragValue::new(&mut self.cfg.local_http_port)
                                .range(1024..=65533)
                                .suffix(" → SOCKS на +1"),
                        );
                    });

                ui.add_space(14.0);

                let can_connect = self.vpn.is_none();
                let can_disconnect = self.vpn.is_some();

                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            can_connect,
                            egui::Button::new(RichText::new("Подключить").size(15.0).strong())
                                .min_size(Vec2::new(140.0, 40.0)),
                        )
                        .clicked()
                    {
                        match self.connect() {
                            Ok(()) => {}
                            Err(e) => self.err = Some(e),
                        }
                    }
                    if ui
                        .add_enabled(
                            can_disconnect,
                            egui::Button::new(RichText::new("Отключить").size(15.0)),
                        )
                        .clicked()
                    {
                        self.disconnect();
                    }
                });

                ui.add_space(12.0);

                let st_color = if self.vpn.is_some() {
                    Color32::from_rgb(110, 220, 150)
                } else {
                    Color32::from_rgb(180, 185, 200)
                };
                ui.label(RichText::new(&self.status).color(st_color).size(14.0));

                if let Some(ref e) = self.err {
                    ui.label(RichText::new(e).color(Color32::from_rgb(255, 140, 140)).size(13.0));
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Сворачивание в трей: нажмите ✕ у окна (процесс не завершается). ЛКМ по иконке — показать окно; ПКМ — меню «Открыть» / «Выход».",
                    )
                    .size(11.0)
                    .color(Color32::from_rgb(120, 125, 145)),
                );
            });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.shutdown_app();
    }
}

fn build_tray_icon() -> tray_icon::Icon {
    const S: u32 = 32;
    let mut rgba = Vec::with_capacity((S * S * 4) as usize);
    for y in 0..S {
        for x in 0..S {
            let cx = x as f32 - (S as f32) * 0.5 + 0.5;
            let cy = y as f32 - (S as f32) * 0.5 + 0.5;
            let r0 = 12.0_f32;
            let d = (cx * cx + cy * cy).sqrt();
            let a = if d < r0 {
                255
            } else if d < r0 + 2.5 {
                (((r0 + 2.5 - d) / 2.5) * 255.0) as u8
            } else {
                0
            };
            let t = (x + y) as f32 * 0.04;
            let r = (55.0_f32 + (t * 40.0).sin() * 30.0) as u8;
            let g = (100.0_f32 + (t * 50.0).cos() * 35.0) as u8;
            let b = (230_u8).saturating_sub((d * 4.0) as u8);
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    tray_icon::Icon::from_rgba(rgba, S, S).expect("tray icon")
}

fn run_tray_thread(tx: Sender<TraySignal>) {
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

    let proxy = event_loop.create_proxy();
    TrayIconEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Tray(event));
    }));
    let proxy = event_loop.create_proxy();
    MenuEvent::set_event_handler(Some(move |event| {
        let _ = proxy.send_event(UserEvent::Menu(event));
    }));

    let tray_menu = Menu::new();
    let open_i = MenuItem::new("Открыть", true, None);
    let quit_i = MenuItem::new("Выход", true, None);
    let _ = tray_menu.append_items(&[
        &open_i,
        &PredefinedMenuItem::separator(),
        &quit_i,
    ]);

    let mut tray_holder: Option<tray_icon::TrayIcon> = None;
    let tx_menu = tx.clone();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(tao::event::StartCause::Init) => {
                let icon = build_tray_icon();
                tray_holder = Some(
                    TrayIconBuilder::new()
                        .with_menu_on_left_click(false)
                        .with_tooltip("BibaVPN")
                        .with_menu(Box::new(tray_menu.clone()))
                        .with_icon(icon)
                        .build()
                        .expect("tray"),
                );
            }

            Event::UserEvent(UserEvent::Tray(ev)) => {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    ..
                } = ev
                {
                    let _ = tx.send(TraySignal::Show);
                }
            }

            Event::UserEvent(UserEvent::Menu(ev)) => {
                if quit_i.id() == &ev.id {
                    tray_holder.take();
                    let _ = tx.send(TraySignal::Exit);
                    *control_flow = ControlFlow::Exit;
                    return;
                }
                if open_i.id() == &ev.id {
                    let _ = tx_menu.send(TraySignal::Show);
                }
            }

            _ => {}
        }
    });
}

fn main() -> eframe::Result<()> {
    install_ring_crypto();

    let (tray_tx, tray_rx) = mpsc::channel::<TraySignal>();
    std::thread::spawn({
        let tray_tx = tray_tx.clone();
        move || run_tray_thread(tray_tx)
    });

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 560.0])
            .with_min_inner_size([400.0, 520.0])
            .with_title("BibaVPN"),
        ..Default::default()
    };

    eframe::run_native(
        "BibaVPN",
        options,
        Box::new(move |cc| Ok(Box::new(BibaApp::new(cc, rt, tray_rx)) as Box<dyn eframe::App>)),
    )
}
