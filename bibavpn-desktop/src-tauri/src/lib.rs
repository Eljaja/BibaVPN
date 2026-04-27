//! BibaVPN Tauri backend — desktop (Windows/macOS/Linux) and mobile (Android) library target.

mod config;
#[cfg(not(target_os = "android"))]
mod locale;
mod logging;
mod split_tunnel;

#[cfg(target_os = "macos")]
mod proxy_mac;
#[cfg(all(unix, not(target_os = "android")))]
mod proxy_stub;
#[cfg(target_os = "android")]
mod proxy_android;
#[cfg(windows)]
mod proxy_win;

#[cfg(target_os = "macos")]
use proxy_mac::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(all(unix, not(target_os = "android")))]
use proxy_stub::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(target_os = "android")]
use proxy_android::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(windows)]
use proxy_win::{apply_proxy, read_backup, restore, ProxyBackup};

#[cfg(target_os = "android")]
mod android_vpn;

use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bibavpn::decode_invite_v1;
use bibavpn::local_client_options_from_json_str_with_binds;
use bibavpn::tls_util::install_ring_crypto;
use config::{
    display_host_line, load_config_disk, normalize_loaded, save_config_disk, server_card_subtitle,
    SavedConfig,
};
#[cfg(not(target_os = "android"))]
use locale::{resolved_tray_lang, tray_strings};
use serde::Serialize;
#[cfg(not(target_os = "android"))]
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
#[cfg(not(target_os = "android"))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State};
#[cfg(not(target_os = "android"))]
use tauri::{include_image, WindowEvent, Wry};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

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

pub(crate) struct Inner {
    cfg: SavedConfig,
    proxy_backup: Option<ProxyBackup>,
    vpn: Option<ActiveVpn>,
    tunnel_server: Option<String>,
    last_error: Option<String>,
}

pub struct AppState {
    pub rt: Arc<tokio::runtime::Runtime>,
    pub inner: Mutex<Inner>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ClientCapabilities {
    boring_tls_available: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StateSnapshot {
    cfg: SavedConfig,
    connected: bool,
    display_host: String,
    server_subtitle: String,
    tunnel_server: Option<String>,
    error: Option<String>,
    can_connect: bool,
    capabilities: ClientCapabilities,
}

fn snapshot(app: &AppHandle, inner: &Inner) -> StateSnapshot {
    #[cfg(target_os = "android")]
    let connected = android_vpn::tunnel_is_active(app).unwrap_or(false);
    #[cfg(not(target_os = "android"))]
    let connected = {
        let _ = app;
        inner.vpn.is_some()
    };
    StateSnapshot {
        cfg: inner.cfg.clone(),
        connected,
        display_host: display_host_line(&inner.cfg),
        server_subtitle: server_card_subtitle(&inner.cfg),
        tunnel_server: inner.tunnel_server.clone(),
        error: inner.last_error.clone(),
        can_connect: inner.cfg.can_connect(),
        capabilities: ClientCapabilities {
            boring_tls_available: cfg!(feature = "boring-tls"),
        },
    }
}

#[cfg(not(target_os = "android"))]
fn sync_tray_tooltip_i18n(app: &AppHandle, connected: bool, cfg: &SavedConfig) {
    let s = tray_strings(resolved_tray_lang(cfg));
    if let Some(tray) = app.tray_by_id("main-tray") {
        let tip = if connected {
            s.tip_connected
        } else {
            s.tip_disconnected
        };
        let _ = tray.set_tooltip(Some(tip));
    }
}

#[cfg(target_os = "android")]
fn sync_tray_tooltip_i18n(_app: &AppHandle, _connected: bool, _cfg: &SavedConfig) {}

#[cfg(not(target_os = "android"))]
fn build_tray_menu(app: &AppHandle, lang: &str) -> tauri::Result<Menu<Wry>> {
    let s = tray_strings(lang);
    let show = MenuItem::with_id(app, "show", s.show, true, None::<&str>)?;
    let on = MenuItem::with_id(app, "on", s.on, true, None::<&str>)?;
    let off = MenuItem::with_id(app, "off", s.off, true, None::<&str>)?;
    let logs = MenuItem::with_id(app, "logs", s.logs, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", s.quit, true, None::<&str>)?;
    Menu::with_items(
        app,
        &[
            &show,
            &PredefinedMenuItem::separator(app)?,
            &on,
            &off,
            &PredefinedMenuItem::separator(app)?,
            &logs,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )
}

#[cfg(not(target_os = "android"))]
fn apply_tray_menu_locale(app: &AppHandle, cfg: &SavedConfig, connected: bool) -> Result<(), String> {
    let menu = build_tray_menu(app, resolved_tray_lang(cfg)).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main-tray") {
        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    }
    sync_tray_tooltip_i18n(app, connected, cfg);
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn disconnect_inner(state: &AppState, app: &AppHandle) {
    let mut g = match state.inner.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    info!(target: "bibavpn_desktop", "отключение VPN");
    g.last_error = None;
    g.tunnel_server = None;
    #[cfg(target_os = "android")]
    {
        if let Err(e) = android_vpn::request_disconnect(app) {
            warn!(target: "bibavpn_desktop", "android VPN stop: {e}");
            g.last_error = Some(e);
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        if let Some(backup) = g.proxy_backup.take() {
            if let Err(e) = restore(&backup) {
                warn!(target: "bibavpn_desktop", "восстановление системного прокси: {e}");
                g.last_error = Some(format!("Прокси: восстановление: {e}"));
            }
        }
        if let Some(vpn) = g.vpn.take() {
            vpn.stop(&state.rt);
        }
    }
    sync_tray_tooltip_i18n(app, false, &g.cfg);
    let snap = snapshot(app, &g);
    let _ = app.emit("vpn-state", &snap);
}

fn apply_invite_to_cfg(cfg: &mut SavedConfig) -> Result<(), String> {
    let p = cfg
        .active_profile_mut()
        .ok_or_else(|| "Нет активного профиля.".to_string())?;
    let uri = p.from_invite.trim();
    let pass = p.invite_passphrase.as_str();
    if uri.is_empty() || pass.trim().is_empty() {
        return Err("Укажите ключ biba:// и passphrase.".into());
    }
    match decode_invite_v1(uri, pass) {
        Ok(inv) => {
            p.server = inv.server;
            p.sni = inv.sni;
            p.token = inv.token;
            p.psk = inv.psk.unwrap_or_default();
            p.decoy_max = inv.decoy_max;
            p.max_pad = inv.max_pad;
            p.max_ws_binary = inv.max_ws_binary;
            p.ws_ping_secs = inv.ws_ping_secs;
            p.insecure = inv.insecure;
            p.tls_profile = inv.tls_profile;
            p.ws_path = inv.ws_path.clone().unwrap_or_default();
            p.pad_mode = inv.pad_mode.clone().unwrap_or_default();
            p.dummy_interval_secs = inv.dummy_interval_secs.unwrap_or(0);
            p.ws_ping_jitter_percent = inv.ws_ping_jitter_percent;
            p.ws_binary_send_jitter_ms = inv.ws_binary_send_jitter_ms;
            p.udp_max_pad = inv.udp_max_pad.map(|x| x.to_string()).unwrap_or_default();
            p.udp_max_ws_binary = inv
                .udp_max_ws_binary
                .map(|x| x.to_string())
                .unwrap_or_default();
            p.udp_mux_reply_timeout_secs = inv.udp_mux_reply_timeout_secs.to_string();
            Ok(())
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "ключ biba://: {e:#}");
            Err(format!("Ключ: {e:#}"))
        }
    }
}

#[cfg(not(target_os = "android"))]
fn connect_inner(state: &AppState, app: &AppHandle) -> Result<(), String> {
    {
        let g = match state.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if g.vpn.is_some() {
            drop(g);
            disconnect_inner(state, app);
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    let mut g = match state.inner.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.last_error = None;

    if !g.cfg.can_connect() {
        warn!(target: "bibavpn_desktop", "подключение: не заполнены сервер/токен или biba://");
        return Err(
            "Укажите сервер и токен или ключ biba:// и passphrase (как в приложении Android)."
                .into(),
        );
    }

    let http_port = g.cfg.local_http_port;
    let socks_port = if g.cfg.local_socks_port == 0 {
        http_port.saturating_add(1)
    } else {
        g.cfg.local_socks_port
    };
    if socks_port == http_port {
        warn!(target: "bibavpn_desktop", "подключение: совпадают порты HTTP и SOCKS");
        return Err(
            "Порт SOCKS5 должен отличаться от HTTP (или оставьте SOCKS = 0 для HTTP+1).".into(),
        );
    }
    let http_bind = format!("127.0.0.1:{http_port}");
    let socks_bind = format!("127.0.0.1:{socks_port}");

    save_config_disk(&g.cfg);

    let backup = read_backup().map_err(|e| e.to_string())?;
    let json = g.cfg.start_config_json()?;
    let opts =
        local_client_options_from_json_str_with_binds(&json, socks_bind, Some(http_bind.clone()))
            .map_err(|e| format!("{e:#}"))?;
    let remote_label = format!("{}:{}", opts.server_host, opts.server_port);

    let (socks_tx, socks_rx) = std::sync::mpsc::channel::<()>();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let join = state.rt.spawn(async move {
        let out = bibavpn::local_client::run_local_client(opts, shutdown_rx, Some(socks_tx)).await;
        match &out {
            Ok(()) => info!(target: "bibavpn_desktop", "VPN-клиент (bibavpn) завершился"),
            Err(e) => error!(target: "bibavpn_desktop", "VPN-клиент (bibavpn): {e:#}"),
        }
        out
    });

    match socks_rx.recv_timeout(Duration::from_secs(25)) {
        Ok(()) => {
            info!(
                target: "bibavpn_desktop",
                "локальный SOCKS5 слушает, можно применять системный прокси"
            );
        }
        Err(RecvTimeoutError::Timeout) => {
            warn!(
                target: "bibavpn_desktop",
                "таймаут 25 с: SOCKS не поднялся, отмена подключения"
            );
            let _ = shutdown_tx.send(true);
            match state.rt.block_on(join) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(target: "bibavpn_desktop", "клиент после таймаута: {e:#}"),
                Err(e) => error!(target: "bibavpn_desktop", "join клиента: {e}"),
            }
            return Err(
                "Локальный SOCKS не поднялся за 25 с. Смотрите лог в папке BibaVPN\\logs.".into(),
            );
        }
        Err(RecvTimeoutError::Disconnected) => {
            let msg = match state.rt.block_on(join) {
                Ok(Ok(())) => "Клиент завершился до готовности SOCKS.".to_string(),
                Ok(Err(e)) => format!("{e:#}"),
                Err(e) => format!("join: {e}"),
            };
            error!(
                target: "bibavpn_desktop",
                "SOCKS не стартовал (канал закрыт): {msg}"
            );
            return Err(msg);
        }
    }

    let http_hp = format!("127.0.0.1:{http_port}");
    let socks_hp = format!("127.0.0.1:{socks_port}");
    let split_hosts = g
        .cfg
        .active_profile()
        .map(split_tunnel::bypass_domains_for_profile)
        .unwrap_or_default();
    #[cfg(windows)]
    let prior_proxy_override = match backup.override_val.as_deref() {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    };
    #[cfg(windows)]
    let proxy_res = apply_proxy(&http_hp, &socks_hp, prior_proxy_override, &split_hosts);
    #[cfg(target_os = "macos")]
    let proxy_res = apply_proxy(&http_hp, &socks_hp, None, &split_hosts, &backup);
    #[cfg(not(any(windows, target_os = "macos")))]
    let proxy_res = apply_proxy(&http_hp, &socks_hp, None, &split_hosts);
    if let Err(e) = proxy_res {
        warn!(target: "bibavpn_desktop", "системный прокси: {e}");
        let _ = shutdown_tx.send(true);
        let _ = state.rt.block_on(join);
        return Err(format!("Системный прокси: {e}"));
    }

    info!(
        target: "bibavpn_desktop",
        remote = %remote_label,
        http = %http_hp,
        socks = %socks_hp,
        "VPN включён, локальный прокси и системные настройки применены"
    );
    g.proxy_backup = Some(backup);
    g.vpn = Some(ActiveVpn {
        shutdown: shutdown_tx,
        join,
    });
    g.tunnel_server = Some(remote_label);
    sync_tray_tooltip_i18n(app, true, &g.cfg);
    Ok(())
}

#[cfg(target_os = "android")]
fn connect_inner(state: &AppState, app: &AppHandle) -> Result<(), String> {
    if android_vpn::tunnel_is_active(app).unwrap_or(false) {
        disconnect_inner(state, app);
        std::thread::sleep(Duration::from_millis(300));
    }

    let mut g = match state.inner.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.last_error = None;

    if !g.cfg.can_connect() {
        warn!(target: "bibavpn_desktop", "подключение: не заполнены сервер/токен или biba://");
        return Err(
            "Укажите сервер и токен или ключ biba:// и passphrase (как в приложении Android)."
                .into(),
        );
    }

    save_config_disk(&g.cfg);
    let json = g.cfg.start_config_json()?;
    let (split_tunnel_enabled, packages, battery) = match g.cfg.active_profile() {
        Some(p) => (
            p.split_tunnel_enabled,
            p.android_split_tunnel_packages.clone(),
            p.android_screen_off_battery_saver,
        ),
        None => (false, Vec::new(), false),
    };
    let remote_label = display_host_line(&g.cfg);
    drop(g);

    android_vpn::request_connect(
        app,
        &json,
        split_tunnel_enabled,
        &packages,
        battery,
    )?;

    let mut g = match state.inner.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.tunnel_server = Some(remote_label);
    let tray_up = android_vpn::tunnel_is_active(app).unwrap_or(false);
    sync_tray_tooltip_i18n(app, tray_up, &g.cfg);
    Ok(())
}

#[tauri::command]
fn get_state(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(snapshot(&app, &g))
}

#[tauri::command]
fn save_config_cmd(
    cfg: SavedConfig,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<StateSnapshot, String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    let old_locale = g.cfg.ui_locale.clone();
    g.cfg = cfg;
    normalize_loaded(&mut g.cfg);
    let locale_changed = old_locale != g.cfg.ui_locale;
    save_config_disk(&g.cfg);
    #[cfg(not(target_os = "android"))]
    let cfg_for_tray = g.cfg.clone();
    let snap = snapshot(&app, &g);
    #[cfg(not(target_os = "android"))]
    let connected = snap.connected;
    drop(g);
    let _ = app.emit("vpn-state", &snap);
    if locale_changed {
        #[cfg(not(target_os = "android"))]
        if let Err(e) = apply_tray_menu_locale(&app, &cfg_for_tray, connected) {
            warn!(target: "bibavpn_desktop", "обновление меню трея: {e}");
        }
    }
    Ok(snap)
}

#[tauri::command]
fn connect_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    if let Err(e) = connect_inner(&*state, &app) {
        let mut g = state.inner.lock().map_err(|e2| e2.to_string())?;
        g.last_error = Some(e.clone());
        let snap = snapshot(&app, &g);
        let _ = app.emit("vpn-state", &snap);
        return Err(e);
    }
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    let snap = snapshot(&app, &g);
    let _ = app.emit("vpn-state", &snap);
    Ok(snap)
}

#[tauri::command]
fn disconnect_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    disconnect_inner(&*state, &app);
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    let snap = snapshot(&app, &g);
    let _ = app.emit("vpn-state", &snap);
    Ok(snap)
}

#[tauri::command]
fn apply_invite_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.last_error = None;
    match apply_invite_to_cfg(&mut g.cfg) {
        Ok(()) => {
            save_config_disk(&g.cfg);
            let snap = snapshot(&app, &g);
            let _ = app.emit("vpn-state", &snap);
            Ok(snap)
        }
        Err(e) => {
            g.last_error = Some(e.clone());
            let snap = snapshot(&app, &g);
            let _ = app.emit("vpn-state", &snap);
            Err(e)
        }
    }
}

#[tauri::command]
fn clear_error_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.last_error = None;
    let snap = snapshot(&app, &g);
    let _ = app.emit("vpn-state", &snap);
    Ok(snap)
}

#[cfg(unix)]
fn unix_ignore_shell_signals() {
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

#[cfg(not(target_os = "android"))]
fn tray_icon() -> tauri::image::Image<'static> {
    include_image!("icons/32x32.png")
}

/// Desktop + mobile entry (Tauri Android uses the `cdylib` from this crate after `tauri android init`).
pub fn run() -> anyhow::Result<()> {
    let _log_dir = logging::init();
    std::panic::set_hook(Box::new(|info| {
        error!(target: "bibavpn_desktop", "panic: {info}");
        eprintln!("BibaVPN panic: {info}");
    }));

    install_ring_crypto();
    #[cfg(unix)]
    unix_ignore_shell_signals();
    #[cfg(target_os = "macos")]
    proxy_mac::init_process_limits();

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );

    let mut cfg = load_config_disk();
    normalize_loaded(&mut cfg);

    let state = AppState {
        rt: rt.clone(),
        inner: Mutex::new(Inner {
            cfg,
            proxy_backup: None,
            vpn: None,
            tunnel_server: None,
            last_error: None,
        }),
    };

    let mut builder = tauri::Builder::default().manage(state);

    #[cfg(not(target_os = "android"))]
    {
        builder = builder
            .on_window_event(|window, event| {
                if window.label() == "main" {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
            })
            .setup(move |app| {
                let tray_cfg = app
                    .state::<AppState>()
                    .inner
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .cfg
                    .clone();
                let lang = resolved_tray_lang(&tray_cfg);
                let menu = build_tray_menu(&app.handle(), lang)?;
                let ts = tray_strings(lang);

                let icon = tray_icon();
                let _tray = TrayIconBuilder::with_id("main-tray")
                    .tooltip(ts.tip_disconnected)
                    .icon(icon)
                    .menu(&menu)
                    .show_menu_on_left_click(false)
                    .on_menu_event(move |app, event| match event.id.as_ref() {
                        "show" => show_main_window(app),
                        "quit" => {
                            let st = app.state::<AppState>();
                            disconnect_inner(&*st, app);
                            app.exit(0);
                        }
                        "on" => {
                            let st = app.state::<AppState>();
                            let h = app.clone();
                            if let Err(e) = connect_inner(&*st, &h) {
                                warn!(target: "bibavpn_desktop", "подключение из трея: {e}");
                                let mut g = st.inner.lock().unwrap_or_else(|e| e.into_inner());
                                g.last_error = Some(e);
                                let snap = snapshot(&h, &g);
                                let _ = h.emit("vpn-state", &snap);
                                show_main_window(&h);
                            } else {
                                let g = st.inner.lock().unwrap_or_else(|e| e.into_inner());
                                let snap = snapshot(&h, &g);
                                let _ = h.emit("vpn-state", &snap);
                            }
                        }
                        "off" => {
                            let st = app.state::<AppState>();
                            let h = app.clone();
                            disconnect_inner(&*st, &h);
                            let g = st.inner.lock().unwrap_or_else(|e| e.into_inner());
                            let snap = snapshot(&h, &g);
                            let _ = h.emit("vpn-state", &snap);
                        }
                        "logs" => {
                            if let Some(dir) = logging::logs_directory() {
                                logging::open_in_file_manager(dir);
                            } else {
                                warn!(target: "bibavpn_desktop", "каталог логов недоступен");
                            }
                        }
                        _ => {}
                    })
                    .on_tray_icon_event(move |tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            show_main_window(tray.app_handle());
                        }
                    })
                    .build(app)?;

                Ok(())
            });
    }

    #[cfg(target_os = "android")]
    {
        builder = builder.setup(|_app| Ok(()));
    }

    builder
        .invoke_handler(tauri::generate_handler![
            get_state,
            save_config_cmd,
            connect_cmd,
            disconnect_cmd,
            apply_invite_cmd,
            clear_error_cmd,
        ])
        .run(tauri::generate_context!())?;

    Ok(())
}
