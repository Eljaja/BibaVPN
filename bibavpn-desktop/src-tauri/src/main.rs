#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod config;
mod logging;

#[cfg(target_os = "macos")]
mod proxy_mac;
#[cfg(not(any(windows, target_os = "macos")))]
mod proxy_stub;
#[cfg(windows)]
mod proxy_win;

#[cfg(target_os = "macos")]
use proxy_mac::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(not(any(windows, target_os = "macos")))]
use proxy_stub::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(windows)]
use proxy_win::{apply_proxy, read_backup, restore, ProxyBackup};

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
use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIconBuilder, TrayIconEvent};
use tauri::{include_image, AppHandle, Emitter, Manager, State, WindowEvent};
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

struct Inner {
    cfg: SavedConfig,
    proxy_backup: Option<ProxyBackup>,
    vpn: Option<ActiveVpn>,
    tunnel_server: Option<String>,
    last_error: Option<String>,
}

pub struct AppState {
    rt: Arc<tokio::runtime::Runtime>,
    inner: Mutex<Inner>,
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
}

fn snapshot(inner: &Inner) -> StateSnapshot {
    StateSnapshot {
        cfg: inner.cfg.clone(),
        connected: inner.vpn.is_some(),
        display_host: display_host_line(&inner.cfg),
        server_subtitle: server_card_subtitle(&inner.cfg),
        tunnel_server: inner.tunnel_server.clone(),
        error: inner.last_error.clone(),
        can_connect: inner.cfg.can_connect(),
    }
}

fn sync_tray_tooltip(app: &AppHandle, connected: bool) {
    if let Some(tray) = app.tray_by_id("main-tray") {
        let tip = if connected {
            "BibaVPN — подключено"
        } else {
            "BibaVPN — отключено"
        };
        let _ = tray.set_tooltip(Some(tip));
    }
}

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
    if let Some(backup) = g.proxy_backup.take() {
        if let Err(e) = restore(&backup) {
            warn!(target: "bibavpn_desktop", "восстановление системного прокси: {e}");
            g.last_error = Some(format!("Прокси: восстановление: {e}"));
        }
    }
    if let Some(vpn) = g.vpn.take() {
        vpn.stop(&state.rt);
    }
    sync_tray_tooltip(app, false);
    let snap = snapshot(&g);
    let _ = app.emit("vpn-state", &snap);
}

fn apply_invite_to_cfg(cfg: &mut SavedConfig) -> Result<(), String> {
    let uri = cfg.from_invite.trim();
    let pass = cfg.invite_passphrase.as_str();
    if uri.is_empty() || pass.trim().is_empty() {
        return Err("Укажите ключ biba:// и passphrase.".into());
    }
    match decode_invite_v1(uri, pass) {
        Ok(inv) => {
            cfg.server = inv.server;
            cfg.sni = inv.sni;
            cfg.token = inv.token;
            cfg.psk = inv.psk.unwrap_or_default();
            cfg.decoy_max = inv.decoy_max;
            cfg.max_pad = inv.max_pad;
            cfg.max_ws_binary = inv.max_ws_binary;
            cfg.ws_ping_secs = inv.ws_ping_secs;
            cfg.insecure = inv.insecure;
            cfg.tls_profile = inv.tls_profile;
            cfg.ws_path = inv.ws_path.clone().unwrap_or_default();
            cfg.pad_mode = inv.pad_mode.clone().unwrap_or_default();
            cfg.dummy_interval_secs = inv.dummy_interval_secs.unwrap_or(0);
            cfg.ws_ping_jitter_percent = inv.ws_ping_jitter_percent;
            cfg.ws_binary_send_jitter_ms = inv.ws_binary_send_jitter_ms;
            cfg.udp_max_pad = inv.udp_max_pad.map(|x| x.to_string()).unwrap_or_default();
            cfg.udp_max_ws_binary = inv
                .udp_max_ws_binary
                .map(|x| x.to_string())
                .unwrap_or_default();
            cfg.udp_mux_reply_timeout_secs = inv.udp_mux_reply_timeout_secs.to_string();
            Ok(())
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "ключ biba://: {e:#}");
            Err(format!("Ключ: {e:#}"))
        }
    }
}

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
    if let Err(e) = apply_proxy(
        &http_hp,
        &socks_hp,
        backup.override_val.as_deref().filter(|s| !s.is_empty()),
    ) {
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
    sync_tray_tooltip(app, true);
    Ok(())
}

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> Result<StateSnapshot, String> {
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(snapshot(&g))
}

#[tauri::command]
fn save_config_cmd(
    cfg: SavedConfig,
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<StateSnapshot, String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.cfg = cfg;
    normalize_loaded(&mut g.cfg);
    save_config_disk(&g.cfg);
    let snap = snapshot(&g);
    let _ = app.emit("vpn-state", &snap);
    Ok(snap)
}

#[tauri::command]
fn connect_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    if let Err(e) = connect_inner(&*state, &app) {
        let mut g = state.inner.lock().map_err(|e2| e2.to_string())?;
        g.last_error = Some(e.clone());
        let snap = snapshot(&g);
        let _ = app.emit("vpn-state", &snap);
        return Err(e);
    }
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    let snap = snapshot(&g);
    let _ = app.emit("vpn-state", &snap);
    Ok(snap)
}

#[tauri::command]
fn disconnect_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    disconnect_inner(&*state, &app);
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    let snap = snapshot(&g);
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
            let snap = snapshot(&g);
            let _ = app.emit("vpn-state", &snap);
            Ok(snap)
        }
        Err(e) => {
            g.last_error = Some(e.clone());
            let snap = snapshot(&g);
            let _ = app.emit("vpn-state", &snap);
            Err(e)
        }
    }
}

#[tauri::command]
fn clear_error_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.last_error = None;
    let snap = snapshot(&g);
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

fn tray_icon() -> tauri::image::Image<'static> {
    include_image!("icons/32x32.png")
}

fn main() {
    let _log_dir = logging::init();
    std::panic::set_hook(Box::new(|info| {
        error!(target: "bibavpn_desktop", "panic: {info}");
        eprintln!("BibaVPN panic: {info}");
    }));

    if let Err(e) = run() {
        error!(target: "bibavpn_desktop", "failed to start: {e}");
        eprintln!("BibaVPN failed to start: {e}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
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

    tauri::Builder::default()
        .manage(state)
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(move |app| {
            let show = MenuItem::with_id(app, "show", "Открыть окно", true, None::<&str>)?;
            let on = MenuItem::with_id(app, "on", "Включить VPN", true, None::<&str>)?;
            let off = MenuItem::with_id(app, "off", "Отключить VPN", true, None::<&str>)?;
            let logs = MenuItem::with_id(app, "logs", "Папка с логами…", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(
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
            )?;

            let icon = tray_icon();
            let _tray = TrayIconBuilder::with_id("main-tray")
                .tooltip("BibaVPN")
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
                            let snap = snapshot(&g);
                            let _ = h.emit("vpn-state", &snap);
                            show_main_window(&h);
                        } else {
                            let g = st.inner.lock().unwrap_or_else(|e| e.into_inner());
                            let snap = snapshot(&g);
                            let _ = h.emit("vpn-state", &snap);
                        }
                    }
                    "off" => {
                        let st = app.state::<AppState>();
                        let h = app.clone();
                        disconnect_inner(&*st, &h);
                        let g = st.inner.lock().unwrap_or_else(|e| e.into_inner());
                        let snap = snapshot(&g);
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
                    if let TrayIconEvent::Click { .. } = event {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            Ok(())
        })
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
