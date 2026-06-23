//! BibaVPN Tauri backend — desktop (Windows/macOS/Linux) and mobile (Android, iOS) library target.

mod bypass_domains;
mod config;
mod control_plane_client;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod locale;
mod logging;
mod split_tunnel;

#[cfg(target_os = "android")]
mod proxy_android;
#[cfg(target_os = "macos")]
mod proxy_mac;
#[cfg(all(unix, not(any(target_os = "android", target_os = "macos"))))]
mod proxy_stub;
#[cfg(windows)]
mod proxy_win;

#[cfg(target_os = "android")]
use proxy_android::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(target_os = "macos")]
use proxy_mac::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(all(unix, not(any(target_os = "android", target_os = "macos"))))]
use proxy_stub::{apply_proxy, read_backup, restore, ProxyBackup};
#[cfg(windows)]
use proxy_win::{apply_proxy, read_backup, restore, ProxyBackup};

#[cfg(target_os = "android")]
mod android_vpn;

#[cfg(target_os = "ios")]
mod ios_vpn;

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bibavpn::decode_invite_v1;
use bibavpn::local_client_options_from_json_str_with_binds;
use bibavpn::tls_util::install_ring_crypto;
#[cfg(any(target_os = "android", target_os = "ios"))]
use config::load_config_from_path;
use config::{
    apply_invite_fields, desktop_config_json_path, display_host_line, import_control_plane_payload,
    load_config_disk, normalize_loaded, save_config_to_path, server_card_subtitle, SavedConfig,
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use locale::{resolved_tray_lang, tray_strings};
use serde::Serialize;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tauri::{include_image, WindowEvent, Wry};
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};
use tauri_plugin_deep_link::DeepLinkExt;
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

#[derive(Clone)]
struct AppState {
    rt: Arc<tokio::runtime::Runtime>,
    inner: Arc<Mutex<Inner>>,
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
    /// Android: секунды с момента поднятия tun2socks (устойчиво к перезапуску UI).
    #[serde(skip_serializing_if = "Option::is_none")]
    vpn_session_uptime_secs: Option<u64>,
}

/// TCP connect time до `profile.server` (host или host:port). IPv6 — только формат `[addr]:port`.
fn parse_server_tcp_target(server_trimmed: &str) -> Option<(String, u16)> {
    let s = server_trimmed.trim();
    if s.is_empty() {
        return None;
    }
    if s.starts_with('[') {
        let end = s.find(']')?;
        let inner_addr = &s[1..end];
        let rest = &s[end + 1..];
        if rest.starts_with(':') {
            let port: u16 = rest[1..].parse().ok()?;
            return Some((inner_addr.to_string(), port));
        }
        return Some((inner_addr.to_string(), 443));
    }
    if let Some((h, p)) = s.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = p.parse::<u16>() {
                return Some((h.to_string(), port));
            }
        }
    }
    Some((s.to_string(), 443))
}

fn measure_tcp_connect_rtt_ms(host: &str, port: u16) -> Option<u32> {
    let addr_str = format!("{host}:{port}");
    let addr = addr_str.to_socket_addrs().ok()?.next()?;
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, Duration::from_secs(4)).ok()?;
    let ms = start.elapsed().as_millis();
    Some(ms.min(u128::from(u32::MAX)) as u32)
}

fn snapshot(app: &AppHandle, inner: &Inner) -> StateSnapshot {
    #[cfg(target_os = "android")]
    let connected = android_vpn::tunnel_is_active(app).unwrap_or(false);
    #[cfg(target_os = "ios")]
    let connected = ios_vpn::tunnel_is_active(app).unwrap_or(false);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let connected = {
        let _ = app;
        inner.vpn.is_some()
    };
    #[cfg(target_os = "android")]
    let vpn_session_uptime_secs = if connected {
        Some(android_vpn::tunnel_session_elapsed_ms(app).unwrap_or(0) / 1000)
    } else {
        None
    };
    #[cfg(target_os = "ios")]
    let vpn_session_uptime_secs = if connected {
        Some(ios_vpn::tunnel_session_elapsed_ms(app).unwrap_or(0) / 1000)
    } else {
        None
    };
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let vpn_session_uptime_secs = None;
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
        vpn_session_uptime_secs,
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn mobile_config_json_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("config.json"))
}

fn persist_cfg(app: &AppHandle, cfg: &SavedConfig) -> Result<(), String> {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let p = mobile_config_json_path(app)?;
        save_config_to_path(cfg, &p)
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = app;
        save_config_to_path(cfg, &desktop_config_json_path())
    }
}

/// Случайные SOCKS auth для этой сессии (как `configJsonWithSessionSocksAuth` в [`BibaVpnService.kt`](../android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt)).
fn inject_mobile_tunnel_session_json(base_json: &str) -> Result<String, String> {
    use rand::{rngs::OsRng, Rng};
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = OsRng;
    let mut rand_part = |n: usize| -> String {
        (0..n)
            .map(|_| {
                let idx = rng.gen_range(0..alphabet.len());
                alphabet[idx] as char
            })
            .collect()
    };
    let mut v: serde_json::Value = serde_json::from_str(base_json).map_err(|e| e.to_string())?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| "конфиг должен быть JSON-объектом".to_string())?;
    obj.remove("socks_auth_user");
    obj.remove("socks_auth_password");
    obj.insert(
        "socks_auth_user".into(),
        serde_json::Value::String(rand_part(16)),
    );
    obj.insert(
        "socks_auth_password".into(),
        serde_json::Value::String(rand_part(24)),
    );
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
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

#[cfg(any(target_os = "android", target_os = "ios"))]
fn sync_tray_tooltip_i18n(_app: &AppHandle, _connected: bool, _cfg: &SavedConfig) {}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
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

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn apply_tray_menu_locale(
    app: &AppHandle,
    cfg: &SavedConfig,
    connected: bool,
) -> Result<(), String> {
    let menu = build_tray_menu(app, resolved_tray_lang(cfg)).map_err(|e| e.to_string())?;
    if let Some(tray) = app.tray_by_id("main-tray") {
        tray.set_menu(Some(menu)).map_err(|e| e.to_string())?;
    }
    sync_tray_tooltip_i18n(app, connected, cfg);
    Ok(())
}

fn install_deep_link_handler(app: &AppHandle, state: AppState) {
    let handle = app.clone();
    let st = state.clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            let raw = url.to_string();
            if let Err(e) = handle_import_deeplink(&st, &handle, &raw) {
                warn!(target: "bibavpn_desktop", "deep link: {e}");
                let mut g = st.inner.lock().unwrap_or_else(|p| p.into_inner());
                g.last_error = Some(e);
                let snap = snapshot(&handle, &g);
                let _ = handle.emit("vpn-state", &snap);
            }
        }
    });
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Err(e) = app.deep_link().register("bibavpn") {
        warn!(target: "bibavpn_desktop", "deep link register: {e}");
    }
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            let raw = url.to_string();
            if let Err(e) = handle_import_deeplink(&state, app, &raw) {
                warn!(target: "bibavpn_desktop", "deep link startup: {e}");
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn show_main_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn show_main_window(_app: &AppHandle) {}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn probe_local_http_health(http_port: u16) -> bool {
    use std::io::{Read, Write};

    let addr: SocketAddr = match format!("127.0.0.1:{http_port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return false;
    };
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n",
        bibavpn::http_connect::LOCAL_HEALTH_PATH
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 32];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => std::str::from_utf8(&buf[..n])
            .map(|s| s.contains("200"))
            .unwrap_or(false),
        _ => false,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn_tunnel_recovery_watch(app: AppHandle, state: AppState) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(12));
        let Some((http_port, client_dead)) = (|| {
            let g = match state.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let vpn = g.vpn.as_ref()?;
            Some((
                g.cfg.local_http_port,
                vpn.join.is_finished(),
            ))
        })() else {
            continue;
        };
        if client_dead {
            warn!(
                target: "bibavpn_desktop",
                "VPN-клиент завершился неожиданно — переподключение"
            );
        } else if probe_local_http_health(http_port) {
            continue;
        } else {
            std::thread::sleep(Duration::from_secs(2));
            if probe_local_http_health(http_port) {
                continue;
            }
            warn!(
                target: "bibavpn_desktop",
                "локальный HTTP-прокси недоступен после сна или сбоя — переподключение VPN"
            );
        }
        disconnect_inner(&state, &app);
        if let Err(e) = connect_inner(&state, &app) {
            warn!(target: "bibavpn_desktop", "автовосстановление VPN: {e}");
            let mut g = match state.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.last_error = Some(format!("После сна: {e}"));
            let snap = snapshot(&app, &g);
            drop(g);
            let _ = app.emit("vpn-state", &snap);
        } else {
            let g = match state.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let snap = snapshot(&app, &g);
            drop(g);
            let _ = app.emit("vpn-state", &snap);
        }
    });
}

fn disconnect_inner(state: &AppState, app: &AppHandle) {
    #[cfg(target_os = "android")]
    {
        {
            let mut g = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            info!(target: "bibavpn_desktop", "отключение VPN");
            g.last_error = None;
            g.tunnel_server = None;
        }

        // JNI/webview без удержания Mutex — иначе ANR/краш при disconnect (глобальный lock + UI-поток).
        let jni_result = android_vpn::request_disconnect(app);

        let mut g = state.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(ref e) = jni_result {
            warn!(target: "bibavpn_desktop", "android VPN stop: {e}");
            g.last_error = Some(e.clone());
        }
        sync_tray_tooltip_i18n(app, false, &g.cfg);
        let mut snap = snapshot(app, &g);
        // Остановка сервиса асинхронна — tunnel_is_active ещё может быть true в snapshot().
        if jni_result.is_ok() {
            snap.connected = false;
        }
        drop(g);
        let _ = app.emit("vpn-state", &snap);
        return;
    }

    #[cfg(target_os = "ios")]
    {
        {
            let mut g = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            info!(target: "bibavpn_desktop", "отключение VPN (iOS)");
            g.last_error = None;
            g.tunnel_server = None;
        }

        let stop_res = ios_vpn::request_disconnect(app);

        let mut g = state.inner.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(ref e) = stop_res {
            warn!(target: "bibavpn_desktop", "ios VPN stop: {e}");
            g.last_error = Some(e.clone());
        }
        sync_tray_tooltip_i18n(app, false, &g.cfg);
        let mut snap = snapshot(app, &g);
        if stop_res.is_ok() {
            snap.connected = false;
        }
        drop(g);
        let _ = app.emit("vpn-state", &snap);
        return;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut g = state.inner.lock().unwrap_or_else(|p| p.into_inner());
        info!(target: "bibavpn_desktop", "отключение VPN");
        g.last_error = None;
        g.tunnel_server = None;
        let backup = g.proxy_backup.take();
        match backup {
            Some(backup) => {
                if let Err(e) = restore(&backup) {
                    warn!(target: "bibavpn_desktop", "восстановление системного прокси: {e}");
                    g.last_error = Some(format!("Прокси: восстановление: {e}"));
                    #[cfg(windows)]
                    if let Err(e2) = crate::proxy_win::disable_if_residual_biba_proxy() {
                        warn!(
                            target: "bibavpn_desktop",
                            "прокси: запасное отключение loopback после ошибки restore: {e2}"
                        );
                    }
                }
            }
            None => {
                #[cfg(windows)]
                if let Err(e) = crate::proxy_win::disable_if_residual_biba_proxy() {
                    warn!(
                        target: "bibavpn_desktop",
                        "прокси: нет снимка настроек — запасная очистка loopback: {e}"
                    );
                    g.last_error = Some(format!("Прокси: {e}"));
                }
            }
        }
        if let Some(vpn) = g.vpn.take() {
            vpn.stop(&state.rt);
        }
        sync_tray_tooltip_i18n(app, false, &g.cfg);
        let snap = snapshot(app, &g);
        let _ = app.emit("vpn-state", &snap);
    }
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
            apply_invite_fields(p, &inv);
            Ok(())
        }
        Err(e) => {
            warn!(target: "bibavpn_desktop", "ключ biba://: {e:#}");
            Err(format!("Ключ: {e:#}"))
        }
    }
}

fn parse_import_deeplink(raw: &str) -> Option<(String, String)> {
    let trimmed = raw.trim();
    if !trimmed.to_lowercase().starts_with("bibavpn://") {
        return None;
    }
    let rest = trimmed.splitn(2, "://").nth(1)?;
    let (host_and_path, query) = rest.split_once('?')?;
    let host = host_and_path.trim_end_matches('/').split('/').next()?;
    if host != "import" {
        return None;
    }
    let mut token = None;
    let mut base_url = None;
    for part in query.split('&') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = urlencoding::decode(k).ok()?.into_owned();
        let val = urlencoding::decode(v).ok()?.into_owned();
        match key.as_str() {
            "token" => token = Some(val),
            "base_url" => base_url = Some(val),
            _ => {}
        }
    }
    Some((token?, base_url?))
}

fn handle_import_deeplink(state: &AppState, app: &AppHandle, raw_url: &str) -> Result<(), String> {
    let (token, base_url) = parse_import_deeplink(raw_url)
        .ok_or_else(|| "Неверная ссылка импорта (ожидается bibavpn://import?...).".to_string())?;
    let payload = control_plane_client::redeem_import(&base_url, &token)?;
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.last_error = None;
    import_control_plane_payload(&mut g.cfg, &payload, &base_url)?;
    persist_cfg(app, &g.cfg)?;
    info!(
        target: "bibavpn_desktop",
        instance_id = payload.instance_id,
        config_version = %payload.config_version,
        "control plane import ok"
    );
    let snap = snapshot(app, &g);
    drop(g);
    let _ = app.emit("vpn-state", &snap);
    let _ = app.emit("control-plane-import", ());
    show_main_window(app);
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
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

    let cfg = {
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

        g.cfg.clone()
    };

    let http_port = cfg.local_http_port;
    let socks_port = if cfg.local_socks_port == 0 {
        http_port.saturating_add(1)
    } else {
        cfg.local_socks_port
    };
    if socks_port == http_port {
        warn!(target: "bibavpn_desktop", "подключение: совпадают порты HTTP и SOCKS");
        return Err(
            "Порт SOCKS5 должен отличаться от HTTP (или оставьте SOCKS = 0 для HTTP+1).".into(),
        );
    }
    let http_bind = format!("127.0.0.1:{http_port}");
    let socks_bind = format!("127.0.0.1:{socks_port}");

    persist_cfg(app, &cfg)?;

    let backup = read_backup().map_err(|e| e.to_string())?;
    let json = cfg.start_config_json()?;
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

    match socks_rx.recv_timeout(Duration::from_secs(45)) {
        Ok(()) => {
            info!(
                target: "bibavpn_desktop",
                "локальный прокси и удалённый туннель готовы, можно применять системный прокси"
            );
        }
        Err(RecvTimeoutError::Timeout) => {
            warn!(
                target: "bibavpn_desktop",
                "таймаут 45 с: локальный прокси или удалённый туннель не поднялись, отмена подключения"
            );
            let _ = shutdown_tx.send(true);
            match state.rt.block_on(join) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => error!(target: "bibavpn_desktop", "клиент после таймаута: {e:#}"),
                Err(e) => error!(target: "bibavpn_desktop", "join клиента: {e}"),
            }
            return Err(
                "Подключение не завершилось за 45 с (TLS/WSS к серверу или локальный прокси). Смотрите лог в папке BibaVPN/logs.".into(),
            );
        }
        Err(RecvTimeoutError::Disconnected) => {
            let msg = match state.rt.block_on(join) {
                Ok(Ok(())) => {
                    "Клиент завершился до готовности прокси (проверьте TLS pin, SNI, token, PSK)."
                        .to_string()
                }
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
    let split_hosts = cfg
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
    let mut g = match state.inner.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
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

    persist_cfg(app, &g.cfg)?;
    let json = g.cfg.start_config_json()?;
    let _ = bypass_domains::ensure_loaded(false);
    let (split_tunnel_enabled, packages, domains, battery) = match g.cfg.active_profile() {
        Some(p) => (
            p.split_tunnel_enabled,
            split_tunnel::android_split_packages_for_profile(p),
            split_tunnel::android_split_domains_for_profile(p),
            p.android_screen_off_battery_saver,
        ),
        None => (false, Vec::new(), Vec::new(), false),
    };
    let remote_label = display_host_line(&g.cfg);
    drop(g);

    android_vpn::request_connect(
        app,
        &json,
        split_tunnel_enabled,
        &packages,
        &domains,
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

#[cfg(target_os = "ios")]
fn connect_inner(state: &AppState, app: &AppHandle) -> Result<(), String> {
    if ios_vpn::tunnel_is_active(app).unwrap_or(false) {
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

    persist_cfg(app, &g.cfg)?;
    let json = g.cfg.start_config_json()?;
    let json = inject_mobile_tunnel_session_json(&json)?;
    let remote_label = display_host_line(&g.cfg);
    drop(g);

    ios_vpn::request_connect(app, &json)?;

    let mut g = match state.inner.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.tunnel_server = Some(remote_label);
    let tray_up = ios_vpn::tunnel_is_active(app).unwrap_or(false);
    sync_tray_tooltip_i18n(app, tray_up, &g.cfg);
    Ok(())
}

#[tauri::command]
#[cfg(target_os = "android")]
fn pick_installed_package_cmd(app: AppHandle) -> Result<Option<String>, String> {
    android_vpn::pick_installed_package(&app)
}

#[tauri::command]
#[cfg(not(target_os = "android"))]
fn pick_installed_package_cmd() -> Result<Option<String>, String> {
    Err("Выбор приложения доступен только на Android.".into())
}

#[tauri::command]
async fn measure_server_rtt_cmd(state: State<'_, AppState>) -> Result<Option<u32>, String> {
    let target = {
        let g = state.inner.lock().map_err(|e| e.to_string())?;
        let Some(p) = g.cfg.active_profile() else {
            return Ok(None);
        };
        let server = p.server.trim();
        if server.is_empty() {
            return Ok(None);
        }
        parse_server_tcp_target(server)
    };
    let Some((host, port)) = target else {
        return Ok(None);
    };
    tauri::async_runtime::spawn_blocking(move || measure_tcp_connect_rtt_ms(&host, port))
        .await
        .map_err(|e| format!("RTT task: {e}"))
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
    persist_cfg(&app, &g.cfg)?;
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let cfg_for_tray = g.cfg.clone();
    let snap = snapshot(&app, &g);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let connected = snap.connected;
    drop(g);
    let _ = app.emit("vpn-state", &snap);
    if locale_changed {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Err(e) = apply_tray_menu_locale(&app, &cfg_for_tray, connected) {
            warn!(target: "bibavpn_desktop", "обновление меню трея: {e}");
        }
    }
    Ok(snap)
}

#[tauri::command]
async fn connect_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Err(e) = connect_inner(&state, &app) {
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
    })
    .await
    .map_err(|e| format!("connect task: {e}"))?
}

#[tauri::command]
async fn disconnect_cmd(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<StateSnapshot, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        disconnect_inner(&state, &app);
        let g = state.inner.lock().map_err(|e| e.to_string())?;
        let snap = snapshot(&app, &g);
        let _ = app.emit("vpn-state", &snap);
        Ok(snap)
    })
    .await
    .map_err(|e| format!("disconnect task: {e}"))?
}

#[tauri::command]
fn apply_invite_cmd(state: State<'_, AppState>, app: AppHandle) -> Result<StateSnapshot, String> {
    let mut g = state.inner.lock().map_err(|e| e.to_string())?;
    g.last_error = None;
    match apply_invite_to_cfg(&mut g.cfg) {
        Ok(()) => {
            persist_cfg(&app, &g.cfg)?;
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
fn open_control_plane_refresh_cmd(
    state: State<'_, AppState>,
    app: AppHandle,
) -> Result<StateSnapshot, String> {
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    let p = g
        .cfg
        .active_profile()
        .ok_or_else(|| "Нет активного профиля.".to_string())?;
    let base = p.control_plane_base_url.trim();
    let inst = p.control_plane_instance_id;
    if base.is_empty() || inst == 0 {
        return Err("Профиль не привязан к control plane. Откройте конфиг из веб-кабинета.".into());
    }
    let url = format!("{base}/me/instances/{inst}/open");
    drop(g);
    open_portal_url(&url)?;
    let g = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(snapshot(&app, &g))
}

fn open_portal_url(url: &str) -> Result<(), String> {
    // `url` is built from the control-plane base URL (config / web cabinet), i.e.
    // partly external input. Refuse anything that isn't a plain http(s) URL before
    // handing it to a launcher. On Windows `cmd /C start` would otherwise treat
    // shell metacharacters (& | < > ^ %) in the URL as commands; on macOS/Linux a
    // leading '-' could be parsed as a flag by `open`/`xdg-open`.
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Недопустимый URL веб-кабинета.".into());
    }
    if url.len() > 2048
        || url.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '&' | '|' | '<' | '>' | '^' | '"' | '\'' | '%' | '`')
        })
    {
        return Err("Недопустимый URL веб-кабинета.".into());
    }
    #[cfg(target_os = "android")]
    {
        use tauri::Manager;
        // Android: rely on VIEW intent via plugin when available; fallback to log.
        let _ = url;
        return Err(
            "Откройте веб-кабинет в браузере и нажмите «Открыть в BibaVPN».".into(),
        );
    }
    #[cfg(target_os = "ios")]
    {
        let _ = url;
        return Err(
            "Откройте веб-кабинет в браузере и нажмите «Open in BibaVPN».".into(),
        );
    }
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios"))))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
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

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BypassPresetsResponse {
    presets: Vec<bypass_domains::BypassPresetInfo>,
    configured: bool,
    error: Option<String>,
}

#[tauri::command]
async fn get_bypass_presets_cmd(refresh: bool) -> BypassPresetsResponse {
    const FETCH_TIMEOUT: Duration =
        Duration::from_secs(bypass_domains::HTTP_TIMEOUT_SECS + 1);

    let task = tauri::async_runtime::spawn_blocking(move || {
        let configured = bypass_domains::bypass_domains_url().is_some();
        match bypass_domains::ensure_loaded(refresh) {
            Ok(presets) => {
                let error = if configured && presets.is_empty() {
                    Some(
                        "Списки обхода недоступны (таймаут 2 с или ошибка сети)".into(),
                    )
                } else {
                    None
                };
                BypassPresetsResponse {
                    presets,
                    configured,
                    error,
                }
            }
            Err(e) => BypassPresetsResponse {
                presets: bypass_domains::cached_presets_or_empty(),
                configured,
                error: Some(e),
            },
        }
    });

    match tokio::time::timeout(FETCH_TIMEOUT, task).await {
        Ok(Ok(response)) => response,
        Ok(Err(e)) => BypassPresetsResponse {
            presets: bypass_domains::cached_presets_or_empty(),
            configured: bypass_domains::bypass_domains_url().is_some(),
            error: Some(format!("bypass presets task: {e}")),
        },
        Err(_) => BypassPresetsResponse {
            presets: bypass_domains::cached_presets_or_empty(),
            configured: bypass_domains::bypass_domains_url().is_some(),
            error: Some("Таймаут загрузки списков обхода (2 с)".into()),
        },
    }
}

fn prefetch_bypass_domains() {
    std::thread::spawn(|| {
        if bypass_domains::bypass_domains_url().is_none() {
            return;
        }
        let _ = bypass_domains::ensure_loaded(false);
        if bypass_domains::cached_presets_or_empty().is_empty() {
            bypass_domains::background_refresh_full();
        }
    });
}

#[cfg(unix)]
fn unix_ignore_shell_signals() {
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn tray_icon() -> tauri::image::Image<'static> {
    include_image!("icons/32x32.png")
}

/// Desktop + mobile entry (Tauri Android / iOS use the `cdylib` after `tauri android/ios init`).
#[cfg_attr(
    any(target_os = "android", target_os = "ios"),
    tauri::mobile_entry_point
)]
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
        inner: Arc::new(Mutex::new(Inner {
            cfg,
            proxy_backup: None,
            vpn: None,
            tunnel_server: None,
            last_error: None,
        })),
    };

    let mut builder = tauri::Builder::default();

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        // Windows/Linux: deep links spawn a second process unless we dedupe here.
        // The deep-link feature forwards argv to the running instance's on_open_url handler.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main_window(app);
        }));
    }

    builder = builder
        .plugin(tauri_plugin_deep_link::init())
        .manage(state);

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
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
                // If a previous run crashed while connected, the system proxy may
                // still point at our now-dead local listener, leaving the user
                // without working internet. Clear any residual BibaVPN proxy at
                // startup (restore() otherwise only runs on a clean exit).
                #[cfg(windows)]
                {
                    if let Err(e) = crate::proxy_win::disable_if_residual_biba_proxy() {
                        warn!(target: "bibavpn_desktop", "очистка остаточного прокси при старте: {e}");
                    }
                }
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

                spawn_tunnel_recovery_watch(
                    app.handle().clone(),
                    Clone::clone(&*app.state::<AppState>()),
                );
                prefetch_bypass_domains();
                install_deep_link_handler(app.handle(), Clone::clone(&*app.state::<AppState>()));
                Ok(())
            });
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        builder = builder.setup(|app| {
            install_deep_link_handler(app.handle(), Clone::clone(&*app.state::<AppState>()));
            let handle = app.handle().clone();
            match mobile_config_json_path(&handle) {
                Ok(path) => {
                    let mut cfg = load_config_from_path(&path);
                    normalize_loaded(&mut cfg);
                    let state = app.state::<AppState>();
                    let mut inner = match state.inner.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    inner.cfg = cfg;
                    drop(inner);
                    let g = match state.inner.lock() {
                        Ok(g) => g,
                        Err(p) => p.into_inner(),
                    };
                    let snap = snapshot(&handle, &g);
                    drop(g);
                    let _ = handle.emit("vpn-state", &snap);
                }
                Err(e) => {
                    warn!(target: "bibavpn_desktop", "mobile config path: {e}");
                }
            }
            prefetch_bypass_domains();
            Ok(())
        });
    }

    let app = builder
        .invoke_handler(tauri::generate_handler![
            get_state,
            measure_server_rtt_cmd,
            pick_installed_package_cmd,
            save_config_cmd,
            connect_cmd,
            disconnect_cmd,
            apply_invite_cmd,
            clear_error_cmd,
            open_control_plane_refresh_cmd,
            get_bypass_presets_cmd,
        ])
        .build(tauri::generate_context!())?;

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            let st = app_handle.state::<AppState>();
            disconnect_inner(&*st, app_handle);
        }
    });

    Ok(())
}

#[cfg(test)]
mod deeplink_tests {
    use super::parse_import_deeplink;

    #[test]
    fn parse_import_deeplink_ok() {
        let url = "bibavpn://import?token=abc123&base_url=https%3A%2F%2Fcp.example.com";
        let (tok, base) = parse_import_deeplink(url).expect("parse");
        assert_eq!(tok, "abc123");
        assert_eq!(base, "https://cp.example.com");
    }
}
