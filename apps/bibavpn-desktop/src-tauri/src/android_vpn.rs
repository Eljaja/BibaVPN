//! Запуск/остановка системного VPN на Android через [dev.bibavpn.TauriVpnBridge] (JNI).
//!
//! Два пути в Kotlin:
//! - [`with_main_webview_jni`] — через wry `jni_handle().exec`. Замыкание уходит в event loop
//!   Tauri, а оттуда в очередь **главного лупера Android** (wry регистрирует свой pipe из
//!   `WryActivity.onCreate`, т.е. на UI-потоке). Нужен только там, где важен UI-поток:
//!   `requestConnect` (диалог разрешения VPN) и `requestDisconnect`.
//! - [`with_bridge_direct`] — вызов статических методов `TauriVpnBridge` прямо с текущего
//!   потока (он прикрепляется к JVM). Для статуса туннеля и ошибок bootstrap: это чтения
//!   `@Volatile`-полей сервиса, гонять их через UI-поток незачем. Раньше опрос раз в
//!   секунду стоил два прыжка через главный поток, каждый с таймаутом 5 с.

use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::jboolean;
use jni::{JNIEnv, JavaVM};
use tauri::AppHandle;
use tauri::Manager;

/// Wry/jni_handle::exec небезопасен при параллельных вызовах (например `get_state` раз в секунду + disconnect).
static VPN_WEBVIEW_JNI_MUTEX: Mutex<()> = Mutex::new(());

const BRIDGE_CLASS: &str = "dev.bibavpn.TauriVpnBridge";

/// Не оставляем pending exception из Kotlin на потоке: следующий JNI-вызов с ним — abort в ART.
fn clear_pending_exception(env: &mut JNIEnv) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }
}

fn with_main_webview_jni<F>(app: &AppHandle, run: F) -> Result<(), String>
where
    F: for<'local> FnOnce(&mut JNIEnv<'local>, &JObject<'local>) + Send + 'static,
{
    let _jni_guard = VPN_WEBVIEW_JNI_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let w = app
        .get_webview_window("main")
        .ok_or_else(|| "нет окна main".to_string())?;
    w.with_webview(move |webview| {
        webview.jni_handle().exec(move |env, activity, _webview| {
            let activity = env
                .new_local_ref(activity)
                .expect("failed to create local Activity reference");
            run(env, &activity);
            clear_pending_exception(env);
        });
    })
    .map_err(|e| e.to_string())
}

fn jni_string_err(_env: &mut JNIEnv, e: jni::errors::Error) -> String {
    format!("JNI: {e:#}")
}

fn load_app_class<'local>(
    env: &mut JNIEnv<'local>,
    activity: &JObject<'local>,
    name: &str,
) -> Result<JClass<'local>, String> {
    let j_name = env.new_string(name).map_err(|e| jni_string_err(env, e))?;
    let cls = env
        .call_method(
            activity,
            "getAppClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[(&j_name).into()],
        )
        .map_err(|e| jni_string_err(env, e))?
        .l()
        .map_err(|e| jni_string_err(env, e))?;
    Ok(JClass::from(cls))
}

/// JavaVM и GlobalRef на `TauriVpnBridge`, один раз полученные через главный лупер.
///
/// Класс кэшируем, потому что `FindClass` из нативного потока видит только системный
/// class loader — классы приложения достаются через `Activity.getAppClass`.
struct DirectBridge {
    vm: JavaVM,
    class: GlobalRef,
}

static DIRECT_BRIDGE: OnceLock<DirectBridge> = OnceLock::new();

fn direct_bridge(app: &AppHandle) -> Result<&'static DirectBridge, String> {
    if let Some(b) = DIRECT_BRIDGE.get() {
        return Ok(b);
    }
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, BRIDGE_CLASS)?;
            let class = env
                .new_global_ref(&cls)
                .map_err(|e| jni_string_err(env, e))?;
            let vm = env.get_java_vm().map_err(|e| jni_string_err(env, e))?;
            Ok::<DirectBridge, String>(DirectBridge { vm, class })
        })();
        let _ = tx.send(res);
    })?;
    let bridge = rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "таймаут JNI (кэш TauriVpnBridge)".to_string())??;
    // Гонка двух первых вызовов безвредна: лишний GlobalRef просто освободится.
    let _ = DIRECT_BRIDGE.set(bridge);
    DIRECT_BRIDGE
        .get()
        .ok_or_else(|| "кэш TauriVpnBridge недоступен".to_string())
}

/// Статические методы `TauriVpnBridge` с текущего потока, без главного лупера и event loop.
fn with_bridge_direct<T, F>(app: &AppHandle, run: F) -> Result<T, String>
where
    F: for<'local> FnOnce(&mut JNIEnv<'local>, &GlobalRef) -> Result<T, String>,
{
    let bridge = direct_bridge(app)?;
    let mut env = bridge
        .vm
        .attach_current_thread()
        .map_err(|e| format!("JNI attach: {e}"))?;
    let out = run(&mut env, &bridge.class);
    clear_pending_exception(&mut env);
    out
}

/// `String?` из Kotlin → `Option<String>`; локальную ссылку освобождаем сразу: поток
/// может оказаться уже прикреплённым к JVM, и тогда локальные ссылки копились бы.
fn take_java_string(env: &mut JNIEnv, obj: JObject) -> Result<Option<String>, String> {
    if obj.is_null() {
        return Ok(None);
    }
    let j_str = JString::from(obj);
    let s = env
        .get_string(&j_str)
        .map(String::from)
        .map_err(|e| jni_string_err(env, e));
    let _ = env.delete_local_ref(j_str);
    s.map(Some)
}

/// Блокируется до завершения колбэка на UI-потоке Android (или таймаут).
pub fn request_connect(
    app: &AppHandle,
    json: &str,
    split_tunnel_enabled: bool,
    packages: &[String],
    domains: &[String],
    screen_off_battery_saver: bool,
) -> Result<(), String> {
    let json = json.to_string();
    let packages: Vec<String> = packages.to_vec();
    let domains: Vec<String> = domains.to_vec();
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, BRIDGE_CLASS)?;
            let j_json = env
                .new_string(&json)
                .map_err(|e| jni_string_err(env, e))?;
            let str_cls = load_app_class(env, activity, "java.lang.String")?;
            let pkg_arr = env
                .new_object_array(
                    packages.len() as jni::sys::jsize,
                    &str_cls,
                    JObject::null(),
                )
                .map_err(|e| jni_string_err(env, e))?;
            for (i, p) in packages.iter().enumerate() {
                let s = env.new_string(p).map_err(|e| jni_string_err(env, e))?;
                env.set_object_array_element(&pkg_arr, i as jni::sys::jsize, &s)
                    .map_err(|e| jni_string_err(env, e))?;
            }
            let domain_arr = env
                .new_object_array(
                    domains.len() as jni::sys::jsize,
                    &str_cls,
                    JObject::null(),
                )
                .map_err(|e| jni_string_err(env, e))?;
            for (i, d) in domains.iter().enumerate() {
                let s = env.new_string(d).map_err(|e| jni_string_err(env, e))?;
                env.set_object_array_element(&domain_arr, i as jni::sys::jsize, &s)
                    .map_err(|e| jni_string_err(env, e))?;
            }
            let out = env
                .call_static_method(
                    &cls,
                    "requestConnect",
                    "(Landroid/app/Activity;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;Z)Ljava/lang/String;",
                    &[
                        activity.into(),
                        (&j_json).into(),
                        (split_tunnel_enabled as jboolean).into(),
                        (&pkg_arr).into(),
                        (&domain_arr).into(),
                        (screen_off_battery_saver as jboolean).into(),
                    ],
                )
                .map_err(|e| jni_string_err(env, e))?;
            let j_obj = out.l().map_err(|e| jni_string_err(env, e))?;
            if j_obj.is_null() {
                return Ok(());
            }
            let j_str = jni::objects::JString::from(j_obj);
            let err: String = env
                .get_string(&j_str)
                .map_err(|e| jni_string_err(env, e))?
                .into();
            Err(err)
        })();
        let _ = tx.send(res);
    })?;
    rx.recv_timeout(Duration::from_secs(125))
        .map_err(|_| "таймаут JNI (VPN)".to_string())?
}

pub fn clear_last_connect_error(app: &AppHandle) -> Result<(), String> {
    with_bridge_direct(app, |env, cls| {
        env.call_static_method(cls, "clearLastConnectError", "()V", &[])
            .map(|_| ())
            .map_err(|e| jni_string_err(env, e))
    })
}

pub fn request_disconnect(app: &AppHandle) -> Result<(), String> {
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, BRIDGE_CLASS)?;
            env.call_static_method(
                &cls,
                "requestDisconnect",
                "(Landroid/content/Context;)V",
                &[activity.into()],
            )
            .map_err(|e| jni_string_err(env, e))?;
            Ok::<(), String>(())
        })();
        let _ = tx.send(res);
    })?;
    rx.recv_timeout(Duration::from_secs(30))
        .map_err(|_| "таймаут JNI (отключение)".to_string())?
}

/// Состояние туннеля из `BibaVpnService` одним снимком (вместо трёх отдельных JNI-вызовов).
#[derive(Debug, Clone, Default)]
pub struct TunnelStatusJni {
    pub active: bool,
    /// Миллисекунды с `Engine.start`; 0, если туннеля нет.
    pub elapsed_ms: u64,
    /// Последняя ошибка bootstrap / разрешения VPN (стабильный код или текст), если есть.
    pub connect_error: Option<String>,
}

pub fn tunnel_status(app: &AppHandle) -> Result<TunnelStatusJni, String> {
    with_bridge_direct(app, |env, cls| {
        let active = env
            .call_static_method(cls, "tunnelIsActive", "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| jni_string_err(env, e))?;
        let elapsed_ms = if active {
            let ms = env
                .call_static_method(cls, "tunnelSessionElapsedMillis", "()J", &[])
                .and_then(|v| v.j())
                .map_err(|e| jni_string_err(env, e))?;
            ms.max(0) as u64
        } else {
            0
        };
        let err_obj = env
            .call_static_method(cls, "lastConnectError", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .map_err(|e| jni_string_err(env, e))?;
        let connect_error = take_java_string(env, err_obj)?.filter(|s| !s.trim().is_empty());
        Ok(TunnelStatusJni {
            active,
            elapsed_ms,
            connect_error,
        })
    })
}

pub fn tunnel_is_active(app: &AppHandle) -> Result<bool, String> {
    with_bridge_direct(app, |env, cls| {
        env.call_static_method(cls, "tunnelIsActive", "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| jni_string_err(env, e))
    })
}

fn parse_pick_reply(s: &str) -> Result<Option<String>, String> {
    let t = s.trim();
    if t.is_empty() || t == "CANCEL" {
        return Ok(None);
    }
    if let Some(pkg) = t.strip_prefix("PACKAGE:") {
        let pkg = pkg.trim();
        if pkg.is_empty() {
            return Err("пустой package".into());
        }
        return Ok(Some(pkg.to_string()));
    }
    if let Some(msg) = t.strip_prefix("ERROR:") {
        return Err(msg.trim().to_string());
    }
    Err(format!("pick_installed_package: {t}"))
}

/// Выбор приложения для split-tunnel.
///
/// Результат picker'а (Activity result) приходит на главный лупер, поэтому ждать его там
/// нельзя — и Kotlin на главном лупере сразу отвечает `ERROR:main_thread`. А `exec`
/// исполняется **только** на главном лупере, так что прежний вызов через него не работал
/// никогда. Теперь с лупера берём лишь ссылку на Activity, а сам вызов делаем с текущего
/// (blocking) потока: Kotlin идёт в ветку воркера — ставит picker на UI-поток и ждёт латч
/// (до 60 с) здесь, не трогая главный поток.
pub fn pick_installed_package(app: &AppHandle) -> Result<Option<String>, String> {
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = env
            .new_global_ref(activity)
            .map_err(|e| jni_string_err(env, e));
        let _ = tx.send(res);
    })?;
    let activity = rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "таймаут JNI (Activity для выбора приложения)".to_string())??;
    let reply = with_bridge_direct(app, |env, cls| {
        let out = env
            .call_static_method(
                cls,
                "pickInstalledLauncherPackage",
                "(Landroid/app/Activity;)Ljava/lang/String;",
                &[JValue::Object(activity.as_obj())],
            )
            .and_then(|v| v.l())
            .map_err(|e| jni_string_err(env, e))?;
        take_java_string(env, out)
    })?;
    parse_pick_reply(reply.as_deref().unwrap_or(""))
}
