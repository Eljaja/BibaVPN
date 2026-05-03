//! Запуск/остановка системного VPN на Android через [dev.bibavpn.TauriVpnBridge] (JNI).

use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use jni::objects::{JClass, JObject, JValueOwned};
use jni::sys::jboolean;
use jni::JNIEnv;
use tauri::AppHandle;
use tauri::Manager;

/// Wry/jni_handle::exec небезопасен при параллельных вызовах (например `get_state` раз в секунду + disconnect).
static VPN_WEBVIEW_JNI_MUTEX: Mutex<()> = Mutex::new(());

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
        });
    })
    .map_err(|e| e.to_string())
}

fn jni_string_err(env: &mut JNIEnv, e: jni::errors::Error) -> String {
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

/// Блокируется до завершения колбэка на UI-потоке Android (или таймаут).
pub fn request_connect(
    app: &AppHandle,
    json: &str,
    split_tunnel_enabled: bool,
    packages: &[String],
    screen_off_battery_saver: bool,
) -> Result<(), String> {
    let json = json.to_string();
    let packages: Vec<String> = packages.to_vec();
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, "dev.bibavpn.TauriVpnBridge")?;
            let j_json = env
                .new_string(&json)
                .map_err(|e| jni_string_err(env, e))?;
            let str_cls = load_app_class(env, activity, "java.lang.String")?;
            let arr = env
                .new_object_array(
                    packages.len() as jni::sys::jsize,
                    &str_cls,
                    JObject::null(),
                )
                .map_err(|e| jni_string_err(env, e))?;
            for (i, p) in packages.iter().enumerate() {
                let s = env.new_string(p).map_err(|e| jni_string_err(env, e))?;
                env.set_object_array_element(&arr, i as jni::sys::jsize, &s)
                    .map_err(|e| jni_string_err(env, e))?;
            }
            let out = env
                .call_static_method(
                    &cls,
                    "requestConnect",
                    "(Landroid/app/Activity;Ljava/lang/String;Z[Ljava/lang/String;Z)Ljava/lang/String;",
                    &[
                        activity.into(),
                        (&j_json).into(),
                        (split_tunnel_enabled as jboolean).into(),
                        (&arr).into(),
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
    rx.recv_timeout(Duration::from_secs(60))
        .map_err(|_| "таймаут JNI (VPN)".to_string())?
}

pub fn request_disconnect(app: &AppHandle) -> Result<(), String> {
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, "dev.bibavpn.TauriVpnBridge")?;
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

pub fn tunnel_is_active(app: &AppHandle) -> Result<bool, String> {
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, "dev.bibavpn.TauriVpnBridge")?;
            let out = env
                .call_static_method(&cls, "tunnelIsActive", "()Z", &[])
                .map_err(|e| jni_string_err(env, e))?;
            let v = out.z().map_err(|e| jni_string_err(env, e))?;
            Ok::<bool, String>(v)
        })();
        let _ = tx.send(res);
    })?;
    rx.recv_timeout(Duration::from_secs(5))
        .map_err(|_| "таймаут JNI (tunnelIsActive)".to_string())?
}

pub fn tunnel_session_elapsed_ms(app: &AppHandle) -> Result<u64, String> {
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, "dev.bibavpn.TauriVpnBridge")?;
            let out = env
                .call_static_method(&cls, "tunnelSessionElapsedMillis", "()J", &[])
                .map_err(|e| jni_string_err(env, e))?;
            let ms = match out {
                JValueOwned::Long(v) => v,
                _ => return Err("tunnelSessionElapsedMillis: unexpected JNI type".into()),
            };
            Ok::<u64, String>(if ms < 0 { 0 } else { ms as u64 })
        })();
        let _ = tx.send(res);
    })?;
    rx.recv_timeout(Duration::from_secs(5))
        .map_err(|_| "таймаут JNI (tunnelSessionElapsedMillis)".to_string())?
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

pub fn pick_installed_package(app: &AppHandle) -> Result<Option<String>, String> {
    let (tx, rx) = mpsc::sync_channel(1);
    with_main_webview_jni(app, move |env, activity| {
        let res = (|| {
            let cls = load_app_class(env, activity, "dev.bibavpn.TauriVpnBridge")?;
            let out = env
                .call_static_method(
                    &cls,
                    "pickInstalledLauncherPackage",
                    "(Landroid/app/Activity;)Ljava/lang/String;",
                    &[activity.into()],
                )
                .map_err(|e| jni_string_err(env, e))?;
            let j_obj = out.l().map_err(|e| jni_string_err(env, e))?;
            let j_str = jni::objects::JString::from(j_obj);
            let s: String = env
                .get_string(&j_str)
                .map_err(|e| jni_string_err(env, e))?
                .into();
            parse_pick_reply(&s)
        })();
        let _ = tx.send(res);
    })?;
    match rx.recv_timeout(Duration::from_secs(125)) {
        Ok(inner) => inner,
        Err(_) => Err("таймаут JNI (pickInstalledLauncherPackage)".into()),
    }
}
