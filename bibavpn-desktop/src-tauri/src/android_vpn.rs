//! Запуск/остановка системного VPN на Android через [dev.bibavpn.TauriVpnBridge] (JNI).

use std::sync::mpsc;
use std::time::Duration;

use jni::objects::JObject;
use jni::sys::jboolean;
use jni::JNIEnv;
use tauri::AppHandle;
use tauri::Manager;

fn with_main_webview_jni<F>(app: &AppHandle, run: F) -> Result<(), String>
where
    F: FnOnce(&mut JNIEnv, &JObject) + Send + 'static,
{
    let w = app
        .get_webview_window("main")
        .ok_or_else(|| "нет окна main".to_string())?;
    w.with_webview(move |webview| {
        webview.jni_handle().exec(move |env, activity, _webview| {
            run(env, activity);
        });
    })
    .map_err(|e| e.to_string())
}

fn jni_string_err(env: &mut JNIEnv, e: jni::errors::Error) -> String {
    format!("JNI: {e:#}")
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
            let cls = env
                .find_class("dev/bibavpn/TauriVpnBridge")
                .map_err(|e| jni_string_err(env, e))?;
            let j_json = env
                .new_string(&json)
                .map_err(|e| jni_string_err(env, e))?;
            let str_cls = env
                .find_class("java/lang/String")
                .map_err(|e| jni_string_err(env, e))?;
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
            let cls = env
                .find_class("dev/bibavpn/TauriVpnBridge")
                .map_err(|e| jni_string_err(env, e))?;
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
    with_main_webview_jni(app, move |env, _activity| {
        let res = (|| {
            let cls = env
                .find_class("dev/bibavpn/TauriVpnBridge")
                .map_err(|e| jni_string_err(env, e))?;
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
