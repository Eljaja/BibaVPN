package dev.bibavpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Looper
import android.os.Handler
import android.util.Log
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Вызовы из Rust (Tauri) через JNI. Рефлексия к [app.tauri.plugin.PluginManager], чтобы модуль
 * компилировался и в чистом Android-проекте без AAR Tauri (там [getTauriPluginManager] вернёт null).
 *
 * Wry крутит [Jni] на своём looper, не на [Looper.getMainLooper] — [startActivityForResult] и
 * запуск FGS с UI-контекстом делаем строго на UI-потоке.
 */
object TauriVpnBridge {
    private const val TAG = "TauriVpnBridge"

    @JvmStatic
    fun tunnelIsActive(): Boolean = BibaVpnService.isTunnelActive

    /** Миллисекунды с момента поднятия туннеля ([Engine.start]); 0 если туннеля нет. */
    @JvmStatic
    fun tunnelSessionElapsedMillis(): Long = BibaVpnService.tunnelSessionElapsedMillis()

    /** Последняя ошибка bootstrap (nativeStart / TUN); null если нет или туннель уже активен. */
    @JvmStatic
    fun lastConnectError(): String? = BibaVpnService.lastConnectError()

    @JvmStatic
    fun clearLastConnectError() {
        BibaVpnService.clearLastConnectError()
    }

    @JvmStatic
    fun requestDisconnect(context: android.content.Context) {
        val app = context.applicationContext
        if (Looper.myLooper() == Looper.getMainLooper()) {
            BibaVpnService.stop(app)
        } else {
            Handler(Looper.getMainLooper()).post { BibaVpnService.stop(app) }
        }
    }

    /**
     * @return null при успешной постановке в очередь (сервис стартовал после разрешения VPN);
     *   не-null — строка ошибки для показа/лога в Rust.
     */
    @JvmStatic
    fun requestConnect(
        activity: Activity,
        json: String,
        splitTunnelEnabled: Boolean,
        splitPackages: Array<String>,
        splitDomains: Array<String>,
        screenOffBatterySaver: Boolean,
    ): String? {
        // Rust вызывает нас через wry `jni_handle().exec`, то есть уже НА главном лупере.
        // Ждать здесь нельзя ни в каком виде: результат диалога разрешения VPN приходит
        // через Activity result на этот же лупер, поэтому любое ожидание — самоблокировка
        // (ANR «Input dispatching timed out» через 5 с). [startConnectOnMain] не блокирует:
        // он ставит диалог и возвращается, а исход прилетает асинхронно и подхватывается
        // через [BibaVpnService.lastConnectError].
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return startConnectOnMain(
                activity,
                json,
                splitTunnelEnabled,
                splitPackages,
                splitDomains,
                screenOffBatterySaver,
            )
        }
        // Вызов с фонового потока: перепрыгиваем на UI и ждём только немедленный код
        // возврата, который [startConnectOnMain] отдаёт не блокируясь.
        val holder = arrayOfNulls<String?>(1)
        val latch = CountDownLatch(1)
        activity.runOnUiThread {
            try {
                holder[0] =
                    startConnectOnMain(
                        activity,
                        json,
                        splitTunnelEnabled,
                        splitPackages,
                        splitDomains,
                        screenOffBatterySaver,
                    )
            } catch (t: Throwable) {
                Log.e(TAG, "requestConnect", t)
                holder[0] = t.message ?: "requestConnect_exception"
            } finally {
                latch.countDown()
            }
        }
        return try {
            if (!latch.await(30, TimeUnit.SECONDS)) {
                "connect_ui_thread_timeout"
            } else {
                holder[0]
            }
        } catch (e: InterruptedException) {
            "connect_interrupted"
        }
    }

    /**
     * Должна вызываться на главном лупере и НИКОГДА не блокировать его.
     *
     * Возвращает только немедленный исход: `null` — сервис стартовал или диалог
     * разрешения VPN поставлен в очередь; строка — ошибка, которую видно сразу.
     * Результат самого диалога приходит позже в [startVpnPermissionFlow] и попадает
     * в [BibaVpnService.lastConnectError], откуда Rust забирает его в snapshot.
     */
    private fun startConnectOnMain(
        activity: Activity,
        json: String,
        splitTunnelEnabled: Boolean,
        splitPackages: Array<String>,
        splitDomains: Array<String>,
        screenOffBatterySaver: Boolean,
    ): String? {
        return try {
            BibaVpnService.setSplitTunnelConfig(
                activity,
                splitTunnelEnabled,
                splitPackages.toSet(),
                splitDomains.toSet(),
            )
            BibaVpnService.setScreenOffBatterySaver(activity, screenOffBatterySaver)

            val prep = VpnService.prepare(activity)
            if (prep == null) {
                BibaVpnService.startWithJson(activity, json)
                return null
            }

            BibaVpnService.stashPendingConnectJson(activity, json)
            BibaVpnService.saveConfig(activity, json)
            val started =
                startVpnPermissionFlow(
                    activity,
                    prep,
                    onOk = {
                        val j =
                            BibaVpnService.takePendingConnectJson(activity)
                                ?: BibaVpnService.getLastConfigJson(activity)
                                ?: json
                        BibaVpnService.clearPendingConnectJson(activity)
                        BibaVpnService.startWithJson(activity, j)
                    },
                    onDenied = {
                        BibaVpnService.clearPendingConnectJson(activity)
                        BibaVpnService.recordConnectError("vpn_permission_denied")
                    },
                )
            if (!started) {
                BibaVpnService.clearPendingConnectJson(activity)
                return "vpn_permission_ui_unavailable"
            }
            null
        } catch (t: Throwable) {
            Log.e(TAG, "startConnectOnMain", t)
            t.message ?: "requestConnect_exception"
        }
    }

    private fun getTauriPluginManager(activity: Activity): Any? {
        return try {
            val m =
                activity.javaClass.methods.find {
                    it.name == "getPluginManager" && it.parameterCount == 0
                } ?: return null
            m.invoke(activity)
        } catch (e: Throwable) {
            Log.w(TAG, "getTauriPluginManager: ${e.message}")
            null
        }
    }

    private fun startVpnPermissionFlow(
        activity: Activity,
        prep: Intent,
        onOk: () -> Unit,
        onDenied: () -> Unit,
    ): Boolean {
        val pm = getTauriPluginManager(activity) ?: return false
        return try {
            val cbClass = Class.forName("app.tauri.plugin.PluginManager\$ActivityResultCallback")
            val proxy =
                java.lang.reflect.Proxy.newProxyInstance(
                    cbClass.classLoader,
                    arrayOf(cbClass),
                ) { _, method, args ->
                    if (method.name != "onResult") {
                        return@newProxyInstance null
                    }
                    val result = args?.firstOrNull() ?: return@newProxyInstance null
                    val code =
                        result.javaClass.getMethod("getResultCode").invoke(result) as Int
                    if (code == Activity.RESULT_OK) {
                        onOk()
                    } else {
                        onDenied()
                    }
                    null
                }
            val m =
                pm.javaClass.getMethod(
                    "startActivityForResult",
                    Intent::class.java,
                    cbClass,
                )
            m.invoke(pm, prep, proxy)
            true
        } catch (e: Throwable) {
            Log.e(TAG, "startVpnPermissionFlow", e)
            false
        }
    }

    /**
     * Выбор приложения для split-tunnel (список лаунчер-приложений).
     * Ответ для JNI (Rust): `CANCEL`, `PACKAGE:имя`, `ERROR:…`.
     */
    @JvmStatic
    fun pickInstalledLauncherPackage(activity: Activity): String {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            // startActivityForResult delivers on main; blocking here would deadlock (see requestConnect).
            return "ERROR:main_thread"
        }
        return pickInstalledLauncherPackageWorker(activity)
    }

    private fun pickInstalledLauncherPackageWorker(activity: Activity): String {
        val latch = CountDownLatch(1)
        val holder = arrayOfNulls<String>(1)
        val released = java.util.concurrent.atomic.AtomicBoolean(false)
        fun finish(result: String) {
            if (released.compareAndSet(false, true)) {
                holder[0] = result
                latch.countDown()
            }
        }

        activity.runOnUiThread {
            try {
                val pm = getTauriPluginManager(activity)
                if (pm == null) {
                    finish("ERROR:no_plugin_manager")
                    return@runOnUiThread
                }
                val cbClass = Class.forName("app.tauri.plugin.PluginManager\$ActivityResultCallback")
                val proxy =
                    java.lang.reflect.Proxy.newProxyInstance(
                        cbClass.classLoader,
                        arrayOf(cbClass),
                    ) { _, method, args ->
                        if (method.name != "onResult") {
                            return@newProxyInstance null
                        }
                        try {
                            val result = args?.firstOrNull()
                            val out =
                                if (result == null) {
                                    "CANCEL"
                                } else {
                                    val code =
                                        try {
                                            result.javaClass.getMethod("getResultCode").invoke(result) as Int
                                        } catch (_: Throwable) {
                                            Activity.RESULT_CANCELED
                                        }
                                    if (code != Activity.RESULT_OK) {
                                        "CANCEL"
                                    } else {
                                        val data = extractResultIntent(result)
                                        val pkg =
                                            data?.getStringExtra(PickInstalledPackageActivity.EXTRA_PACKAGE_NAME)?.trim().orEmpty()
                                        if (pkg.isEmpty()) {
                                            "CANCEL"
                                        } else {
                                            "PACKAGE:$pkg"
                                        }
                                    }
                                }
                            finish(out)
                        } catch (t: Throwable) {
                            Log.e(TAG, "pick onResult", t)
                            finish("ERROR:${t.message ?: t.javaClass.simpleName}")
                        }
                        null
                    }
                val intent = Intent(activity, PickInstalledPackageActivity::class.java)
                val m =
                    pm.javaClass.getMethod(
                        "startActivityForResult",
                        Intent::class.java,
                        cbClass,
                    )
                m.invoke(pm, intent, proxy)
            } catch (e: Throwable) {
                Log.e(TAG, "pickInstalledLauncherPackageWorker", e)
                finish("ERROR:${e.message ?: e.javaClass.simpleName}")
            }
        }
        return try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                "ERROR:timeout"
            } else {
                holder[0] ?: "ERROR:null_result"
            }
        } catch (e: InterruptedException) {
            "ERROR:interrupted"
        }
    }

    private fun extractResultIntent(activityResult: Any): Intent? {
        for (method in activityResult.javaClass.methods) {
            if (method.parameterCount != 0) continue
            val n = method.name
            if (n != "getData" && n != "getIntent" && n != "getResultIntent") continue
            val v =
                try {
                    method.invoke(activityResult)
                } catch (_: Throwable) {
                    continue
                }
            if (v is Intent) return v
        }
        return null
    }
}
