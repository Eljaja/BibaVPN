package dev.bibavpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * Вызовы из Rust (Tauri) через JNI. Рефлексия к [app.tauri.plugin.PluginManager], чтобы модуль
 * компилировался и в чистом Android-проекте без AAR Tauri (там [getTauriPluginManager] вернёт null).
 */
object TauriVpnBridge {
    private const val TAG = "TauriVpnBridge"

    @JvmStatic
    fun tunnelIsActive(): Boolean = BibaVpnService.isTunnelActive

    @JvmStatic
    fun requestDisconnect(context: android.content.Context) {
        BibaVpnService.stop(context.applicationContext)
    }

    /**
     * @return null при успешной постановке в очередь (сервис стартовал или запущен диалог VPN);
     *   не-null — строка ошибки для показа/лога в Rust.
     */
    @JvmStatic
    fun requestConnect(
        activity: Activity,
        json: String,
        splitTunnelEnabled: Boolean,
        splitPackages: Array<String>,
        screenOffBatterySaver: Boolean,
    ): String? {
        BibaVpnService.setSplitTunnelConfig(activity, splitTunnelEnabled, splitPackages.toSet())
        BibaVpnService.setScreenOffBatterySaver(activity, screenOffBatterySaver)

        val prep = VpnService.prepare(activity)
        if (prep != null) {
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
                    },
                )
            if (!started) {
                BibaVpnService.clearPendingConnectJson(activity)
                return "vpn_permission_ui_unavailable"
            }
            return null
        }

        BibaVpnService.startWithJson(activity, json)
        return null
    }

    private fun getTauriPluginManager(activity: Activity): Any? =
        try {
            val m =
                activity.javaClass.methods.find {
                    it.name == "getPluginManager" && it.parameterCount == 0
                } ?: return null
            m.invoke(activity)
        } catch (e: Throwable) {
            Log.w(TAG, "getTauriPluginManager: ${e.message}")
            null
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
}
