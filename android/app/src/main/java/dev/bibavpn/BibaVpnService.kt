package dev.bibavpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.PowerManager
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.bibavpn.core.BibaNative
import engine.Engine
import engine.Key
import org.json.JSONObject

/**
 * Запускает Rust SOCKS5→BibaVPN, затем поднимает системный VPN (TUN) и tun2socks на 127.0.0.1:1080.
 */
class BibaVpnService : VpnService() {

    private val tunLock = Any()
    private var tun2socksThread: Thread? = null
    /** После успешного Engine.start() fd закрывает Go; не вызывать ParcelFileDescriptor.close() — fdsan/SIGABRT. */
    @Volatile
    private var tunFdMustCloseInJava = false
    private var tunParcelOrphan: ParcelFileDescriptor? = null
    private var tunnelWakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?) = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnelAndNative()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
        }

        val json = intent?.getStringExtra(EXTRA_CONFIG_JSON) ?: loadSavedConfigJson()
        if (json.isNullOrBlank()) {
            stopSelf()
            return START_NOT_STICKY
        }

        val socks = runCatching {
            JSONObject(json).optString("socks_bind", SOCKS_LOCAL).ifBlank { SOCKS_LOCAL }
        }.getOrDefault(SOCKS_LOCAL)

        val notification = buildNotification(socks)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        // nativeStart ждёт bind SOCKS в Rust — не блокируем main thread (ANR).
        Thread(
            {
                try {
                    val err = try {
                        BibaNative.nativeStart(json)
                    } catch (e: Throwable) {
                        Log.e(TAG, "native start", e)
                        e.message ?: e.javaClass.simpleName
                    }
                    if (err != null) {
                        isTunnelActive = false
                        mainHandler.post {
                            android.widget.Toast.makeText(
                                applicationContext,
                                err,
                                android.widget.Toast.LENGTH_LONG,
                            ).show()
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelf()
                        }
                        return@Thread
                    }

                    if (!startVpnTunnel(socks)) {
                        isTunnelActive = false
                        BibaNative.nativeStop()
                        mainHandler.post {
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelf()
                        }
                        return@Thread
                    }
                } catch (e: Throwable) {
                    isTunnelActive = false
                    Log.e(TAG, "vpn start thread", e)
                    mainHandler.post {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
            },
            "biba-vpn-start",
        ).start()

        return START_STICKY
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onDestroy() {
        stopTunnelAndNative()
        super.onDestroy()
    }

    private fun startVpnTunnel(socksBind: String): Boolean {
        synchronized(tunLock) {
            stopTun2socksOnly()
            val builder = Builder()
                .setSession("BibaVPN")
                .setMtu(1500)
                .addAddress(VPN_LOCAL_IP, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
            builder.addDisallowedApplication(packageName)
            try {
                builder.addRoute("::", 0)
            } catch (_: Throwable) {
                /* IPv6 маршрут необязателен */
            }

            val pfd: ParcelFileDescriptor = builder.establish() ?: run {
                Log.e(TAG, "VpnService.Builder.establish() returned null")
                return false
            }

            val fd = try {
                pfd.detachFd()
            } catch (e: Exception) {
                Log.e(TAG, "detachFd", e)
                pfd.close()
                return false
            }
            tunFdMustCloseInJava = true
            runCatching { tunParcelOrphan?.close() }
            tunParcelOrphan = ParcelFileDescriptor.adoptFd(fd)

            val proxy =
                socksBind.trim().let { b ->
                    if (b.startsWith("socks5://", ignoreCase = true)) b else "socks5://$b"
                }
            tun2socksThread = Thread(
                {
                    try {
                        val key = Key()
                        key.setDevice("fd://$fd")
                        key.setProxy(proxy)
                        key.setMTU(1500)
                        // П последним setter'ом: в некоторых gomobile-биндингах поля сбрасываются при других set* .
                        key.setLogLevel("info")
                        Log.i(TAG, "tun2socks Key.logLevel=${key.logLevel}")
                        Engine.insert(key)
                        Engine.start()
                        synchronized(tunLock) { tunFdMustCloseInJava = false }
                        acquireTunnelWakeLock()
                        isTunnelActive = true
                    } catch (e: Throwable) {
                        Log.e(TAG, "tun2socks", e)
                        abortVpnFromWorker(e.message)
                    }
                },
                "biba-tun2socks",
            ).also { it.start() }
            Log.i(TAG, "VPN up, tun2socks -> $proxy")
            return true
        }
    }

    private fun abortVpnFromWorker(detail: String?) {
        Handler(Looper.getMainLooper()).post {
            val msg = detail?.let { "BibaVPN: $it" } ?: "BibaVPN: ошибка tun2socks"
            android.widget.Toast.makeText(applicationContext, msg, android.widget.Toast.LENGTH_LONG)
                .show()
            stopTunnelAndNative()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun acquireTunnelWakeLock() {
        releaseTunnelWakeLock()
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        tunnelWakeLock = pm.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK,
            "$packageName:biba-tunnel",
        ).apply {
            setReferenceCounted(false)
            acquire()
        }
        Log.i(TAG, "PARTIAL_WAKE_LOCK acquired for VPN tunnel")
    }

    private fun releaseTunnelWakeLock() {
        runCatching {
            tunnelWakeLock?.let { wl ->
                if (wl.isHeld) wl.release()
            }
        }
        tunnelWakeLock = null
    }

    private fun stopTun2socksOnly() {
        isTunnelActive = false
        releaseTunnelWakeLock()
        runCatching { Engine.stop() }
        tun2socksThread?.let { t ->
            try {
                t.join(8000)
            } catch (_: InterruptedException) {
            }
        }
        tun2socksThread = null
        synchronized(tunLock) {
            if (tunFdMustCloseInJava) {
                runCatching { tunParcelOrphan?.close() }
            }
            tunParcelOrphan = null
            tunFdMustCloseInJava = false
        }
    }

    private fun stopTunnelAndNative() {
        synchronized(tunLock) {
            stopTun2socksOnly()
        }
        BibaNative.nativeStop()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = getSystemService(NotificationManager::class.java) ?: return
        val ch = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        mgr.createNotificationChannel(ch)
    }

    private fun buildNotification(socksBind: String): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, BibaVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text, socksBind))
            .setContentIntent(openApp)
            .addAction(0, getString(android.R.string.cancel), stop)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun loadSavedConfigJson(): String? =
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_JSON, null)

    companion object {
        /** true после успешного Engine.start() tun2socks; сбрасывается при остановке. */
        @Volatile
        var isTunnelActive: Boolean = false
            private set

        private const val TAG = "BibaVpnService"
        private const val CHANNEL_ID = "bibavpn_proxy"
        private const val NOTIFICATION_ID = 42
        const val ACTION_STOP = "dev.bibavpn.STOP"
        const val EXTRA_CONFIG_JSON = "config_json"
        private const val PREFS = "bibavpn"
        private const val KEY_LAST_JSON = "last_config_json"

        /** Должен совпадать с настройкой в JSON для native (tun2socks подключается сюда). */
        const val SOCKS_LOCAL = "127.0.0.1:1080"
        private const val VPN_LOCAL_IP = "10.69.0.2"

        fun saveConfig(ctx: Context, json: String) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_LAST_JSON, json)
                .apply()
        }

        fun getLastConfigJson(ctx: Context): String? =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_JSON, null)

        fun startWithJson(ctx: Context, json: String) {
            saveConfig(ctx, json)
            val i = Intent(ctx, BibaVpnService::class.java).putExtra(EXTRA_CONFIG_JSON, json)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ctx.startForegroundService(i)
            } else {
                ctx.startService(i)
            }
        }

        fun stop(ctx: Context) {
            ctx.startService(
                Intent(ctx, BibaVpnService::class.java).setAction(ACTION_STOP),
            )
        }
    }
}
