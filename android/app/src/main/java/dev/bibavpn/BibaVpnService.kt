package dev.bibavpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.PowerManager
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import dev.bibavpn.core.BibaNative
import dev.bibavpn.core.VpnProtect
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

    /** Старт/стоп Rust JNI: не параллелить с перезапуском после SCREEN_ON. */
    private val nativeLifecycleLock = Any()

    @Volatile
    private var lastScreenOffElapsed: Long = 0L

    @Volatile
    private var lastFullStackRestartElapsed: Long = 0L

    /**
     * true только после успешного [Engine.start] в потоке tun2socks — до этого SCREEN_ON не трогаем стек
     * (иначе гонка с первым [BibaNative.nativeStart]).
     */
    @Volatile
    private var allowScreenOnStackRestart: Boolean = false

    /** Не запускать второй [BibaNative.nativeStart], пока живёт поток первого bootstrap. */
    private val connectThreadLock = Any()

    @Volatile
    private var connectBootstrapThread: Thread? = null

    private var connectivityManager: ConnectivityManager? = null

    /** Синхронизация с [lastPhysicalNetworkForRestart]: не считать сменой сеть при первом известном состоянии. */
    private val networkTrackingLock = Any()

    /**
     * Последняя **физическая** (не VPN) интернет-сеть. Когда VPN поднят, default network в колбэках часто
     * — сам VPN без [NetworkCapabilities.NET_CAPABILITY_NOT_VPN]; обрабатывать её нельзя (иначе цикл перезапусков).
     */
    private var lastPhysicalNetworkForRestart: Network? = null

    /** После смены Wi‑Fi ↔ LTE обновляем underlying network и перезапускаем стек (WSS привязан к старому пути). */
    private val networkRestartHandler = Handler(Looper.getMainLooper())
    private var networkRestartRunnable: Runnable? = null

    private val defaultNetworkCallback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val cm = connectivityManager ?: return
                val caps = cm.getNetworkCapabilities(network) ?: return
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                    Log.d(TAG, "onAvailable skip (not physical / likely VPN): $network")
                    return
                }
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return
                if (!isTunnelActive) return
                val underlying = physicalInternetNetwork(cm) ?: return
                applyUnderlyingNetworks(arrayOf(underlying))
                val shouldRestart =
                    synchronized(networkTrackingLock) {
                        val prev = lastPhysicalNetworkForRestart
                        lastPhysicalNetworkForRestart = underlying
                        prev != null && prev != underlying
                    }
                if (shouldRestart) {
                    Log.i(TAG, "physical network changed -> schedule full restart")
                    scheduleFullRestartAfterNetworkChange()
                }
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                if (!isTunnelActive) return
                if (!networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return
                val cm = connectivityManager ?: return
                val underlying = physicalInternetNetwork(cm) ?: return
                applyUnderlyingNetworks(arrayOf(underlying))
            }
        }

    private val screenOnOffReceiver =
        object : BroadcastReceiver() {
            override fun onReceive(
                context: Context?,
                intent: Intent?,
            ) {
                when (intent?.action) {
                    Intent.ACTION_SCREEN_OFF -> {
                        lastScreenOffElapsed = SystemClock.elapsedRealtime()
                        if (screenOffBatterySaverEnabled() && isTunnelActive) {
                            releaseTunnelWakeLock()
                            Log.i(TAG, "SCREEN_OFF: wake lock released (screen-off battery saver)")
                        }
                    }
                    Intent.ACTION_SCREEN_ON -> {
                        if (screenOffBatterySaverEnabled() && isTunnelActive) {
                            acquireTunnelWakeLock()
                            Log.i(TAG, "SCREEN_ON: wake lock re-acquired (battery saver)")
                        }
                        maybeRestartStackAfterUnlockEvent("SCREEN_ON")
                    }
                    Intent.ACTION_USER_PRESENT -> {
                        if (screenOffBatterySaverEnabled() && isTunnelActive) {
                            acquireTunnelWakeLock()
                            Log.i(TAG, "USER_PRESENT: wake lock re-acquired (battery saver)")
                        }
                        maybeRestartStackAfterUnlockEvent("USER_PRESENT")
                    }
                }
            }
        }

    /**
     * После сна часто «умирает» внешний WSS; поднимаем стек заново.
     * - [Intent.ACTION_SCREEN_ON] без debounce ловит ложные срабатывания (AOD за сотни мс после OFF) — отсекаем короткий интервал.
     * - [Intent.ACTION_USER_PRESENT] — реальная разблокировка; debounce с SCREEN_OFF не применяем (иначе после AOD VPN не восстанавливается).
     */
    private fun maybeRestartStackAfterUnlockEvent(source: String) {
        val now = SystemClock.elapsedRealtime()
        if (!allowScreenOnStackRestart) {
            Log.d(TAG, "$source: skip full restart (allowScreenOnStackRestart=false)")
            return
        }
        if (source == Intent.ACTION_SCREEN_ON && now - lastScreenOffElapsed < 500L) {
            Log.d(
                TAG,
                "$source: skip full restart (display bounce: ${now - lastScreenOffElapsed}ms since SCREEN_OFF)",
            )
            return
        }
        if (now - lastFullStackRestartElapsed < 2500L) {
            Log.d(
                TAG,
                "$source: skip full restart (throttle: ${now - lastFullStackRestartElapsed}ms since last restart)",
            )
            return
        }
        val json = loadSavedConfigJson()
        if (json.isNullOrBlank()) {
            Log.w(TAG, "$source: skip full restart (no saved config)")
            return
        }
        lastFullStackRestartElapsed = now
        Log.i(TAG, "$source: scheduling full stack restart (nativeStop + nativeStart + new TUN + tun2socks)")
        restartFullStackAfterScreenOn(json)
    }

    override fun onBind(intent: Intent?) = null

    override fun onCreate() {
        super.onCreate()
        VpnProtect.vpn = this
        ensureChannel()
        val f =
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_USER_PRESENT)
            }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(screenOnOffReceiver, f, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(screenOnOffReceiver, f)
        }

        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        runCatching {
            connectivityManager?.registerDefaultNetworkCallback(defaultNetworkCallback)
        }.onFailure { e ->
            Log.w(TAG, "registerDefaultNetworkCallback: ${e.message}")
        }
    }

    /** [VpnService.setUnderlyingNetworks] — API 22+; при смене default network без этого трафик VPN может остаться на старом интерфейсе. */
    private fun applyUnderlyingNetworks(networks: Array<Network>) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return
        runCatching {
            setUnderlyingNetworks(networks)
        }.onFailure { e ->
            Log.w(TAG, "setUnderlyingNetworks: ${e.message}")
        }
    }

    private fun scheduleFullRestartAfterNetworkChange() {
        networkRestartRunnable?.let { networkRestartHandler.removeCallbacks(it) }
        val r =
            Runnable {
                networkRestartRunnable = null
                if (!isTunnelActive) return@Runnable
                val json = loadSavedConfigJson()
                if (json.isNullOrBlank()) {
                    Log.w(TAG, "network change: no saved config, skip full restart")
                    return@Runnable
                }
                val now = SystemClock.elapsedRealtime()
                if (now - lastFullStackRestartElapsed < 2500L) {
                    Log.d(TAG, "network change: skip full restart (throttle ${now - lastFullStackRestartElapsed}ms)")
                    return@Runnable
                }
                lastFullStackRestartElapsed = now
                Log.i(TAG, "network change: full stack restart (native + TUN + tun2socks)")
                restartFullStackAfterScreenOn(json)
            }
        networkRestartRunnable = r
        networkRestartHandler.postDelayed(r, 1500L)
    }

    /** Сеть для underlying VPN: только не-VPN с INTERNET (при активном VPN [activeNetwork] часто указывает на TUN). */
    private fun physicalInternetNetwork(cm: ConnectivityManager?): Network? {
        if (cm == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return cm?.activeNetwork
        var fallback: Network? = null
        for (n in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(n) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) continue
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return n
            if (fallback == null) fallback = n
        }
        return fallback
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(
            TAG,
            "onStartCommand action=${intent?.action} flags=0x${Integer.toHexString(flags)} startId=$startId",
        )
        when (intent?.action) {
            ACTION_STOP -> {
                networkRestartRunnable?.let { networkRestartHandler.removeCallbacks(it) }
                networkRestartRunnable = null
                stopTunnelAndNative()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_SYNC_WAKE_LOCK -> {
                if (isTunnelActive && !screenOffBatterySaverEnabled()) {
                    acquireTunnelWakeLock()
                    Log.i(TAG, "SYNC_WAKE_LOCK: wake lock restored (saver off)")
                }
                return START_STICKY
            }
        }

        val fromExtra = intent?.getStringExtra(EXTRA_CONFIG_JSON)
        val json =
            if (intent?.action == ACTION_ENABLE) {
                loadSavedConfigJson()
            } else {
                fromExtra ?: loadSavedConfigJson()
            }
        if (json.isNullOrBlank()) {
            Log.w(TAG, "no config JSON (intent extra and prefs empty) — stopSelf")
            stopSelf()
            return START_NOT_STICKY
        }

        val socks = runCatching {
            JSONObject(json).optString("socks_bind", SOCKS_LOCAL).ifBlank { SOCKS_LOCAL }
        }.getOrDefault(SOCKS_LOCAL)

        Log.i(
            TAG,
            "bootstrap ${configFingerprint(json)} socks=$socks fromIntentExtra=" +
                "${fromExtra != null && intent?.action != ACTION_ENABLE} action=${intent?.action}",
        )

        startForegroundWithNotification()

        if (intent?.action == ACTION_ENABLE) {
            synchronized(connectThreadLock) {
                if (connectBootstrapThread?.isAlive == true) {
                    Log.w(TAG, "ACTION_ENABLE: bootstrap already running — skip")
                    return START_STICKY
                }
            }
            if (isTunnelActive) {
                Log.i(TAG, "ACTION_ENABLE: tunnel up — full stack refresh")
                restartFullStackAfterScreenOn(json)
                return START_STICKY
            }
            enqueueBootstrapWorker(json, socks)
            return START_STICKY
        }

        synchronized(connectThreadLock) {
            if (connectBootstrapThread?.isAlive == true) {
                Log.w(TAG, "bootstrap already running — skip duplicate onStartCommand")
                return START_STICKY
            }
        }

        enqueueBootstrapWorker(json, socks)
        return START_STICKY
    }

    private fun startForegroundWithNotification() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    /** nativeStart ждёт bind SOCKS в Rust — не блокируем main thread (ANR). */
    private fun enqueueBootstrapWorker(
        json: String,
        socks: String,
    ) {
        val worker =
            Thread(
                {
                    val self = Thread.currentThread()
                    try {
                        Log.i(TAG, "worker: nativeStart begin ${configFingerprint(json)}")
                        val err = try {
                            synchronized(nativeLifecycleLock) {
                                BibaNative.nativeStart(json)
                            }
                        } catch (e: Throwable) {
                            Log.e(TAG, "native start", e)
                            e.message ?: e.javaClass.simpleName
                        }
                        if (err != null) {
                            if (err.contains(ERR_ALREADY_RUNNING, ignoreCase = true)) {
                                Log.w(TAG, "nativeStart: $err — оставляем сервис как есть")
                                return@Thread
                            }
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

                        Log.i(TAG, "worker: nativeStart OK — startVpnTunnel")
                        if (!startVpnTunnel(socks)) {
                            Log.e(TAG, "startVpnTunnel returned false — nativeStop + stopSelf")
                            isTunnelActive = false
                            synchronized(nativeLifecycleLock) {
                                BibaNative.nativeStop()
                            }
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
                    } finally {
                        synchronized(connectThreadLock) {
                            if (connectBootstrapThread === self) {
                                connectBootstrapThread = null
                            }
                        }
                    }
                },
                "biba-vpn-start",
            )
        synchronized(connectThreadLock) {
            connectBootstrapThread = worker
        }
        worker.start()
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onDestroy() {
        networkRestartRunnable?.let { networkRestartHandler.removeCallbacks(it) }
        networkRestartRunnable = null
        runCatching { connectivityManager?.unregisterNetworkCallback(defaultNetworkCallback) }
        runCatching { unregisterReceiver(screenOnOffReceiver) }
        if (VpnProtect.vpn === this) {
            VpnProtect.vpn = null
        }
        stopTunnelAndNative()
        super.onDestroy()
    }

    /** Полный перезапуск: остановка tun2socks + Rust, снова nativeStart и новый [Builder.establish]. */
    private fun restartFullStackAfterScreenOn(json: String) {
        val socks =
            runCatching {
                JSONObject(json).optString("socks_bind", SOCKS_LOCAL).ifBlank { SOCKS_LOCAL }
            }.getOrDefault(SOCKS_LOCAL)
        Thread(
            {
                try {
                    synchronized(nativeLifecycleLock) {
                        stopTunnelAndNative()
                        allowScreenOnStackRestart = false
                        val err =
                            try {
                                BibaNative.nativeStart(json)
                            } catch (e: Throwable) {
                                Log.e(TAG, "screen-on nativeStart", e)
                                e.message ?: e.javaClass.simpleName
                            }
                        if (err != null) {
                            Log.e(TAG, "screen-on nativeStart failed: $err")
                            allowScreenOnStackRestart = true
                            mainHandler.post {
                                isTunnelActive = false
                                android.widget.Toast.makeText(
                                    applicationContext,
                                    err,
                                    android.widget.Toast.LENGTH_LONG,
                                ).show()
                            }
                            return@Thread
                        }
                    }
                    if (!startVpnTunnel(socks)) {
                        isTunnelActive = false
                        synchronized(nativeLifecycleLock) {
                            BibaNative.nativeStop()
                        }
                        allowScreenOnStackRestart = true
                        Log.e(TAG, "screen-on startVpnTunnel failed")
                    }
                } catch (e: Throwable) {
                    allowScreenOnStackRestart = true
                    Log.e(TAG, "screen-on full restart", e)
                }
            },
            "biba-screen-on-restart",
        ).start()
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

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                runCatching {
                    physicalInternetNetwork(connectivityManager)?.let { n ->
                        builder.setUnderlyingNetworks(arrayOf(n))
                    }
                }.onFailure { e ->
                    Log.w(TAG, "Builder.setUnderlyingNetworks skipped: ${e.message}")
                }
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
                        allowScreenOnStackRestart = true
                        mainHandler.post {
                            val cm = connectivityManager ?: return@post
                            val und = physicalInternetNetwork(cm) ?: return@post
                            applyUnderlyingNetworks(arrayOf(und))
                            synchronized(networkTrackingLock) {
                                lastPhysicalNetworkForRestart = und
                            }
                        }
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
        synchronized(networkTrackingLock) {
            lastPhysicalNetworkForRestart = null
        }
        allowScreenOnStackRestart = false
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
        synchronized(nativeLifecycleLock) {
            BibaNative.nativeStop()
        }
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

    private fun buildNotification(): Notification {
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
        val enable = PendingIntent.getService(
            this,
            2,
            Intent(this, BibaVpnService::class.java).setAction(ACTION_ENABLE),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_CANCEL_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_vpn)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(openApp)
            .addAction(0, getString(R.string.notification_action_disable), stop)
            .addAction(0, getString(R.string.notification_action_enable), enable)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun loadSavedConfigJson(): String? =
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_JSON, null)

    /** См. [Companion.isScreenOffBatterySaverEnabled]. */
    private fun screenOffBatterySaverEnabled(): Boolean =
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_SCREEN_OFF_BATTERY_SAVER, false)

    companion object {
        /** true после успешного Engine.start() tun2socks; сбрасывается при остановке. */
        @Volatile
        var isTunnelActive: Boolean = false
            private set

        private const val ERR_ALREADY_RUNNING = "already running"

        private const val TAG = "BibaVpnService"
        private const val CHANNEL_ID = "bibavpn_proxy"
        private const val NOTIFICATION_ID = 42
        const val ACTION_STOP = "dev.bibavpn.STOP"
        const val ACTION_ENABLE = "dev.bibavpn.ENABLE"
        const val ACTION_SYNC_WAKE_LOCK = "dev.bibavpn.SYNC_WAKE_LOCK"

        /** После выключения «экономии при блокировке» восстановить wake lock, если туннель ещё активен. */
        fun requestSyncWakeLock(ctx: Context) {
            ctx.startService(
                Intent(ctx, BibaVpnService::class.java).setAction(ACTION_SYNC_WAKE_LOCK),
            )
        }
        const val EXTRA_CONFIG_JSON = "config_json"
        private const val PREFS = "bibavpn"
        private const val KEY_LAST_JSON = "last_config_json"
        /**
         * Если true: при ACTION_SCREEN_OFF снимаем PARTIAL_WAKE_LOCK, при SCREEN_ON/USER_PRESENT снова берём.
         * Экономит батарею при заблокированном телефоне; VPN и foreground service остаются, но возможны чаще обрывы WSS в Doze.
         */
        private const val KEY_SCREEN_OFF_BATTERY_SAVER = "screen_off_battery_saver"
        /** Конфиг на время [VpnService.prepare] — Activity может быть убита до возврата из системного диалога. */
        private const val KEY_PENDING_AFTER_PREPARE = "pending_after_vpn_prepare"

        fun isScreenOffBatterySaverEnabled(ctx: Context): Boolean =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(
                KEY_SCREEN_OFF_BATTERY_SAVER,
                false,
            )

        fun setScreenOffBatterySaver(
            ctx: Context,
            enabled: Boolean,
        ) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_SCREEN_OFF_BATTERY_SAVER, enabled)
                .apply()
        }

        fun stashPendingConnectJson(ctx: Context, json: String) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_PENDING_AFTER_PREPARE, json)
                .apply()
        }

        fun takePendingConnectJson(ctx: Context): String? {
            val sp = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val v = sp.getString(KEY_PENDING_AFTER_PREPARE, null) ?: return null
            sp.edit().remove(KEY_PENDING_AFTER_PREPARE).apply()
            return v
        }

        fun clearPendingConnectJson(ctx: Context) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .remove(KEY_PENDING_AFTER_PREPARE)
                .apply()
        }

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
            Log.i(TAG, "startWithJson ${configFingerprint(json)}")
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

        /** Длина и короткий отпечаток JSON без вывода содержимого в лог. */
        private fun configFingerprint(json: String): String =
            "len=${json.length} fp=${Integer.toHexString(json.hashCode())}"
    }
}
