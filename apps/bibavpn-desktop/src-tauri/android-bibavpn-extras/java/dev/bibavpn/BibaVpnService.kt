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
import android.net.IpPrefix
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.PowerManager
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import java.net.Inet4Address
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
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

    /** После [stopTunnelAndNative] из STOP/abort не повторять в [onDestroy] — двойной nativeStop может уронить процесс. */
    @Volatile
    private var tunnelTeardownDoneBeforeDestroy: Boolean = false

    /** Разбор стека идёт в воркере ([enqueueTeardownWorker]) — не запускать второй. */
    @Volatile
    private var teardownInProgress: Boolean = false

    /** Поток текущего разбора: [onDestroy] ждёт его недолго, чтобы `nativeStop` успел. */
    @Volatile
    private var teardownThread: Thread? = null

    private val tunLock = Any()
    private var tun2socksThread: Thread? = null
    /** Java держит свой dup TUN fd; в Go отдаём отдельный dup, чтобы не спорить за ownership с fdsan. */
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
    private var pendingPhysicalNetworkRestart: Network? = null

    /** После смены Wi‑Fi ↔ LTE обновляем underlying network и перезапускаем стек (WSS привязан к старому пути). */
    private val networkRestartHandler = Handler(Looper.getMainLooper())
    private var networkRestartRunnable: Runnable? = null
    private val restartLock = Any()

    @Volatile
    private var fullStackRestartInProgress: Boolean = false

    @Volatile
    private var fullStackRestartQueued: Boolean = false

    private val physicalNetworkCallback =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handlePhysicalNetworkSignal("onAvailable", network)
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) {
                if (!networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return
                handlePhysicalNetworkSignal("onCapabilitiesChanged", network)
            }

            override fun onLost(network: Network) {
                handlePhysicalNetworkSignal("onLost", network)
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
        requestFullStackRestart(source, json)
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
            val request =
                NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()
            connectivityManager?.registerNetworkCallback(request, physicalNetworkCallback)
        }.onFailure { e ->
            Log.w(TAG, "registerNetworkCallback(physical): ${e.message}")
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

    private fun scheduleFullRestartAfterNetworkChange(targetNetwork: Network) {
        synchronized(networkTrackingLock) {
            pendingPhysicalNetworkRestart = targetNetwork
        }
        networkRestartRunnable?.let { networkRestartHandler.removeCallbacks(it) }
        val r =
            Runnable {
                networkRestartRunnable = null
                if (!isTunnelActive) return@Runnable
                val cm = connectivityManager
                val stillPending =
                    synchronized(networkTrackingLock) {
                        pendingPhysicalNetworkRestart == targetNetwork &&
                            lastPhysicalNetworkForRestart == targetNetwork
                    }
                val stableSelection = cm != null && physicalInternetNetwork(cm) == targetNetwork
                if (!stillPending || !stableSelection) {
                    Log.d(TAG, "network change: skip full restart (selection changed before debounce)")
                    return@Runnable
                }
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
                requestFullStackRestart("network change", json)
            }
        networkRestartRunnable = r
        networkRestartHandler.postDelayed(r, 1500L)
    }

    /** Сеть для underlying VPN: только не-VPN с INTERNET (при активном VPN [activeNetwork] часто указывает на TUN). */
    private fun physicalInternetNetwork(cm: ConnectivityManager?): Network? {
        if (cm == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return cm?.activeNetwork
        cm.activeNetwork?.let { active ->
            val caps = cm.getNetworkCapabilities(active)
            if (caps != null && isUsablePhysicalInternet(caps)) return active
        }
        var validatedWifi: Network? = null
        var validatedCellular: Network? = null
        var validatedOther: Network? = null
        var fallback: Network? = null
        for (n in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(n) ?: continue
            if (!isUsablePhysicalInternet(caps)) continue
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) && validatedWifi == null -> validatedWifi = n
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) && validatedCellular == null -> validatedCellular = n
                    validatedOther == null -> validatedOther = n
                }
                continue
            }
            if (fallback == null) fallback = n
        }
        return validatedWifi ?: validatedCellular ?: validatedOther ?: fallback
    }

    private fun isUsablePhysicalInternet(caps: NetworkCapabilities): Boolean =
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)

    private fun shouldPromotePhysicalNetwork(
        cm: ConnectivityManager,
        current: Network,
        candidate: Network,
    ): Boolean {
        if (current == candidate) return false
        val currentCaps = cm.getNetworkCapabilities(current)
        val candidateCaps = cm.getNetworkCapabilities(candidate) ?: return false
        if (currentCaps == null || !isUsablePhysicalInternet(currentCaps)) return true
        val currentValidated = currentCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val candidateValidated = candidateCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        if (candidateValidated && !currentValidated) return true
        val currentCellular = currentCaps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        val candidateWifi = candidateCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        return currentCellular && candidateWifi && candidateValidated
    }

    private fun handlePhysicalNetworkSignal(
        source: String,
        network: Network,
    ) {
        if (!isTunnelActive) return
        val cm = connectivityManager ?: return
        val selected = physicalInternetNetwork(cm)
        val networkToApply: Network
        var shouldRestart = false
        synchronized(networkTrackingLock) {
            val current = lastPhysicalNetworkForRestart
            when {
                selected == null -> {
                    if (current == network) {
                        lastPhysicalNetworkForRestart = null
                        pendingPhysicalNetworkRestart = null
                        Log.i(TAG, "$source: lost current physical network and no replacement yet")
                    }
                    return
                }
                current == null -> {
                    lastPhysicalNetworkForRestart = selected
                    pendingPhysicalNetworkRestart = null
                    networkToApply = selected
                }
                current == selected -> {
                    pendingPhysicalNetworkRestart = null
                    networkToApply = current
                }
                shouldPromotePhysicalNetwork(cm, current, selected) || current == network -> {
                    lastPhysicalNetworkForRestart = selected
                    pendingPhysicalNetworkRestart = selected
                    networkToApply = selected
                    shouldRestart = true
                }
                else -> {
                    networkToApply = current
                }
            }
        }
        applyUnderlyingNetworks(arrayOf(networkToApply))
        if (shouldRestart) {
            Log.i(TAG, "$source: physical network changed -> schedule full restart")
            scheduleFullRestartAfterNetworkChange(networkToApply)
        }
    }

    private fun requestFullStackRestart(
        reason: String,
        json: String,
    ) {
        val shouldStartNow =
            synchronized(restartLock) {
                if (fullStackRestartInProgress) {
                    fullStackRestartQueued = true
                    false
                } else {
                    fullStackRestartInProgress = true
                    true
                }
            }
        if (!shouldStartNow) {
            Log.i(TAG, "$reason: full restart already in progress, queued one follow-up run")
            return
        }
        performFullStackRestart(reason, json)
    }

    private fun performFullStackRestart(
        reason: String,
        json: String,
    ) {
        val sessionJson = configJsonWithSessionSocksAuth(json)
        Thread(
            {
                try {
                    Log.i(TAG, "$reason: begin full stack restart")
                    synchronized(nativeLifecycleLock) {
                        stopTunnelAndNative()
                        allowScreenOnStackRestart = false
                        val err =
                            try {
                                BibaNative.nativeStart(sessionJson)
                            } catch (e: Throwable) {
                                Log.e(TAG, "$reason: nativeStart", e)
                                e.message ?: e.javaClass.simpleName
                            }
                        if (err != null) {
                            Log.e(TAG, "$reason: nativeStart failed: $err")
                            allowScreenOnStackRestart = true
                            mainHandler.post {
                                setTunnelActive(false)
                                android.widget.Toast.makeText(
                                    applicationContext,
                                    err,
                                    android.widget.Toast.LENGTH_LONG,
                                ).show()
                            }
                            return@Thread
                        }
                    }
                    if (!startVpnTunnel(tun2socksProxyFromSessionJson(sessionJson))) {
                        setTunnelActive(false)
                        synchronized(nativeLifecycleLock) {
                            BibaNative.nativeStop()
                        }
                        allowScreenOnStackRestart = true
                        Log.e(TAG, "$reason: startVpnTunnel failed")
                    }
                } catch (e: Throwable) {
                    allowScreenOnStackRestart = true
                    Log.e(TAG, "$reason: full restart", e)
                } finally {
                    val rerun =
                        synchronized(restartLock) {
                            val queued = fullStackRestartQueued
                            fullStackRestartQueued = false
                            fullStackRestartInProgress = false
                            queued
                        }
                    if (rerun) {
                        val latestJson = loadSavedConfigJson()
                        if (!latestJson.isNullOrBlank()) {
                            Log.i(TAG, "$reason: running queued full restart")
                            requestFullStackRestart("$reason (queued)", latestJson)
                        }
                    }
                }
            },
            "biba-full-restart",
        ).start()
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
                enqueueTeardownWorker("ACTION_STOP") {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
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

        val sessionJson = configJsonWithSessionSocksAuth(json)
        val socks = runCatching {
            JSONObject(sessionJson).optString("socks_bind", SOCKS_LOCAL).ifBlank { SOCKS_LOCAL }
        }.getOrDefault(SOCKS_LOCAL)

        Log.i(
            TAG,
            "bootstrap ${configFingerprint(sessionJson)} socks=$socks fromIntentExtra=" +
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
                requestFullStackRestart("ACTION_ENABLE", json)
                return START_STICKY
            }
            enqueueBootstrapWorker(sessionJson)
            return START_STICKY
        }

        synchronized(connectThreadLock) {
            if (connectBootstrapThread?.isAlive == true) {
                Log.w(TAG, "bootstrap already running — skip duplicate onStartCommand")
                return START_STICKY
            }
        }

        enqueueBootstrapWorker(sessionJson)
        return START_STICKY
    }

    private fun startForegroundWithNotification() {
        ensureChannel()
        applyForegroundNotification(buildNotification())
    }

    private fun applyForegroundNotification(notification: Notification) {
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

    /** Обновить текст «подключение / активен» в постоянном уведомлении (шторка). */
    private fun refreshForegroundNotification() {
        ensureChannel()
        try {
            applyForegroundNotification(buildNotification())
        } catch (e: Throwable) {
            Log.w(TAG, "refreshForegroundNotification", e)
        }
    }

    /** nativeStart ждёт bind SOCKS в Rust — не блокируем main thread (ANR). */
    private fun enqueueBootstrapWorker(sessionJson: String) {
        val worker =
            Thread(
                {
                    val self = Thread.currentThread()
                    try {
                        Log.i(TAG, "worker: nativeStart begin ${configFingerprint(sessionJson)}")
                        val err = try {
                            synchronized(nativeLifecycleLock) {
                                BibaNative.nativeStart(sessionJson)
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
                            setTunnelActive(false)
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
                        if (!startVpnTunnel(tun2socksProxyFromSessionJson(sessionJson))) {
                            Log.e(TAG, "startVpnTunnel returned false — nativeStop + stopSelf")
                            setTunnelActive(false)
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
                        setTunnelActive(false)
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
        runCatching { connectivityManager?.unregisterNetworkCallback(physicalNetworkCallback) }
        runCatching { unregisterReceiver(screenOnOffReceiver) }
        if (VpnProtect.vpn === this) {
            VpnProtect.vpn = null
        }
        if (!tunnelTeardownDoneBeforeDestroy) {
            // Страховка: разбор не начинали (сервис снят системой, а не через STOP).
            // Уносить в воркер поздно — процесс может умереть сразу после onDestroy;
            // сверху время здесь ограничивает STOP_JOIN_TIMEOUT в JNI.
            stopTunnelAndNative()
        } else {
            // Разбор уже идёт в воркере: ждём его недолго, иначе daemon-поток убьют
            // вместе с процессом на середине nativeStop.
            teardownThread?.let { t ->
                try {
                    t.join(3000)
                } catch (_: InterruptedException) {
                }
            }
        }
        super.onDestroy()
    }

    /** @param proxyUrl полный URL для tun2socks, например `socks5://user:pass@127.0.0.1:1080`. */
    private fun startVpnTunnel(proxyUrl: String): Boolean {
        synchronized(tunLock) {
            stopTun2socksOnly()
            // MTU ниже 1500: запас под Encapsulation (TUN → SOCKS → WSS); иначе фрагментация/чёрные дыры на LTE.
            val tunMtu = 1400
            val builder = Builder()
                .setSession("BibaVPN")
                .setMtu(tunMtu)
                .addAddress(VPN_LOCAL_IP, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
            builder.addDisallowedApplication(packageName)
            builder.applySplitTunnelBypasses()
            builder.applySplitTunnelDomainBypasses()
            // Не добавляем ::/0: у многих сборок tun2socks UDP/IPv6 через TUN неполный — тогда AAAA/DNS v6 «висят».

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

            val javaOwnedTun = try {
                ParcelFileDescriptor.dup(pfd.fileDescriptor)
            } catch (e: Exception) {
                Log.e(TAG, "dup(tun fd)", e)
                pfd.close()
                return false
            }

            val fd = try {
                val engineTun = ParcelFileDescriptor.dup(pfd.fileDescriptor)
                val detached = engineTun.detachFd()
                pfd.close()
                detached
            } catch (e: Exception) {
                Log.e(TAG, "detachFd(engine tun)", e)
                javaOwnedTun.close()
                pfd.close()
                return false
            }
            runCatching { tunParcelOrphan?.close() }
            tunParcelOrphan = javaOwnedTun

            val proxy = proxyUrl.trim()
            val startLatch = CountDownLatch(1)
            val startErr = AtomicReference<String?>(null)
            tun2socksThread = Thread(
                {
                    try {
                        val key = Key()
                        key.setDevice("fd://$fd")
                        key.setProxy(proxy)
                        key.setMTU(tunMtu.toLong())
                        // П последним setter'ом: в некоторых gomobile-биндингах поля сбрасываются при других set* .
                        key.setLogLevel("info")
                        Log.i(TAG, "tun2socks Key.logLevel=${key.logLevel}")
                        Engine.insert(key)
                        Engine.start()
                        acquireTunnelWakeLock()
                        setTunnelActive(true)
                        allowScreenOnStackRestart = true
                        mainHandler.post {
                            refreshForegroundNotification()
                            val cm = connectivityManager ?: return@post
                            val und = physicalInternetNetwork(cm) ?: return@post
                            applyUnderlyingNetworks(arrayOf(und))
                            synchronized(networkTrackingLock) {
                                lastPhysicalNetworkForRestart = und
                            }
                        }
                        Log.i(TAG, "tun2socks Engine.start OK")
                    } catch (e: Throwable) {
                        Log.e(TAG, "tun2socks", e)
                        startErr.set(e.message ?: e.javaClass.simpleName)
                        mainHandler.post { abortVpnFromWorker(e.message) }
                    } finally {
                        startLatch.countDown()
                    }
                },
                "biba-tun2socks",
            ).also { it.start() }

            val ok = startLatch.await(25, TimeUnit.SECONDS)
            if (!ok) {
                Log.e(TAG, "tun2socks: Engine.start timeout (${25}s) — останавливаем")
                tun2socksThread?.interrupt()
                stopTun2socksOnly()
                return false
            }
            startErr.get()?.let { err ->
                Log.e(TAG, "tun2socks failed: $err")
                stopTun2socksOnly()
                return false
            }
            Log.i(TAG, "VPN up, tun2socks -> ${proxyUrlForLog(proxy)}")
            return true
        }
    }

    /**
     * Трафик выбранных приложений не идёт в TUN (прямой IP), если включено в настройках.
     * Нет пакета на устройстве — [addDisallowedApplication] бросает, игнорируем.
     */
    private fun Builder.applySplitTunnelBypasses() {
        if (!isSplitTunnelEnabled(this@BibaVpnService)) return
        val selected = getSplitTunnelSelectedPackages(this@BibaVpnService)
        for (pkg in selected) {
            if (pkg == packageName) continue
            runCatching { addDisallowedApplication(pkg) }.onFailure { e ->
                Log.d(TAG, "split tunnel: не добавлен $pkg (${e.message})")
            }
        }
    }

    /**
     * Домены из preset API → IPv4 excludeRoute (API 33+). Трафик к этим IP не идёт в TUN.
     * IP фиксируются при подключении; после смены CDN переподключите VPN.
     */
    private fun Builder.applySplitTunnelDomainBypasses() {
        if (!isSplitTunnelEnabled(this@BibaVpnService)) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            Log.i(
                TAG,
                "split tunnel domains: excludeRoute requires Android 13+ (API ${Build.VERSION.SDK_INT}); use per-app bypass",
            )
            return
        }
        val hosts = normalizeBypassHosts(getSplitTunnelBypassDomains(this@BibaVpnService))
        if (hosts.isEmpty()) return

        val seenIps = LinkedHashSet<String>()
        var excludeCount = 0
        for (host in hosts) {
            if (excludeCount >= MAX_DOMAIN_ROUTE_EXCLUSIONS) {
                Log.w(TAG, "split tunnel domains: cap $MAX_DOMAIN_ROUTE_EXCLUSIONS excludeRoute(s)")
                break
            }
            val addrs =
                runCatching { InetAddress.getAllByName(host) }.getOrElse { e ->
                    Log.w(TAG, "split tunnel: resolve $host failed: ${e.message}")
                    return@getOrElse emptyArray()
                }
            for (addr in addrs) {
                if (excludeCount >= MAX_DOMAIN_ROUTE_EXCLUSIONS) break
                if (addr !is Inet4Address) continue
                val ip = addr.hostAddress ?: continue
                if (!seenIps.add(ip)) continue
                runCatching {
                    excludeRoute(IpPrefix(addr, 32))
                }.onSuccess {
                    excludeCount++
                    Log.i(TAG, "split tunnel: excludeRoute $ip/32 ($host)")
                }.onFailure { e ->
                    Log.w(TAG, "split tunnel: excludeRoute $ip failed: ${e.message}")
                }
            }
        }
        Log.i(
            TAG,
            "split tunnel domains: $excludeCount excludeRoute(s) from ${hosts.size} host(s)",
        )
    }

    private fun normalizeBypassHosts(raw: Set<String>): List<String> {
        val out = LinkedHashSet<String>()
        for (entry in raw) {
            var s = entry.trim().lowercase()
            if (s.isEmpty()) continue
            if (s.startsWith("http://")) s = s.removePrefix("http://")
            if (s.startsWith("https://")) s = s.removePrefix("https://")
            s = s.substringBefore('/').substringBefore(':')
            if (s.startsWith("*.")) s = s.removePrefix("*.")
            if (s.isEmpty() || s == "localhost") continue
            out.add(s)
        }
        return out.toList()
    }

    private fun abortVpnFromWorker(detail: String?) {
        Handler(Looper.getMainLooper()).post {
            val msg =
                getString(
                    R.string.vpn_error_prefix,
                    detail?.takeIf { it.isNotBlank() } ?: getString(R.string.vpn_error_tun2socks),
                )
            android.widget.Toast.makeText(applicationContext, msg, android.widget.Toast.LENGTH_LONG)
                .show()
            enqueueTeardownWorker("abort") {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * Разбор стека вне главного потока.
     *
     * [stopTunnelAndNative] блокирует надолго: `tunLock` может держать воркер перезапуска,
     * ожидающий `Engine.start` до 25 с, затем идут `Engine.stop` + `join(8000)` у потока
     * tun2socks и `nativeStop` (join клиентского потока, ограничен 5 с в JNI). На главном
     * потоке это ANR — то же самое, из-за чего [enqueueBootstrapWorker] уже уносит
     * `nativeStart` в отдельный поток.
     *
     * Флаг [tunnelTeardownDoneBeforeDestroy] и `setTunnelActive(false)` ставим сразу, до
     * ухода в воркер: тогда [onDestroy] не начнёт второй разбор, а триггеры перезапуска
     * (SCREEN_ON / USER_PRESENT / смена сети) сразу видят неактивный туннель.
     *
     * @param onDone выполняется на главном потоке после завершения разбора.
     */
    private fun enqueueTeardownWorker(reason: String, onDone: (() -> Unit)? = null) {
        if (teardownInProgress) {
            Log.i(TAG, "$reason: teardown already in progress")
            return
        }
        teardownInProgress = true
        tunnelTeardownDoneBeforeDestroy = true
        setTunnelActive(false)
        Thread(
            {
                try {
                    Log.i(TAG, "$reason: teardown begin (worker)")
                    stopTunnelAndNative()
                    Log.i(TAG, "$reason: teardown done")
                } catch (e: Throwable) {
                    Log.e(TAG, "$reason: teardown", e)
                } finally {
                    teardownThread = null
                    mainHandler.post {
                        teardownInProgress = false
                        onDone?.invoke()
                    }
                }
            },
            "biba-teardown",
        ).also {
            it.isDaemon = true
            teardownThread = it
            it.start()
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
        setTunnelActive(false)
        synchronized(networkTrackingLock) {
            lastPhysicalNetworkForRestart = null
            pendingPhysicalNetworkRestart = null
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
            runCatching { tunParcelOrphan?.close() }
            tunParcelOrphan = null
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
        val tunnelUp = Companion.isTunnelActive
        val titleRes =
            if (tunnelUp) R.string.notification_title else R.string.notification_title_connecting
        val textRes =
            if (tunnelUp) R.string.notification_text else R.string.notification_text_connecting
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
            .setContentTitle(getString(titleRes))
            .setContentText(getString(textRes))
            .setContentIntent(openApp)
            .addAction(0, getString(R.string.notification_action_disable), stop)
            .addAction(0, getString(R.string.notification_action_enable), enable)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }

    private fun loadSavedConfigJson(): String? =
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_LAST_JSON, null)

    private val socksRandom = SecureRandom()

    private fun randomSocksCredential(length: Int): String {
        val alphabet = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        return buildString(length) {
            repeat(length) { append(alphabet[socksRandom.nextInt(alphabet.size)]) }
        }
    }

    /**
     * Случайный логин/пароль для локального SOCKS5 на эту сессию (Rust listener + tun2socks).
     * В хранилище профиля не попадает.
     */
    private fun configJsonWithSessionSocksAuth(baseJson: String): String {
        val o = JSONObject(baseJson)
        o.remove("socks_auth_user")
        o.remove("socks_auth_password")
        o.put("socks_auth_user", randomSocksCredential(16))
        o.put("socks_auth_password", randomSocksCredential(24))
        applyInviteProtoDomainFallback(o)
        applyLegacyPadModeForBundledNative(o)
        capWsParallelForUdpMux(o)
        return o.toString()
    }

    /**
     * UDP mux поднимает отдельный полный TLS+WSS поверх уже существующих параллельных mux-сессий ([ws_parallel] до 4).
     * Суммарно получается много одновременных TLS к одному хосту; часть сетей/CDN закрывает лишние с `unexpected-eof`,
     * после чего не работает DNS (UDP) и «интернета нет» при живом TCP.
     */
    private fun capWsParallelForUdpMux(o: JSONObject) {
        if (!o.optBoolean("use_tcp_mux", true)) return
        val cur = o.optInt("ws_parallel", 1).coerceIn(1, 4)
        if (cur > 1) {
            o.put("ws_parallel", 1)
            Log.i(TAG, "config: ws_parallel=1 for this session (was $cur) — extra WSS + UDP mux TLS were failing")
        }
    }

    /**
     * Old invites may omit `proto_domain`, while the server's v3 default is actually `default`.
     * That makes the client fall back to SNI/IP and fail ACK MAC on UDP mux.
     */
    private fun applyInviteProtoDomainFallback(o: JSONObject) {
        if (o.optString("proto_domain", "").trim().isNotEmpty()) return
        val invite = o.optString("from_invite", "").trim()
        val pass = o.optString("invite_passphrase", "")
        if (invite.isBlank() || pass.isBlank()) return

        val decoded =
            runCatching {
                val raw = BibaNative.nativeDecodeInvite(invite, pass)
                JSONObject(raw)
            }.getOrNull()
                ?: return
        if (!decoded.optBoolean("ok")) return

        val invProtoDomain = decoded.optString("proto_domain", "").trim()
        if (invProtoDomain.isNotEmpty()) {
            o.put("proto_domain", invProtoDomain)
            Log.i(TAG, "config: proto_domain taken from invite: $invProtoDomain")
            return
        }

        val proto = o.optInt("proto", decoded.optInt("proto", 3))
        val psk = o.optString("psk", decoded.optString("psk", "")).trim()
        if (proto >= 3 && psk.isNotEmpty()) {
            o.put("proto_domain", "default")
            Log.w(TAG, "config: invite missing proto_domain; falling back to server default 'default'")
        }
    }

    /**
     * В jniLibs может лежать lib без поддержки [pad_mode] `adaptive` (ошибка parse: use random or http-buckets).
     * В Rust top-level `pad_mode` перекрывает значение из invite.
     *
     * Раньше подставляли `random`, из‑за чего UDP mux (DNS) мог отваливаться, если сервер ожидал не random‑паддинг.
     * Для `adaptive` используем `http-buckets` — тот же wire‑формат, другой закон распределения паддинга, обычно ближе к серверу.
     */
    private fun applyLegacyPadModeForBundledNative(o: JSONObject) {
        val current = o.optString("pad_mode", "").trim()
        if (current.equals("adaptive", ignoreCase = true)) {
            o.put("pad_mode", "http-buckets")
            return
        }
        if (current.isNotEmpty()) return

        val invite = o.optString("from_invite", "").trim()
        val pass = o.optString("invite_passphrase", "")
        if (invite.isBlank() || pass.isBlank()) return

        val invPad =
            runCatching {
                val raw = BibaNative.nativeDecodeInvite(invite, pass)
                val j = JSONObject(raw)
                if (!j.optBoolean("ok")) return@runCatching null
                j.optString("pad_mode", "").trim()
            }.getOrNull()
                ?: return

        val legacy =
            when {
                invPad.isEmpty() || invPad.equals("adaptive", ignoreCase = true) -> "http-buckets"
                invPad.equals("random", ignoreCase = true) -> "random"
                invPad.equals("http-buckets", ignoreCase = true) ||
                    invPad.equals("buckets", ignoreCase = true) -> "http-buckets"
                else -> null
            }
        if (legacy != null) o.put("pad_mode", legacy)
    }

    private fun tun2socksProxyFromSessionJson(sessionJson: String): String {
        val o = JSONObject(sessionJson)
        val raw = o.optString("socks_bind", SOCKS_LOCAL).ifBlank { SOCKS_LOCAL }
        val hostPort = raw.removePrefix("socks5://").removePrefix("SOCKS5://")
        val u = o.optString("socks_auth_user", "")
        val p = o.optString("socks_auth_password", "")
        check(u.isNotEmpty() && p.isNotEmpty()) { "session SOCKS auth missing after inject" }
        return "socks5://$u:$p@$hostPort"
    }

    private fun proxyUrlForLog(proxy: String): String {
        val s = proxy.trim()
        val schemeEnd = s.indexOf("://")
        if (schemeEnd < 0) return s
        val scheme = s.substring(0, schemeEnd)
        val rest = s.substring(schemeEnd + 3)
        val at = rest.lastIndexOf('@')
        if (at <= 0) return s
        val host = rest.substring(at + 1)
        return "$scheme://***@$host"
    }

    /** См. [Companion.isScreenOffBatterySaverEnabled]. */
    private fun screenOffBatterySaverEnabled(): Boolean =
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_SCREEN_OFF_BATTERY_SAVER, false)

    companion object {
        /** true после успешного Engine.start() tun2socks; сбрасывается при остановке. */
        @Volatile
        var isTunnelActive: Boolean = false
            private set

        /** Якорь [SystemClock.elapsedRealtime] в момент [setTunnelActive](true); 0 если туннеля нет. */
        @Volatile
        private var tunnelConnectedSinceElapsed: Long = 0L

        /** Длительность текущей VPN-сессии (устойчиво к смене пользовательских часов). */
        @JvmStatic
        fun tunnelSessionElapsedMillis(): Long {
            if (!isTunnelActive || tunnelConnectedSinceElapsed == 0L) return 0L
            return SystemClock.elapsedRealtime() - tunnelConnectedSinceElapsed
        }

        private fun setTunnelActive(active: Boolean) {
            if (active) {
                isTunnelActive = true
                tunnelConnectedSinceElapsed = SystemClock.elapsedRealtime()
            } else {
                isTunnelActive = false
                tunnelConnectedSinceElapsed = 0L
            }
        }

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
        private const val KEY_SPLIT_TUNNEL_ENABLED = "split_tunnel_enabled"
        private const val KEY_SPLIT_TUNNEL_PACKAGES = "split_tunnel_packages"
        private const val KEY_SPLIT_TUNNEL_DOMAINS = "split_tunnel_domains"
        /** Лимит excludeRoute при резолве preset-доменов (защита от раздувания VPN config). */
        private const val MAX_DOMAIN_ROUTE_EXCLUSIONS = 128

        /** Раздельный туннель: выбранные приложения в обход VPN (прямой IP). */
        fun isSplitTunnelEnabled(ctx: Context): Boolean =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(
                KEY_SPLIT_TUNNEL_ENABLED,
                false,
            )

        fun getSplitTunnelSelectedPackages(ctx: Context): Set<String> =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getStringSet(KEY_SPLIT_TUNNEL_PACKAGES, null)
                ?.toHashSet()
                ?: emptySet()

        fun getSplitTunnelBypassDomains(ctx: Context): Set<String> =
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getStringSet(KEY_SPLIT_TUNNEL_DOMAINS, null)
                ?.toHashSet()
                ?: emptySet()

        fun setSplitTunnelConfig(
            ctx: Context,
            enabled: Boolean,
            packages: Set<String>,
            domains: Set<String> = emptySet(),
        ) {
            val domainSet =
                HashSet(
                    domains.map { it.trim() }.filter { it.isNotEmpty() },
                )
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_SPLIT_TUNNEL_ENABLED, enabled)
                .putStringSet(KEY_SPLIT_TUNNEL_PACKAGES, HashSet(packages))
                .putStringSet(KEY_SPLIT_TUNNEL_DOMAINS, domainSet)
                .apply()
        }

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
