package dev.bibavpn

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import dev.bibavpn.core.BibaNative
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import org.json.JSONArray
import org.json.JSONObject

private val BgRoot = Color(0xFF070B14)
private val BgScreen = Color(0xFF0B0F1A)
private val CardBg = Color(0xFF121826)
private val LabelSky = Color(0xFF60A5FA)
private val TextMuted = Color(0xFF94A3B8)
private val TextSlate200 = Color(0xFFE2E8F0)
private val Mint = Color(0xFF00FFA3)
private val MintSoft = Color(0xFF34D399)
private val BorderSubtle = Color.White.copy(alpha = 0.08f)
private val MainButtonBrush = Brush.verticalGradient(
    listOf(Color(0xFF1A2950), Color(0xFF14203C)),
)
private val MainButtonBorder = Color(0x3360A5FA)

class MainActivity : ComponentActivity() {

    private val notifPerm = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    private var pendingConnectJson: String? = null

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val json =
            pendingConnectJson
                ?: BibaVpnService.takePendingConnectJson(this)
        pendingConnectJson = null
        if (result.resultCode != RESULT_OK) {
            BibaVpnService.clearPendingConnectJson(this)
            Log.w(TAG, "VpnService.prepare: denied or cancelled resultCode=${result.resultCode}")
            return@registerForActivityResult
        }
        if (json == null) {
            Log.w(TAG, "VpnService.prepare: OK but pending config lost (memory + prefs empty)")
            return@registerForActivityResult
        }
        BibaVpnService.clearPendingConnectJson(this)
        Log.i(
            TAG,
            "VpnService.prepare OK — start service len=${json.length} fp=${Integer.toHexString(json.hashCode())}",
        )
        BibaVpnService.startWithJson(this, json)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingConnectJson =
            pendingConnectJson ?: savedInstanceState?.getString(STATE_PENDING_VPN_JSON)
        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        setContent {
            MaterialTheme {
                Surface(color = BgRoot) {
                    BibaRootScreen(
                        onRequestVpnConnect = { json ->
                            val prep = VpnService.prepare(this@MainActivity)
                            if (prep != null) {
                                pendingConnectJson = json
                                BibaVpnService.stashPendingConnectJson(this@MainActivity, json)
                                vpnPermission.launch(prep)
                            } else {
                                BibaVpnService.clearPendingConnectJson(this@MainActivity)
                                BibaVpnService.startWithJson(this@MainActivity, json)
                            }
                        },
                    )
                }
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        pendingConnectJson?.let { outState.putString(STATE_PENDING_VPN_JSON, it) }
    }

    private companion object {
        private const val TAG = "BibaMain"
        private const val STATE_PENDING_VPN_JSON = "pending_vpn_json"
    }
}

@Composable
private fun BibaRootScreen(
    onRequestVpnConnect: (String) -> Unit,
) {
    val context = LocalContext.current
    var showSettings by remember { mutableStateOf(false) }
    var tunnelUp by remember { mutableStateOf(BibaVpnService.isTunnelActive) }

    val last = remember {
        BibaVpnService.getLastConfigJson(context)?.let { runCatching { JSONObject(it) }.getOrNull() }
    }

    var server by remember { mutableStateOf(last?.optString("server") ?: "") }
    var token by remember { mutableStateOf(last?.optString("token") ?: "") }
    var tokenVisible by remember { mutableStateOf(false) }
    var sni by remember { mutableStateOf(last?.optString("sni") ?: "") }
    var psk by remember { mutableStateOf(last?.optString("psk") ?: "") }
    var pskVisible by remember { mutableStateOf(false) }
    var socksBind by remember { mutableStateOf(last?.optString("socks_bind") ?: "") }
    var insecure by remember { mutableStateOf(last?.optBoolean("insecure") ?: false) }
    var maxPad by remember { mutableStateOf(last?.optInt("max_pad")?.toString() ?: "64") }
    var decoyMax by remember { mutableStateOf(last?.optInt("decoy_max")?.toString() ?: "32") }
    var junkFrames by remember { mutableStateOf(last?.optInt("junk_frames")?.toString() ?: "0") }
    var earlyWs by remember { mutableStateOf(last?.optInt("early_ws_frames")?.toString() ?: "0") }
    var maxWsBin by remember { mutableStateOf(last?.optInt("max_ws_binary")?.toString() ?: "1400") }
    var wsPing by remember { mutableStateOf(last?.optInt("ws_ping_secs")?.toString() ?: "25") }
    var wsHeaders by remember {
        mutableStateOf(
            last?.optJSONArray("ws_headers")?.let { arr ->
                (0 until arr.length()).joinToString("\n") { i -> arr.getString(i) }
            } ?: "",
        )
    }
    var bibaInvite by remember { mutableStateOf(last?.optString("from_invite") ?: "") }
    var invitePassphrase by remember { mutableStateOf(last?.optString("invite_passphrase") ?: "") }
    var tlsProfile by remember { mutableStateOf(last?.optString("tls_profile") ?: "") }
    var wsPath by remember { mutableStateOf(last?.optString("ws_path") ?: "") }
    var useTcpMux by remember {
        mutableStateOf(last?.let { it.optBoolean("use_tcp_mux", true) } ?: true)
    }
    var padMode by remember { mutableStateOf(last?.optString("pad_mode") ?: "") }
    var wsPingJitter by remember {
        mutableStateOf(
            if (last?.has("ws_ping_jitter_percent") == true) {
                last!!.getInt("ws_ping_jitter_percent").toString()
            } else {
                "0"
            },
        )
    }
    var wsBinaryJitter by remember {
        mutableStateOf(
            if (last?.has("ws_binary_send_jitter_ms") == true) {
                last!!.getInt("ws_binary_send_jitter_ms").toString()
            } else {
                "0"
            },
        )
    }
    var udpMaxPad by remember {
        mutableStateOf(
            if (last?.has("udp_max_pad") == true && last!!.isNull("udp_max_pad").not()) {
                last!!.getInt("udp_max_pad").toString()
            } else {
                ""
            },
        )
    }
    var udpMaxWsBin by remember {
        mutableStateOf(
            if (last?.has("udp_max_ws_binary") == true && last!!.isNull("udp_max_ws_binary").not()) {
                last!!.getInt("udp_max_ws_binary").toString()
            } else {
                ""
            },
        )
    }
    var udpMuxTimeout by remember {
        mutableStateOf(
            if (last?.has("udp_mux_reply_timeout_secs") == true) {
                last!!.getLong("udp_mux_reply_timeout_secs").toString()
            } else {
                ""
            },
        )
    }
    var dummyInterval by remember {
        mutableStateOf(
            if (last?.has("dummy_interval_secs") == true && !last!!.isNull("dummy_interval_secs")) {
                last!!.getLong("dummy_interval_secs").toString()
            } else {
                "0"
            },
        )
    }
    var decoyGets by remember { mutableStateOf(last?.optBoolean("decoy_gets") ?: false) }
    var decoyGetsInterval by remember {
        mutableStateOf(
            if (last?.has("decoy_gets_interval_secs") == true) {
                last!!.getLong("decoy_gets_interval_secs").toString()
            } else {
                "30"
            },
        )
    }
    var decoyGetsPaths by remember {
        mutableStateOf(last?.optString("decoy_gets_paths") ?: "")
    }
    var pinCertPem by remember {
        mutableStateOf(last?.optString("pin_cert_pem") ?: "")
    }

    val activity = context as ComponentActivity
    DisposableEffect(activity) {
        val obs = LifecycleEventObserver { _, e ->
            if (e == Lifecycle.Event.ON_RESUME) {
                tunnelUp = BibaVpnService.isTunnelActive
            }
        }
        activity.lifecycle.addObserver(obs)
        onDispose { activity.lifecycle.removeObserver(obs) }
    }

    LaunchedEffect(Unit) {
        while (isActive) {
            delay(400)
            val t = BibaVpnService.isTunnelActive
            if (t != tunnelUp) tunnelUp = t
        }
    }

    fun applyInviteToForm() {
        val uri = bibaInvite.trim()
        val pass = invitePassphrase
        if (uri.isBlank() || pass.isBlank()) {
            Toast.makeText(context, "Нужны ключ biba:// и passphrase", Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val raw = BibaNative.nativeDecodeInvite(uri, pass)
            val j = JSONObject(raw)
            if (!j.optBoolean("ok")) {
                Toast.makeText(context, j.optString("error", "Ошибка ключа"), Toast.LENGTH_LONG).show()
                return
            }
            server = j.optString("server", "")
            sni = j.optString("sni", "")
            token = j.optString("token", "")
            psk = j.optString("psk", "")
            maxPad = j.optInt("max_pad", 64).toString()
            decoyMax = j.optInt("decoy_max", 32).toString()
            maxWsBin = j.optInt("max_ws_binary", 1400).toString()
            wsPing = j.optLong("ws_ping_secs", 25).toString()
            insecure = j.optBoolean("insecure", false)
            tlsProfile = j.optString("tls_profile", "default")
            wsPath = j.optString("ws_path", "")
            padMode = j.optString("pad_mode", "")
            wsPingJitter =
                if (j.has("ws_ping_jitter_percent")) j.getInt("ws_ping_jitter_percent").toString() else "0"
            wsBinaryJitter =
                if (j.has("ws_binary_send_jitter_ms")) j.getInt("ws_binary_send_jitter_ms").toString() else "0"
            udpMaxPad =
                if (j.has("udp_max_pad") && !j.isNull("udp_max_pad")) j.getInt("udp_max_pad").toString() else ""
            udpMaxWsBin =
                if (j.has("udp_max_ws_binary") && !j.isNull("udp_max_ws_binary")) {
                    j.getInt("udp_max_ws_binary").toString()
                } else {
                    ""
                }
            udpMuxTimeout =
                if (j.has("udp_mux_reply_timeout_secs")) j.getLong("udp_mux_reply_timeout_secs").toString() else ""
            dummyInterval =
                if (j.has("dummy_interval_secs") && !j.isNull("dummy_interval_secs")) {
                    j.getLong("dummy_interval_secs").toString()
                } else {
                    "0"
                }
            useTcpMux = true
            Toast.makeText(context, "Поля подключения обновлены", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(context, e.message ?: "decode", Toast.LENGTH_LONG).show()
        }
    }

    fun buildConfigJson(): JSONObject = buildJson(
        fromInvite = bibaInvite.trim(),
        invitePassphrase = invitePassphrase,
        server = server.trim(),
        token = token,
        sni = sni.trim(),
        psk = psk.trim(),
        socksBind = socksBind.trim(),
        insecure = insecure,
        tlsProfile = tlsProfile.trim(),
        maxPad = maxPad.toIntOrNull() ?: 64,
        decoyMax = decoyMax.toIntOrNull() ?: 32,
        junkFrames = junkFrames.toIntOrNull() ?: 0,
        earlyWs = earlyWs.toIntOrNull() ?: 0,
        maxWsBinary = maxWsBin.toIntOrNull() ?: 1400,
        wsPing = wsPing.toLongOrNull() ?: 25L,
        wsHeaders = wsHeaders,
        wsPath = wsPath,
        useTcpMux = useTcpMux,
        padMode = padMode,
        wsPingJitter = wsPingJitter.toIntOrNull() ?: 0,
        wsBinaryJitter = wsBinaryJitter.toIntOrNull() ?: 0,
        udpMaxPad = udpMaxPad.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
        udpMaxWsBinary = udpMaxWsBin.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
        udpMuxTimeout = udpMuxTimeout.trim().takeIf { it.isNotEmpty() }?.toLongOrNull(),
        dummyInterval = dummyInterval.toLongOrNull() ?: 0L,
        decoyGets = decoyGets,
        decoyGetsInterval = decoyGetsInterval.toLongOrNull() ?: 30L,
        decoyGetsPaths = decoyGetsPaths,
        pinCertPem = pinCertPem,
    )

    /** Актуальный сохранённый конфиг (не застывший snapshot из remember). */
    fun savedConfigObject(): JSONObject? =
        BibaVpnService.getLastConfigJson(context)?.let { runCatching { JSONObject(it) }.getOrNull() }

    /** Поля формы + fallback на последний сохранённый JSON (после сброса состояния invite часто «теряется» в UI). */
    fun mergedInvitePair(): Pair<String, String> {
        val snap = savedConfigObject()
        val bi = bibaInvite.trim().ifBlank { snap?.optString("from_invite") ?: "" }
        val ip = invitePassphrase.ifBlank { snap?.optString("invite_passphrase") ?: "" }
        return Pair(bi, ip)
    }

    fun mergedServerToken(): Pair<String, String> {
        val snap = savedConfigObject()
        val sv = server.trim().ifBlank { snap?.optString("server") ?: "" }
        val tk = token.trim().ifBlank { snap?.optString("token") ?: "" }
        return Pair(sv, tk)
    }

    fun canConnectWithSavedFallback(): Boolean {
        val (bi, ip) = mergedInvitePair()
        val (sv, tk) = mergedServerToken()
        return (bi.isNotBlank() && ip.isNotBlank()) || (sv.isNotBlank() && tk.isNotBlank())
    }

    fun buildConnectJsonForVpn(): JSONObject {
        val (bi, ip) = mergedInvitePair()
        val (sv, tk) = mergedServerToken()
        return buildJson(
            fromInvite = bi,
            invitePassphrase = ip,
            server = sv,
            token = tk,
            sni = sni.trim(),
            psk = psk.trim(),
            socksBind = socksBind.trim(),
            insecure = insecure,
            tlsProfile = tlsProfile.trim(),
            maxPad = maxPad.toIntOrNull() ?: 64,
            decoyMax = decoyMax.toIntOrNull() ?: 32,
            junkFrames = junkFrames.toIntOrNull() ?: 0,
            earlyWs = earlyWs.toIntOrNull() ?: 0,
            maxWsBinary = maxWsBin.toIntOrNull() ?: 1400,
            wsPing = wsPing.toLongOrNull() ?: 25L,
            wsHeaders = wsHeaders,
            wsPath = wsPath,
            useTcpMux = useTcpMux,
            padMode = padMode,
            wsPingJitter = wsPingJitter.toIntOrNull() ?: 0,
            wsBinaryJitter = wsBinaryJitter.toIntOrNull() ?: 0,
            udpMaxPad = udpMaxPad.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
            udpMaxWsBinary = udpMaxWsBin.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
            udpMuxTimeout = udpMuxTimeout.trim().takeIf { it.isNotEmpty() }?.toLongOrNull(),
            dummyInterval = dummyInterval.toLongOrNull() ?: 0L,
            decoyGets = decoyGets,
            decoyGetsInterval = decoyGetsInterval.toLongOrNull() ?: 30L,
            decoyGetsPaths = decoyGetsPaths,
            pinCertPem = pinCertPem,
        )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(Color(0xFF16203B), BgRoot, BgRoot),
                    center = Offset(0.5f, 0f),
                    radius = 1200f,
                ),
            ),
    ) {
        if (showSettings) {
            SettingsScreen(
                bibaInvite = bibaInvite,
                onBibaInviteChange = { bibaInvite = it },
                invitePassphrase = invitePassphrase,
                onInvitePassphraseChange = { invitePassphrase = it },
                onApplyInvite = { applyInviteToForm() },
                tlsProfile = tlsProfile,
                onTlsProfileChange = { tlsProfile = it },
                server = server,
                onServerChange = { server = it },
                token = token,
                onTokenChange = { token = it },
                tokenVisible = tokenVisible,
                onTokenVisibleChange = { tokenVisible = it },
                sni = sni,
                onSniChange = { sni = it },
                psk = psk,
                onPskChange = { psk = it },
                pskVisible = pskVisible,
                onPskVisibleChange = { pskVisible = it },
                insecure = insecure,
                onInsecureChange = { insecure = it },
                socksBind = socksBind,
                onSocksBindChange = { socksBind = it },
                maxPad = maxPad,
                onMaxPadChange = { maxPad = it },
                decoyMax = decoyMax,
                onDecoyMaxChange = { decoyMax = it },
                junkFrames = junkFrames,
                onJunkFramesChange = { junkFrames = it },
                earlyWs = earlyWs,
                onEarlyWsChange = { earlyWs = it },
                maxWsBin = maxWsBin,
                onMaxWsBinChange = { maxWsBin = it },
                wsPing = wsPing,
                onWsPingChange = { wsPing = it },
                wsHeaders = wsHeaders,
                onWsHeadersChange = { wsHeaders = it },
                wsPath = wsPath,
                onWsPathChange = { wsPath = it },
                useTcpMux = useTcpMux,
                onUseTcpMuxChange = { useTcpMux = it },
                padMode = padMode,
                onPadModeChange = { padMode = it },
                wsPingJitter = wsPingJitter,
                onWsPingJitterChange = { wsPingJitter = it },
                wsBinaryJitter = wsBinaryJitter,
                onWsBinaryJitterChange = { wsBinaryJitter = it },
                udpMaxPad = udpMaxPad,
                onUdpMaxPadChange = { udpMaxPad = it },
                udpMaxWsBin = udpMaxWsBin,
                onUdpMaxWsBinChange = { udpMaxWsBin = it },
                udpMuxTimeout = udpMuxTimeout,
                onUdpMuxTimeoutChange = { udpMuxTimeout = it },
                dummyInterval = dummyInterval,
                onDummyIntervalChange = { dummyInterval = it },
                decoyGets = decoyGets,
                onDecoyGetsChange = { decoyGets = it },
                decoyGetsInterval = decoyGetsInterval,
                onDecoyGetsIntervalChange = { decoyGetsInterval = it },
                decoyGetsPaths = decoyGetsPaths,
                onDecoyGetsPathsChange = { decoyGetsPaths = it },
                pinCertPem = pinCertPem,
                onPinCertPemChange = { pinCertPem = it },
                onBack = { showSettings = false },
            )
        } else {
            HomeScreen(
                tunnelUp = tunnelUp,
                server = server.trim(),
                sni = sni.trim(),
                bibaInvite = bibaInvite.trim(),
                configLooksReady = canConnectWithSavedFallback(),
                onOpenSettings = { showSettings = true },
                onConnectToggle = {
                    if (tunnelUp) {
                        BibaVpnService.stop(context)
                    } else if (!canConnectWithSavedFallback()) {
                        Toast.makeText(
                            context,
                            "Укажите сервер в настройках или задайте ключ biba:// и passphrase",
                            Toast.LENGTH_LONG,
                        ).show()
                    } else {
                        val json = buildConnectJsonForVpn()
                        BibaVpnService.saveConfig(context, json.toString())
                        onRequestVpnConnect(json.toString())
                    }
                },
                onServerCardTap = { showSettings = true },
            )
        }
    }
}

@Composable
private fun HomeScreen(
    tunnelUp: Boolean,
    server: String,
    sni: String,
    bibaInvite: String,
    /** Есть ли данные для подключения (включая fallback из последнего JSON) — только для подсказки/прозрачности. */
    configLooksReady: Boolean,
    onOpenSettings: () -> Unit,
    onConnectToggle: () -> Unit,
    onServerCardTap: () -> Unit,
) {
    val displayHost = remember(server, sni, bibaInvite) {
        when {
            server.isNotBlank() && sni.isNotBlank() -> sni
            server.isNotBlank() -> server.substringBefore(':').ifBlank { server }
            bibaInvite.isNotBlank() -> "Ключ Biba"
            else -> "—"
        }
    }
    val subtitle = when {
        server.isNotBlank() -> server
        bibaInvite.isNotBlank() ->
            bibaInvite.take(36).let { if (bibaInvite.length > 36) "$it…" else it }
        else -> "Не задан сервер"
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RoundIconButton(onClick = onOpenSettings, symbol = "⚙")
            Image(
                painter = painterResource(id = R.drawable.img_biba_wordmark),
                contentDescription = null,
                modifier = Modifier
                    .weight(1f)
                    .height(36.dp)
                    .padding(horizontal = 12.dp),
                contentScale = ContentScale.Fit,
            )
            Spacer(Modifier.width(40.dp))
        }

        Spacer(Modifier.height(24.dp))

        // Status card
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(26.dp))
                .border(1.dp, BorderSubtle, RoundedCornerShape(26.dp))
                .background(CardBg)
                .padding(20.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatusDot(active = tunnelUp)
                Text(
                    if (tunnelUp) "Подключено" else "Не подключено",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(12.dp))
            Text(
                if (tunnelUp) "$displayHost · туннель активен" else "Нажмите, чтобы включить VPN",
                color = TextSlate200.copy(alpha = 0.85f),
                fontSize = 14.sp,
            )
        }

        Spacer(Modifier.height(40.dp))

        // Main action — всегда кликабельно: проверка данных и Toast в onConnectToggle
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .alpha(if (tunnelUp || configLooksReady) 1f else 0.55f)
                .clip(RoundedCornerShape(28.dp))
                .border(1.dp, MainButtonBorder, RoundedCornerShape(28.dp))
                .background(MainButtonBrush)
                .clickable { onConnectToggle() }
                .padding(horizontal = 24.dp, vertical = 22.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        if (tunnelUp) "Отключить" else "Подключить",
                        color = Color.White,
                        fontSize = 22.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        if (tunnelUp) {
                            "Защищено · отключить туннель"
                        } else {
                            "Трафик через System VPN + локальный SOCKS"
                        },
                        color = LabelSky.copy(alpha = 0.75f),
                        fontSize = 14.sp,
                    )
                }
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(16.dp))
                        .border(1.dp, Mint.copy(alpha = 0.35f), RoundedCornerShape(16.dp))
                        .background(Mint.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center,
                ) {
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(MintSoft),
                    )
                }
            }
        }

        Spacer(Modifier.height(32.dp))

        // Server card
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(24.dp))
                .border(1.dp, BorderSubtle, RoundedCornerShape(24.dp))
                .background(CardBg)
                .clickable { onServerCardTap() }
                .padding(16.dp),
        ) {
            Text(
                "SERVER",
                color = TextMuted,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 2.4.sp,
            )
            Spacer(Modifier.height(12.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        displayHost,
                        color = Color.White,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        subtitle,
                        color = TextMuted,
                        fontSize = 14.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text("›", color = TextMuted.copy(alpha = 0.55f), fontSize = 22.sp)
            }
        }
    }
}

@Composable
private fun StatusDot(active: Boolean) {
    val c = if (active) MintSoft else TextMuted
    Box(contentAlignment = Alignment.Center) {
        Box(
            modifier = Modifier
                .size(18.dp)
                .clip(CircleShape)
                .background(if (active) Mint.copy(alpha = 0.35f) else Color.Transparent),
        )
        Box(
            modifier = Modifier
                .size(10.dp)
                .clip(CircleShape)
                .background(c),
        )
    }
}

@Composable
private fun RoundIconButton(onClick: () -> Unit, symbol: String) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .border(1.dp, BorderSubtle, CircleShape)
            .background(Color.White.copy(alpha = 0.03f))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(symbol, color = TextSlate200.copy(alpha = 0.88f), fontSize = 18.sp)
    }
}

@Composable
private fun SettingsScreen(
    bibaInvite: String,
    onBibaInviteChange: (String) -> Unit,
    invitePassphrase: String,
    onInvitePassphraseChange: (String) -> Unit,
    onApplyInvite: () -> Unit,
    tlsProfile: String,
    onTlsProfileChange: (String) -> Unit,
    server: String,
    onServerChange: (String) -> Unit,
    token: String,
    onTokenChange: (String) -> Unit,
    tokenVisible: Boolean,
    onTokenVisibleChange: (Boolean) -> Unit,
    sni: String,
    onSniChange: (String) -> Unit,
    psk: String,
    onPskChange: (String) -> Unit,
    pskVisible: Boolean,
    onPskVisibleChange: (Boolean) -> Unit,
    insecure: Boolean,
    onInsecureChange: (Boolean) -> Unit,
    socksBind: String,
    onSocksBindChange: (String) -> Unit,
    maxPad: String,
    onMaxPadChange: (String) -> Unit,
    decoyMax: String,
    onDecoyMaxChange: (String) -> Unit,
    junkFrames: String,
    onJunkFramesChange: (String) -> Unit,
    earlyWs: String,
    onEarlyWsChange: (String) -> Unit,
    maxWsBin: String,
    onMaxWsBinChange: (String) -> Unit,
    wsPing: String,
    onWsPingChange: (String) -> Unit,
    wsHeaders: String,
    onWsHeadersChange: (String) -> Unit,
    wsPath: String,
    onWsPathChange: (String) -> Unit,
    useTcpMux: Boolean,
    onUseTcpMuxChange: (Boolean) -> Unit,
    padMode: String,
    onPadModeChange: (String) -> Unit,
    wsPingJitter: String,
    onWsPingJitterChange: (String) -> Unit,
    wsBinaryJitter: String,
    onWsBinaryJitterChange: (String) -> Unit,
    udpMaxPad: String,
    onUdpMaxPadChange: (String) -> Unit,
    udpMaxWsBin: String,
    onUdpMaxWsBinChange: (String) -> Unit,
    udpMuxTimeout: String,
    onUdpMuxTimeoutChange: (String) -> Unit,
    dummyInterval: String,
    onDummyIntervalChange: (String) -> Unit,
    decoyGets: Boolean,
    onDecoyGetsChange: (Boolean) -> Unit,
    decoyGetsInterval: String,
    onDecoyGetsIntervalChange: (String) -> Unit,
    decoyGetsPaths: String,
    onDecoyGetsPathsChange: (String) -> Unit,
    pinCertPem: String,
    onPinCertPemChange: (String) -> Unit,
    onBack: () -> Unit,
) {
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgScreen)
            .verticalScroll(scroll)
            .padding(20.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            RoundIconButton(onClick = onBack, symbol = "‹")
            Text(
                "Настройки",
                color = TextSlate200,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 0.6.sp,
            )
            Spacer(Modifier.width(40.dp))
        }

        Spacer(Modifier.height(24.dp))

        SettingsSection(
            title = "Ключ Biba",
            subtitle = "Зашифрованный biba://… и passphrase (как --from-invite у desktop-клиента)",
        ) {
            SettingsTextField(
                label = "Biba key",
                value = bibaInvite,
                onChange = onBibaInviteChange,
                placeholder = "biba://…",
                singleLine = false,
                maxLines = 4,
            )
            SettingsTextField(
                label = "Passphrase",
                value = invitePassphrase,
                onChange = onInvitePassphraseChange,
                placeholder = "секрет out-of-band",
                isPassword = true,
            )
            Text(
                "Параметры туннеля берутся из ключа; junk_frames, ws_headers и SNI ниже можно переопределить.",
                color = TextMuted,
                fontSize = 11.sp,
            )
            Button(
                onClick = onApplyInvite,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Mint.copy(alpha = 0.2f),
                    contentColor = Mint,
                ),
                contentPadding = PaddingValues(vertical = 14.dp),
            ) {
                Text("Применить к полям подключения", fontWeight = FontWeight.SemiBold)
            }
        }

        Spacer(Modifier.height(16.dp))

        SettingsSection(
            title = "Подключение",
            subtitle = "Сервер и параметры рукопожатия",
        ) {
            SettingsTextField(
                label = "Server",
                value = server,
                onChange = onServerChange,
                placeholder = "host:443",
            )
            SettingsTextField(
                label = "Token",
                value = token,
                onChange = onTokenChange,
                placeholder = "токен",
                isPassword = !tokenVisible,
                trailing = {
                    Text(
                        if (tokenVisible) "🙈" else "👁",
                        modifier = Modifier
                            .clickable { onTokenVisibleChange(!tokenVisible) }
                            .padding(4.dp),
                        fontSize = 16.sp,
                    )
                },
            )
            SettingsTextField(
                label = "SNI / TLS Name",
                value = sni,
                onChange = onSniChange,
                placeholder = "Auto (пусто = host)",
                hint = "Leave empty to use host",
            )
            SettingsTextField(
                label = "PSK",
                value = psk,
                onChange = onPskChange,
                isPassword = !pskVisible,
                trailing = {
                    Text(
                        if (pskVisible) "🙈" else "👁",
                        modifier = Modifier
                            .clickable { onPskVisibleChange(!pskVisible) }
                            .padding(4.dp),
                        fontSize = 16.sp,
                    )
                },
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column {
                    Text("Пропуск TLS (insecure)", color = Color.White, fontSize = 14.sp)
                    Text("Только для лаборатории", color = TextMuted, fontSize = 12.sp)
                }
                Switch(
                    checked = insecure,
                    onCheckedChange = onInsecureChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Mint,
                        checkedTrackColor = Mint.copy(alpha = 0.4f),
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = TextMuted.copy(alpha = 0.3f),
                    ),
                )
            }
        }

        Spacer(Modifier.height(16.dp))

        SettingsSection(
            title = "Сеть",
            subtitle = "Маршрутизация",
        ) {
            SettingsStaticField(
                label = "Routing Mode",
                value = "System VPN",
                hint = "Весь трафик через туннель",
            )
            SettingsTextField(
                label = "Локальный SOCKS",
                value = socksBind,
                onChange = onSocksBindChange,
                placeholder = BibaVpnService.SOCKS_LOCAL,
                hint = "Пусто = ${BibaVpnService.SOCKS_LOCAL}",
            )
        }

        Spacer(Modifier.height(16.dp))

        SettingsSection(
            title = "Транспорт",
            subtitle = "Обфускация и WebSocket",
        ) {
            SettingsTextField(
                label = "tls_profile",
                value = tlsProfile,
                onChange = onTlsProfileChange,
                placeholder = "default",
                hint = "Профиль ClientHello (default, chrome70, firefox65, …); для ключа можно переопределить",
            )
            SettingsTextField(
                label = "ws_path",
                value = wsPath,
                onChange = onWsPathChange,
                placeholder = "/ws",
                hint = "Путь WebSocket на сервере (пусто = /ws после ключа)",
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("TCP multiplex (WSS)", color = Color.White, fontSize = 14.sp)
                    Text("Выключите для режима как --no-mux", color = TextMuted, fontSize = 12.sp)
                }
                Switch(
                    checked = useTcpMux,
                    onCheckedChange = onUseTcpMuxChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Mint,
                        checkedTrackColor = Mint.copy(alpha = 0.4f),
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = TextMuted.copy(alpha = 0.3f),
                    ),
                )
            }
            SettingsTextField(
                label = "pad_mode",
                value = padMode,
                onChange = onPadModeChange,
                placeholder = "random или http-buckets",
                hint = "Режим паддинга; пусто = из ключа или random",
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "max_pad",
                    value = maxPad,
                    onChange = onMaxPadChange,
                    hint = "Packet padding",
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "decoy_max",
                    value = decoyMax,
                    onChange = onDecoyMaxChange,
                    hint = "Fake packets",
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "junk_frames",
                    value = junkFrames,
                    onChange = onJunkFramesChange,
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "early_ws_frames",
                    value = earlyWs,
                    onChange = onEarlyWsChange,
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "max_ws_binary",
                    value = maxWsBin,
                    onChange = onMaxWsBinChange,
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "ws_ping_secs",
                    value = wsPing,
                    onChange = onWsPingChange,
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "ws_ping_jitter_%",
                    value = wsPingJitter,
                    onChange = onWsPingJitterChange,
                    hint = "0–50",
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "ws_send_jitter_ms",
                    value = wsBinaryJitter,
                    onChange = onWsBinaryJitterChange,
                    hint = "0–255",
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "udp_max_pad",
                    value = udpMaxPad,
                    onChange = onUdpMaxPadChange,
                    hint = "пусто = как max_pad",
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "udp_max_ws",
                    value = udpMaxWsBin,
                    onChange = onUdpMaxWsBinChange,
                    hint = "пусто = как max_ws",
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "udp_mux_to",
                    value = udpMuxTimeout,
                    onChange = onUdpMuxTimeoutChange,
                    hint = "сек, пусто = по умолч.",
                    modifier = Modifier.weight(1f),
                )
            }
            SettingsMiniField(
                label = "dummy_interval_secs",
                value = dummyInterval,
                onChange = onDummyIntervalChange,
                hint = "0 = выкл; idle WS кадры",
                modifier = Modifier.fillMaxWidth(),
            )
            SettingsTextField(
                label = "ws_headers",
                value = wsHeaders,
                onChange = onWsHeadersChange,
                singleLine = false,
                maxLines = 5,
                placeholder = "Name: value",
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Decoy HTTPS GET", color = Color.White, fontSize = 14.sp)
                    Text("Параллельные GET на сервер (как --decoy-gets)", color = TextMuted, fontSize = 12.sp)
                }
                Switch(
                    checked = decoyGets,
                    onCheckedChange = onDecoyGetsChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Mint,
                        checkedTrackColor = Mint.copy(alpha = 0.4f),
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = TextMuted.copy(alpha = 0.3f),
                    ),
                )
            }
            if (decoyGets) {
                SettingsMiniField(
                    label = "decoy_gets_interval_secs",
                    value = decoyGetsInterval,
                    onChange = onDecoyGetsIntervalChange,
                    hint = "≥1 сек",
                    modifier = Modifier.fillMaxWidth(),
                )
                SettingsTextField(
                    label = "decoy_gets_paths",
                    value = decoyGetsPaths,
                    onChange = onDecoyGetsPathsChange,
                    placeholder = "/,/favicon.ico",
                    hint = "Через запятую (как у desktop-клиента)",
                )
            }
            SettingsTextField(
                label = "pin_cert_pem",
                value = pinCertPem,
                onChange = onPinCertPemChange,
                singleLine = false,
                maxLines = 8,
                placeholder = "-----BEGIN CERTIFICATE-----",
                hint = "Один или несколько PEM; взаимоисключимо с insecure",
            )
        }

        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun SettingsSection(
    title: String,
    subtitle: String,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(28.dp))
            .border(1.dp, BorderSubtle, RoundedCornerShape(28.dp))
            .background(CardBg.copy(alpha = 0.92f))
            .padding(20.dp),
    ) {
        Text(title, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(4.dp))
        Text(subtitle, color = TextMuted, fontSize = 14.sp)
        Spacer(Modifier.height(16.dp))
        Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
            content()
        }
    }
}

@Composable
private fun SettingsStaticField(
    label: String,
    value: String,
    hint: String? = null,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            label,
            color = LabelSky.copy(alpha = 0.9f),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            letterSpacing = 0.3.sp,
        )
        Spacer(Modifier.height(8.dp))
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
                .background(Color(0xFF020617).copy(alpha = 0.55f))
                .padding(horizontal = 16.dp, vertical = 14.dp),
        ) {
            Text(value, color = Color(0xFFF8FAFC), fontSize = 14.sp)
            if (hint != null) {
                Spacer(Modifier.height(4.dp))
                Text(hint, color = TextMuted, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun SettingsTextField(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    placeholder: String = "",
    hint: String? = null,
    isPassword: Boolean = false,
    singleLine: Boolean = true,
    maxLines: Int = if (singleLine) 1 else 5,
    trailing: (@Composable () -> Unit)? = null,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            label,
            color = LabelSky.copy(alpha = 0.9f),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            letterSpacing = 0.3.sp,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier.fillMaxWidth(),
            singleLine = singleLine,
            maxLines = maxLines,
            placeholder = {
                Text(placeholder, color = TextMuted.copy(alpha = 0.65f), fontSize = 14.sp)
            },
            trailingIcon = trailing,
            visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = KeyboardOptions.Default,
            shape = RoundedCornerShape(16.dp),
            colors = fieldInsetColors(),
        )
        if (hint != null) {
            Spacer(Modifier.height(4.dp))
            Text(hint, color = TextMuted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun SettingsMiniField(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    hint: String? = null,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        Text(
            label,
            color = LabelSky.copy(alpha = 0.9f),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            letterSpacing = 0.3.sp,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            shape = RoundedCornerShape(16.dp),
            colors = fieldInsetColors(),
        )
        if (hint != null) {
            Spacer(Modifier.height(4.dp))
            Text(hint, color = TextMuted, fontSize = 11.sp)
        }
    }
}

@Composable
private fun fieldInsetColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Color(0xFFF8FAFC),
    unfocusedTextColor = Color(0xFFF8FAFC),
    focusedContainerColor = Color(0xFF020617).copy(alpha = 0.55f),
    unfocusedContainerColor = Color(0xFF020617).copy(alpha = 0.55f),
    cursorColor = Mint,
    focusedBorderColor = BorderSubtle,
    unfocusedBorderColor = BorderSubtle,
    focusedPlaceholderColor = TextMuted,
    unfocusedPlaceholderColor = TextMuted,
)

private fun buildJson(
    fromInvite: String,
    invitePassphrase: String,
    server: String,
    token: String,
    sni: String,
    psk: String,
    socksBind: String,
    insecure: Boolean,
    tlsProfile: String,
    maxPad: Int,
    decoyMax: Int,
    junkFrames: Int,
    earlyWs: Int,
    maxWsBinary: Int,
    wsPing: Long,
    wsHeaders: String,
    wsPath: String,
    useTcpMux: Boolean,
    padMode: String,
    wsPingJitter: Int,
    wsBinaryJitter: Int,
    udpMaxPad: Int?,
    udpMaxWsBinary: Int?,
    udpMuxTimeout: Long?,
    dummyInterval: Long,
    decoyGets: Boolean,
    decoyGetsInterval: Long,
    decoyGetsPaths: String,
    pinCertPem: String,
): JSONObject {
    val o = JSONObject()
    val useInvite = fromInvite.isNotBlank() && invitePassphrase.isNotBlank()
    if (useInvite) {
        o.put("from_invite", fromInvite.trim())
        o.put("invite_passphrase", invitePassphrase)
        o.put("server", "")
        o.put("token", "change-me")
    } else {
        o.put("server", server)
        o.put("token", token)
        if (tlsProfile.isNotBlank()) o.put("tls_profile", tlsProfile.trim())
    }
    if (sni.isNotBlank()) o.put("sni", sni)
    o.put("socks_bind", socksBind.trim().ifBlank { BibaVpnService.SOCKS_LOCAL })
    o.put("insecure", insecure)
    o.put("max_pad", maxPad)
    o.put("decoy_max", decoyMax.coerceIn(0, 255))
    o.put("junk_frames", junkFrames)
    o.put("early_ws_frames", earlyWs)
    o.put("max_ws_binary", maxWsBinary)
    o.put("ws_ping_secs", wsPing)
    o.put("use_tcp_mux", useTcpMux)
    val wp = wsPath.trim()
    if (wp.isNotEmpty()) o.put("ws_path", wp)
    val pm = padMode.trim()
    if (pm.isNotEmpty()) o.put("pad_mode", pm)
    val jPing = wsPingJitter.coerceIn(0, 50)
    if (jPing > 0) o.put("ws_ping_jitter_percent", jPing)
    val jBin = wsBinaryJitter.coerceIn(0, 255)
    if (jBin > 0) o.put("ws_binary_send_jitter_ms", jBin)
    udpMaxPad?.let { o.put("udp_max_pad", it.coerceIn(0, 255)) }
    udpMaxWsBinary?.let { if (it > 0) o.put("udp_max_ws_binary", it) }
    udpMuxTimeout?.let { if (it >= 0) o.put("udp_mux_reply_timeout_secs", it) }
    if (dummyInterval > 0) o.put("dummy_interval_secs", dummyInterval)
    if (psk.isNotBlank()) o.put("psk", psk)
    val lines = wsHeaders.lines().map { it.trim() }.filter { it.isNotBlank() }
    if (lines.isNotEmpty()) o.put("ws_headers", JSONArray(lines))
    o.put("decoy_gets", decoyGets)
    if (decoyGets) {
        o.put("decoy_gets_interval_secs", decoyGetsInterval.coerceAtLeast(1))
        val dp = decoyGetsPaths.trim()
        if (dp.isNotEmpty()) o.put("decoy_gets_paths", dp)
    }
    val pin = pinCertPem.trim()
    if (pin.isNotEmpty()) o.put("pin_cert_pem", pin)
    return o
}
