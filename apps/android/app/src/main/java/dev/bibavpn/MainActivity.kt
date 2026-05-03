package dev.bibavpn

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.provider.Settings
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
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

/** Терминальная тёмная тема (как в макетах): ч/б, моноширинный шрифт. */
private val BgRoot = Color(0xFF000000)
private val BgScreen = Color(0xFF000000)
private val CardBg = Color(0xFF000000)
private val LabelSky = Color(0xFF888888)
private val TextMuted = Color(0xFF888888)
private val TextSlate200 = Color(0xFFFFFFFF)
private val Mint = Color(0xFFFFFFFF)
private val MintSoft = Color(0xFFAAAAAA)
private val TermOrange = Color(0xFFFFA500)
private val BorderSubtle = Color(0xFF444444)

private val Mono = FontFamily.Monospace

class MainActivity : AppCompatActivity() {

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
    /** 0 connection, 1 profiles, 2 config, 3 logs */
    var mainTab by remember { mutableStateOf(0) }
    var tunnelUp by remember { mutableStateOf(BibaVpnService.isTunnelActive) }
    var tunnelStartElapsed by remember { mutableStateOf<Long?>(null) }
    var uptimeTick by remember { mutableStateOf(0) }

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
    var proto by remember {
        mutableStateOf(
            if (last?.has("proto") == true && last!!.isNull("proto").not()) {
                last!!.getInt("proto").toString()
            } else {
                "3"
            },
        )
    }
    var protoDomain by remember { mutableStateOf(last?.optString("proto_domain") ?: "") }
    var wsJitterMin by remember {
        mutableStateOf(
            if (last?.has("ws_jitter_min_ms") == true) last!!.getInt("ws_jitter_min_ms").toString() else "0",
        )
    }
    var wsJitterMax by remember {
        mutableStateOf(
            if (last?.has("ws_jitter_max_ms") == true) last!!.getInt("ws_jitter_max_ms").toString() else "0",
        )
    }
    var stealthProfile by remember { mutableStateOf(last?.optString("stealth_profile") ?: "") }
    var decoyMode by remember { mutableStateOf(last?.optString("decoy_mode") ?: "") }
    var desyncMode by remember { mutableStateOf(last?.optString("desync_mode") ?: "") }
    var tcpFooling by remember { mutableStateOf(last?.optString("tcp_fooling") ?: "") }
    var tlsFragment by remember { mutableStateOf(last?.optBoolean("tls_fragment") ?: false) }
    var wsParallel by remember {
        mutableStateOf(
            if (last?.has("ws_parallel") == true) last!!.getInt("ws_parallel").coerceIn(1, 4).toString() else "1",
        )
    }
    var idleDecoySecs by remember {
        mutableStateOf(
            if (last?.has("idle_decoy_secs") == true && last!!.isNull("idle_decoy_secs").not()) {
                last!!.getLong("idle_decoy_secs").toString()
            } else {
                "0"
            },
        )
    }
    var tlsStack by remember { mutableStateOf(last?.optString("tls_stack")?.ifBlank { null } ?: "rustls") }
    var fingerprint by remember { mutableStateOf(last?.optString("fingerprint") ?: "") }
    var realityTarget by remember { mutableStateOf(last?.optString("reality_target") ?: "") }
    var realityPublicKey by remember { mutableStateOf(last?.optString("reality_public_key") ?: "") }
    var realityShortId by remember { mutableStateOf(last?.optString("reality_short_id") ?: "") }
    var wsHost by remember { mutableStateOf(last?.optString("ws_host") ?: "") }
    var wsOrigin by remember { mutableStateOf(last?.optString("ws_origin") ?: "") }
    var wsUserAgent by remember { mutableStateOf(last?.optString("ws_user_agent") ?: "") }
    var wsAcceptLanguage by remember { mutableStateOf(last?.optString("ws_accept_language") ?: "") }
    var screenOffBatterySaver by remember {
        mutableStateOf(BibaVpnService.isScreenOffBatterySaverEnabled(context))
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

    LaunchedEffect(tunnelUp) {
        if (tunnelUp) {
            if (tunnelStartElapsed == null) {
                tunnelStartElapsed = SystemClock.elapsedRealtime()
            }
        } else {
            tunnelStartElapsed = null
        }
    }

    LaunchedEffect(tunnelUp) {
        while (tunnelUp) {
            delay(1000)
            uptimeTick++
        }
    }

    fun applyInviteToForm() {
        val uri = bibaInvite.trim()
        val pass = invitePassphrase
        if (uri.isBlank() || pass.isBlank()) {
            Toast.makeText(context, context.getString(R.string.toast_invite_need_key_pass), Toast.LENGTH_SHORT).show()
            return
        }
        try {
            val raw = BibaNative.nativeDecodeInvite(uri, pass)
            val j = JSONObject(raw)
            if (!j.optBoolean("ok")) {
                Toast.makeText(
                    context,
                    j.optString("error", context.getString(R.string.toast_invite_decode_error)),
                    Toast.LENGTH_LONG,
                ).show()
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
            junkFrames = j.optInt("junk_frames", 0).toString()
            earlyWs = j.optInt("early_ws_frames", 0).toString()
            wsPingJitter =
                if (j.has("ws_ping_jitter_percent")) j.getInt("ws_ping_jitter_percent").toString() else "0"
            wsBinaryJitter =
                if (j.has("ws_binary_send_jitter_ms")) j.getInt("ws_binary_send_jitter_ms").toString() else "0"
            wsJitterMin =
                if (j.has("ws_jitter_min_ms")) j.getInt("ws_jitter_min_ms").toString() else "0"
            wsJitterMax =
                if (j.has("ws_jitter_max_ms")) j.getInt("ws_jitter_max_ms").toString() else "0"
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
            useTcpMux = j.optBoolean("use_tcp_mux", true)
            decoyGets = j.optBoolean("decoy_gets", false)
            decoyGetsInterval = j.optLong("decoy_gets_interval_secs", 30).toString()
            decoyGetsPaths = j.optString("decoy_gets_paths", "")
            proto =
                if (j.has("proto") && !j.isNull("proto")) j.getInt("proto").toString() else "3"
            protoDomain = j.optString("proto_domain", "")
            stealthProfile = j.optString("stealth_profile", "")
            decoyMode = j.optString("decoy_mode", "")
            desyncMode = j.optString("desync_mode", "")
            tcpFooling = j.optString("tcp_fooling", "")
            tlsFragment = j.optBoolean("tls_fragment", false)
            wsParallel =
                if (j.has("ws_parallel")) j.getInt("ws_parallel").coerceIn(1, 4).toString() else "1"
            idleDecoySecs =
                if (j.has("idle_decoy_secs") && !j.isNull("idle_decoy_secs")) {
                    j.getLong("idle_decoy_secs").toString()
                } else {
                    "0"
                }
            tlsStack = j.optString("tls_stack", "rustls").ifBlank { "rustls" }
            fingerprint = j.optString("fingerprint", "")
            realityTarget = j.optString("reality_target", "")
            realityPublicKey = j.optString("reality_public_key", "")
            realityShortId = j.optString("reality_short_id", "")
            wsHost = j.optString("ws_host", "")
            wsOrigin = j.optString("ws_origin", "")
            wsUserAgent = j.optString("ws_user_agent", "")
            wsAcceptLanguage = j.optString("ws_accept_language", "")
            if (j.has("ws_headers") && !j.isNull("ws_headers")) {
                val arr = j.getJSONArray("ws_headers")
                wsHeaders = (0 until arr.length()).joinToString("\n") { idx -> arr.getString(idx) }
            }
            if (j.has("pin_cert_pem") && !j.isNull("pin_cert_pem")) {
                pinCertPem = j.optString("pin_cert_pem", "")
            }
            if (j.has("socks_bind") && !j.isNull("socks_bind")) {
                val sb = j.optString("socks_bind", "")
                if (sb.isNotBlank()) socksBind = sb
            }
            Toast.makeText(context, context.getString(R.string.toast_invite_fields_updated), Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(
                context,
                context.getString(R.string.toast_decode_failed, e.message ?: "decode"),
                Toast.LENGTH_LONG,
            ).show()
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
        wsJitterMin = wsJitterMin.toIntOrNull() ?: 0,
        wsJitterMax = wsJitterMax.toIntOrNull() ?: 0,
        udpMaxPad = udpMaxPad.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
        udpMaxWsBinary = udpMaxWsBin.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
        udpMuxTimeout = udpMuxTimeout.trim().takeIf { it.isNotEmpty() }?.toLongOrNull(),
        dummyInterval = dummyInterval.toLongOrNull() ?: 0L,
        decoyGets = decoyGets,
        decoyGetsInterval = decoyGetsInterval.toLongOrNull() ?: 30L,
        decoyGetsPaths = decoyGetsPaths,
        pinCertPem = pinCertPem,
        proto = proto.toIntOrNull() ?: 3,
        protoDomain = protoDomain.trim(),
        stealthProfile = stealthProfile.trim(),
        decoyMode = decoyMode.trim(),
        desyncMode = desyncMode.trim(),
        tcpFooling = tcpFooling.trim(),
        tlsFragment = tlsFragment,
        wsParallel = wsParallel.toIntOrNull()?.coerceIn(1, 4) ?: 1,
        idleDecoySecs = idleDecoySecs.toLongOrNull() ?: 0L,
        tlsStack = tlsStack.trim().ifBlank { "rustls" },
        fingerprint = fingerprint.trim(),
        realityTarget = realityTarget.trim(),
        realityPublicKey = realityPublicKey.trim(),
        realityShortId = realityShortId.trim(),
        wsHost = wsHost.trim(),
        wsOrigin = wsOrigin.trim(),
        wsUserAgent = wsUserAgent.trim(),
        wsAcceptLanguage = wsAcceptLanguage.trim(),
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
            wsJitterMin = wsJitterMin.toIntOrNull() ?: 0,
            wsJitterMax = wsJitterMax.toIntOrNull() ?: 0,
            udpMaxPad = udpMaxPad.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
            udpMaxWsBinary = udpMaxWsBin.trim().takeIf { it.isNotEmpty() }?.toIntOrNull(),
            udpMuxTimeout = udpMuxTimeout.trim().takeIf { it.isNotEmpty() }?.toLongOrNull(),
            dummyInterval = dummyInterval.toLongOrNull() ?: 0L,
            decoyGets = decoyGets,
            decoyGetsInterval = decoyGetsInterval.toLongOrNull() ?: 30L,
            decoyGetsPaths = decoyGetsPaths,
            pinCertPem = pinCertPem,
            proto = proto.toIntOrNull() ?: 3,
            protoDomain = protoDomain.trim(),
            stealthProfile = stealthProfile.trim(),
            decoyMode = decoyMode.trim(),
            desyncMode = desyncMode.trim(),
            tcpFooling = tcpFooling.trim(),
            tlsFragment = tlsFragment,
            wsParallel = wsParallel.toIntOrNull()?.coerceIn(1, 4) ?: 1,
            idleDecoySecs = idleDecoySecs.toLongOrNull() ?: 0L,
            tlsStack = tlsStack.trim().ifBlank { "rustls" },
            fingerprint = fingerprint.trim(),
            realityTarget = realityTarget.trim(),
            realityPublicKey = realityPublicKey.trim(),
            realityShortId = realityShortId.trim(),
            wsHost = wsHost.trim(),
            wsOrigin = wsOrigin.trim(),
            wsUserAgent = wsUserAgent.trim(),
            wsAcceptLanguage = wsAcceptLanguage.trim(),
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgRoot),
    ) {
        Box(Modifier.weight(1f)) {
            when (mainTab) {
                0 -> {
                    ConnectionTab(
                        tunnelUp = tunnelUp,
                        tunnelStartElapsed = tunnelStartElapsed,
                        uptimeTick = uptimeTick,
                        server = server.trim(),
                        sni = sni.trim(),
                        bibaInvite = bibaInvite.trim(),
                        configLooksReady = canConnectWithSavedFallback(),
                        tlsProfile = tlsProfile,
                        decoyMax = decoyMax,
                        maxPad = maxPad,
                        padMode = padMode,
                        pinCertPem = pinCertPem,
                        insecure = insecure,
                        onConnectToggle = {
                            if (tunnelUp) {
                                BibaVpnService.stop(context)
                            } else if (!canConnectWithSavedFallback()) {
                                Toast.makeText(
                                    context,
                                    context.getString(R.string.toast_connect_need_config),
                                    Toast.LENGTH_LONG,
                                ).show()
                            } else {
                                val json = buildConnectJsonForVpn()
                                BibaVpnService.saveConfig(context, json.toString())
                                onRequestVpnConnect(json.toString())
                            }
                        },
                        onGoToConfig = { mainTab = 2 },
                    )
                }
                1 -> ProfilesTab(
                    tunnelUp = tunnelUp,
                    server = server.trim(),
                    sni = sni.trim(),
                    bibaInvite = bibaInvite.trim(),
                    insecure = insecure,
                    onImport = { mainTab = 2 },
                )
                2 -> SettingsScreen(
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
                    proto = proto,
                    onProtoChange = { proto = it },
                    protoDomain = protoDomain,
                    onProtoDomainChange = { protoDomain = it },
                    wsJitterMin = wsJitterMin,
                    onWsJitterMinChange = { wsJitterMin = it },
                    wsJitterMax = wsJitterMax,
                    onWsJitterMaxChange = { wsJitterMax = it },
                    stealthProfile = stealthProfile,
                    onStealthProfileChange = { stealthProfile = it },
                    decoyMode = decoyMode,
                    onDecoyModeChange = { decoyMode = it },
                    desyncMode = desyncMode,
                    onDesyncModeChange = { desyncMode = it },
                    tcpFooling = tcpFooling,
                    onTcpFoolingChange = { tcpFooling = it },
                    tlsFragment = tlsFragment,
                    onTlsFragmentChange = { tlsFragment = it },
                    wsParallel = wsParallel,
                    onWsParallelChange = { wsParallel = it },
                    idleDecoySecs = idleDecoySecs,
                    onIdleDecoySecsChange = { idleDecoySecs = it },
                    tlsStack = tlsStack,
                    onTlsStackChange = { tlsStack = it },
                    fingerprint = fingerprint,
                    onFingerprintChange = { fingerprint = it },
                    realityTarget = realityTarget,
                    onRealityTargetChange = { realityTarget = it },
                    realityPublicKey = realityPublicKey,
                    onRealityPublicKeyChange = { realityPublicKey = it },
                    realityShortId = realityShortId,
                    onRealityShortIdChange = { realityShortId = it },
                    wsHost = wsHost,
                    onWsHostChange = { wsHost = it },
                    wsOrigin = wsOrigin,
                    onWsOriginChange = { wsOrigin = it },
                    wsUserAgent = wsUserAgent,
                    onWsUserAgentChange = { wsUserAgent = it },
                    wsAcceptLanguage = wsAcceptLanguage,
                    onWsAcceptLanguageChange = { wsAcceptLanguage = it },
                    screenOffBatterySaver = screenOffBatterySaver,
                    onScreenOffBatterySaverChange = { v ->
                        screenOffBatterySaver = v
                        BibaVpnService.setScreenOffBatterySaver(context, v)
                        if (!v && BibaVpnService.isTunnelActive) {
                            BibaVpnService.requestSyncWakeLock(context)
                        }
                    },
                    onBack = null,
                )
                else -> LogsTab()
            }
        }
        TerminalBottomNav(
            selectedIndex = mainTab,
            onSelect = { mainTab = it },
        )
    }
}

private fun formatTunnelUptime(
    start: Long?,
    @Suppress("UNUSED_PARAMETER") tick: Int,
): String {
    if (start == null) return "—"
    val elapsed = (SystemClock.elapsedRealtime() - start) / 1000L
    val h = elapsed / 3600L
    val m = (elapsed % 3600L) / 60L
    val s = elapsed % 60L
    return if (h > 0L) {
        String.format("%d:%02d:%02d", h, m, s)
    } else {
        String.format("%02d:%02d", m, s)
    }
}

@Composable
private fun ConnectionTab(
    tunnelUp: Boolean,
    tunnelStartElapsed: Long?,
    uptimeTick: Int,
    server: String,
    sni: String,
    bibaInvite: String,
    configLooksReady: Boolean,
    tlsProfile: String,
    decoyMax: String,
    maxPad: String,
    padMode: String,
    pinCertPem: String,
    insecure: Boolean,
    onConnectToggle: () -> Unit,
    onGoToConfig: () -> Unit,
) {
    if (!configLooksReady) {
        WelcomeScreen(onOpenConfig = onGoToConfig)
    } else {
        TerminalConnectionScreen(
            tunnelUp = tunnelUp,
            tunnelStartElapsed = tunnelStartElapsed,
            uptimeTick = uptimeTick,
            server = server,
            sni = sni,
            bibaInvite = bibaInvite,
            onConnectToggle = onConnectToggle,
            tlsProfile = tlsProfile,
            decoyMax = decoyMax,
            maxPad = maxPad,
            padMode = padMode,
            pinCertPem = pinCertPem,
            insecure = insecure,
        )
    }
}

@Composable
private fun WelcomeScreen(
    onOpenConfig: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.ascii_logo_biba),
            color = Color.White,
            fontFamily = Mono,
            fontSize = 12.sp,
            lineHeight = 15.sp,
        )
        Spacer(Modifier.height(40.dp))
        Text(
            stringResource(R.string.welcome_operator),
            color = Color.White,
            fontFamily = Mono,
            fontSize = 16.sp,
        )
        Spacer(Modifier.height(16.dp))
        Text(
            stringResource(R.string.welcome_hint),
            color = TextDim66,
            fontFamily = Mono,
            fontSize = 12.sp,
            lineHeight = 18.sp,
        )
        Spacer(Modifier.height(48.dp))
        WelcomeOutlineButton(
            label = stringResource(R.string.btn_welcome_import),
            strong = true,
            onClick = onOpenConfig,
        )
        Spacer(Modifier.height(12.dp))
        WelcomeOutlineButton(
            label = stringResource(R.string.btn_welcome_manual),
            strong = false,
            onClick = onOpenConfig,
        )
    }
}

private val TextDim66 = Color(0xFF666666)

@Composable
private fun WelcomeOutlineButton(
    label: String,
    strong: Boolean,
    onClick: () -> Unit,
) {
    val border = if (strong) Color.White else Color(0xFF333333)
    Text(
        text = label,
        color = if (strong) Color.White else TextDim66,
        fontFamily = Mono,
        fontSize = 13.sp,
        fontWeight = FontWeight.Medium,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .border(1.dp, border, RoundedCornerShape(6.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 16.dp),
        textAlign = TextAlign.Center,
    )
}

@Composable
private fun TerminalConnectionScreen(
    tunnelUp: Boolean,
    tunnelStartElapsed: Long?,
    uptimeTick: Int,
    server: String,
    sni: String,
    bibaInvite: String,
    onConnectToggle: () -> Unit,
    tlsProfile: String,
    decoyMax: String,
    maxPad: String,
    padMode: String,
    pinCertPem: String,
    insecure: Boolean,
) {
    val bibaKeyShort = stringResource(R.string.home_biba_key_short)
    val noServer = stringResource(R.string.home_no_server)
    val displayName = remember(server, sni, bibaInvite, bibaKeyShort) {
        when {
            sni.isNotBlank() -> sni
            server.isNotBlank() -> server.substringBefore(':').ifBlank { server }
            bibaInvite.isNotBlank() -> bibaKeyShort
            else -> "—"
        }
    }
    val subtitle = remember(server, bibaInvite, noServer) {
        when {
            server.isNotBlank() -> server
            bibaInvite.isNotBlank() ->
                bibaInvite.take(40).let { if (bibaInvite.length > 40) "$it…" else it }
            else -> noServer
        }
    }
    var showTech by remember { mutableStateOf(true) }
    val scroll = rememberScrollState()
    val padLine =
        remember(decoyMax, maxPad, padMode) {
            "$decoyMax decoy · $maxPad pad · ${padMode.trim().ifBlank { "off" }}"
        }
    val tlsLine =
        remember(tlsProfile) {
            val p = tlsProfile.trim().ifBlank { "default" }
            "$p · chacha20-poly1305"
        }
    val sniLine = sni.trim().ifBlank { server.substringBefore(':').ifBlank { "—" } }
    val trustLine = when {
        pinCertPem.isNotBlank() -> stringResource(R.string.tech_trust_pinned)
        insecure -> "insecure"
        else -> stringResource(R.string.tech_trust_system)
    }
    val metricDash = stringResource(R.string.metric_dash)
    val rttText = metricDash
    val downText = if (tunnelUp) metricDash else "0 B/s"

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .drawBehind {
                val lineH = 3.dp.toPx()
                var y = 0f
                while (y < size.height) {
                    drawLine(
                        color = Color.White.copy(0.03f),
                        start = androidx.compose.ui.geometry.Offset(0f, y),
                        end = androidx.compose.ui.geometry.Offset(size.width, y),
                        strokeWidth = 1f,
                    )
                    y += lineH
                }
            }
            .verticalScroll(scroll)
            .padding(horizontal = 20.dp, vertical = 8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.wordmark),
                color = Color.White,
                fontFamily = Mono,
                fontSize = 20.sp,
                fontWeight = FontWeight.Normal,
            )
            Spacer(Modifier.weight(1f))
            StatusDot(active = tunnelUp)
            Spacer(Modifier.width(6.dp))
            Text(
                stringResource(if (tunnelUp) R.string.status_tunnel_up else R.string.status_tunnel_down),
                color = TextMuted,
                fontFamily = Mono,
                fontSize = 10.sp,
            )
        }
        Spacer(Modifier.height(20.dp))
        // Center: pill + power ring
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .clip(RoundedCornerShape(100))
                    .border(1.dp, Color.White, RoundedCornerShape(100))
                    .padding(horizontal = 12.dp, vertical = 6.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .clip(CircleShape)
                        .background(if (tunnelUp) Color.White else TextMuted),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(if (tunnelUp) R.string.status_tunnel_up else R.string.status_tunnel_down),
                    color = Color.White,
                    fontFamily = Mono,
                    fontSize = 10.sp,
                )
            }
            Spacer(Modifier.height(24.dp))
            PowerTunnelRing(
                onClick = onConnectToggle,
            ) {
                Text(
                    "⏻",
                    color = Color.White,
                    fontSize = 28.sp,
                    fontFamily = Mono,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(
                        if (tunnelUp) {
                            R.string.action_drop_tunnel
                        } else {
                            R.string.action_establish_tunnel
                        },
                    ),
                    color = Color.White,
                    fontFamily = Mono,
                    fontSize = 11.sp,
                )
            }
        }
        Spacer(Modifier.height(28.dp))
        Text(
            stringResource(R.string.label_endpoint),
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 10.sp,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            displayName,
            color = Color.White,
            fontFamily = Mono,
            fontSize = 18.sp,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            subtitle,
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 12.sp,
        )
        Spacer(Modifier.height(24.dp))
        // Metrics
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(64.dp)
                .border(1.dp, BorderSubtle, RoundedCornerShape(0.dp)),
        ) {
            TerminalMetric(
                label = stringResource(R.string.metric_rtt),
                value = rttText,
                modifier = Modifier.weight(1f),
            )
            Box(
                Modifier
                    .width(1.dp)
                    .fillMaxSize()
                    .background(BorderSubtle),
            )
            TerminalMetric(
                label = stringResource(R.string.metric_uptime),
                value = formatTunnelUptime(tunnelStartElapsed, uptimeTick).takeIf { tunnelUp } ?: metricDash,
                modifier = Modifier.weight(1f),
            )
            Box(
                Modifier
                    .width(1.dp)
                    .fillMaxSize()
                    .background(BorderSubtle),
            )
            TerminalMetric(
                label = stringResource(R.string.metric_down),
                value = downText,
                modifier = Modifier.weight(1f),
            )
        }
        Spacer(Modifier.height(20.dp))
        Text(
            if (showTech) stringResource(R.string.hide_technical) else stringResource(R.string.show_technical),
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 10.sp,
            modifier = Modifier
                .clickable { showTech = !showTech }
                .padding(vertical = 4.dp),
        )
        if (showTech) {
            Spacer(Modifier.height(8.dp))
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .border(1.dp, BorderSubtle, RoundedCornerShape(8.dp))
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TechKeyValue(
                    k = stringResource(R.string.tech_sni),
                    v = sniLine,
                )
                TechKeyValue(
                    k = stringResource(R.string.tech_tls),
                    v = tlsLine,
                )
                TechKeyValue(
                    k = stringResource(R.string.tech_auth),
                    v = stringResource(R.string.tech_auth_value),
                )
                TechKeyValue(
                    k = stringResource(R.string.tech_trust),
                    v = trustLine,
                )
                TechKeyValue(
                    k = stringResource(R.string.tech_pad),
                    v = padLine,
                )
            }
        }
    }
}

@Composable
private fun TechKeyValue(
    k: String,
    v: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            k,
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 12.sp,
        )
        Text(
            v,
            color = Color.White,
            fontFamily = Mono,
            fontSize = 12.sp,
            modifier = Modifier.padding(start = 8.dp),
        )
    }
}

@Composable
private fun TerminalMetric(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxHeight()
            .padding(vertical = 8.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            label,
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 9.sp,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            value,
            color = Color.White,
            fontFamily = Mono,
            fontSize = 12.sp,
        )
    }
}

@Composable
private fun PowerTunnelRing(
    onClick: () -> Unit,
    content: @Composable () -> Unit,
) {
    val glow = Brush.radialGradient(
        listOf(
            Color.White.copy(0.12f),
            Color.Transparent,
        ),
    )
    Box(
        modifier = Modifier
            .size(220.dp)
            .drawBehind {
                drawCircle(brush = glow, radius = size.minDimension * 0.5f, center = center)
            },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            modifier = Modifier
                .size(200.dp)
                .clip(CircleShape)
                .border(1.dp, Color.White, CircleShape)
                .clickable(onClick = onClick),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(150.dp)
                    .border(1.dp, Color.White.copy(0.85f), CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    content()
                }
            }
        }
    }
}

@Composable
private fun ProfilesTab(
    tunnelUp: Boolean,
    server: String,
    sni: String,
    bibaInvite: String,
    insecure: Boolean,
    onImport: () -> Unit,
) {
    val bibaKeyShort = stringResource(R.string.home_biba_key_short)
    val noServer = stringResource(R.string.home_no_server)
    val title = remember(server, sni, bibaInvite, bibaKeyShort, noServer) {
        when {
            sni.isNotBlank() -> sni
            server.isNotBlank() -> server.substringBefore(':').ifBlank { server }
            bibaInvite.isNotBlank() -> bibaKeyShort
            else -> noServer
        }
    }
    val sub = remember(server, bibaInvite, noServer) {
        if (server.isNotBlank()) {
            server
        } else if (bibaInvite.isNotBlank()) {
            bibaInvite.take(36).let { if (bibaInvite.length > 36) "$it…" else it }
        } else {
            "—"
        }
    }
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .verticalScroll(scroll)
            .padding(20.dp)
            .drawBehind {
                val lineH = 3.dp.toPx()
                var y = 0f
                while (y < size.height) {
                    drawLine(
                        color = Color.White.copy(0.03f),
                        start = androidx.compose.ui.geometry.Offset(0f, y),
                        end = androidx.compose.ui.geometry.Offset(size.width, y),
                        strokeWidth = 1f,
                    )
                    y += lineH
                }
            },
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Bottom,
        ) {
            Text(
                stringResource(R.string.profiles_header),
                color = Color.White,
                fontFamily = Mono,
                fontSize = 12.sp,
            )
            Spacer(Modifier.weight(1f))
            Text(
                stringResource(R.string.profiles_count_fmt, 1),
                color = TextMuted,
                fontFamily = Mono,
                fontSize = 10.sp,
            )
        }
        Spacer(Modifier.height(16.dp))
        // один сохранённый профиль
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(4.dp))
                .border(1.dp, if (tunnelUp) Color.White else BorderSubtle, RoundedCornerShape(4.dp))
                .clickable { }
                .padding(14.dp),
        ) {
            Text(title, color = Color.White, fontFamily = Mono, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(2.dp))
            Text(sub, color = TextMuted, fontFamily = Mono, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (tunnelUp) {
                    Text(
                        stringResource(R.string.profile_badge_active),
                        color = Color.White,
                        fontFamily = Mono,
                        fontSize = 9.sp,
                        modifier = Modifier
                            .border(1.dp, Color.White, RoundedCornerShape(2.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                }
                Text("—", color = TextMuted, fontFamily = Mono, fontSize = 11.sp)
                if (insecure) {
                    Spacer(Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.profile_badge_insecure),
                        color = TermOrange,
                        fontFamily = Mono,
                        fontSize = 9.sp,
                        modifier = Modifier
                            .border(1.dp, TermOrange, RoundedCornerShape(2.dp))
                            .padding(horizontal = 6.dp, vertical = 2.dp),
                    )
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        Text(
            stringResource(R.string.btn_import_biba),
            color = Color.White,
            fontFamily = Mono,
            fontSize = 12.sp,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(4.dp))
                .border(1.dp, BorderSubtle, RoundedCornerShape(4.dp))
                .clickable(onClick = onImport)
                .padding(16.dp),
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun LogsTab() {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(20.dp),
    ) {
        Text(
            stringResource(R.string.logs_title),
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 12.sp,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.logs_placeholder),
            color = TextMuted,
            fontFamily = Mono,
            fontSize = 12.sp,
        )
    }
}

@Composable
private fun TerminalBottomNav(
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
) {
    val items = listOf(
        Triple(R.string.nav_connection, "◆", 0),
        Triple(R.string.nav_profiles, "◎", 1),
        Triple(R.string.nav_config, "▤", 2),
        Triple(R.string.nav_logs, "≡", 3),
    )
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .navigationBarsPadding()
            .background(Color(0xFF000000))
            .border(1.dp, BorderSubtle)
            .padding(vertical = 6.dp, horizontal = 4.dp),
        horizontalArrangement = Arrangement.SpaceEvenly,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        items.forEach { (nameRes, sym, idx) ->
            val sel = selectedIndex == idx
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier
                    .weight(1f)
                    .clickable { onSelect(idx) }
                    .padding(4.dp),
            ) {
                Text(
                    sym,
                    color = if (sel) Color.White else TextMuted,
                    fontSize = 16.sp,
                    fontFamily = Mono,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    stringResource(nameRes),
                    color = if (sel) Color.White else TextMuted,
                    fontSize = 7.sp,
                    fontFamily = Mono,
                    maxLines = 1,
                )
                if (sel) {
                    Spacer(Modifier.height(2.dp))
                    Box(
                        Modifier
                            .height(1.dp)
                            .width(24.dp)
                            .background(Color.White),
                    )
                } else {
                    Spacer(Modifier.height(3.dp))
                }
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
    proto: String,
    onProtoChange: (String) -> Unit,
    protoDomain: String,
    onProtoDomainChange: (String) -> Unit,
    wsJitterMin: String,
    onWsJitterMinChange: (String) -> Unit,
    wsJitterMax: String,
    onWsJitterMaxChange: (String) -> Unit,
    stealthProfile: String,
    onStealthProfileChange: (String) -> Unit,
    decoyMode: String,
    onDecoyModeChange: (String) -> Unit,
    desyncMode: String,
    onDesyncModeChange: (String) -> Unit,
    tcpFooling: String,
    onTcpFoolingChange: (String) -> Unit,
    tlsFragment: Boolean,
    onTlsFragmentChange: (Boolean) -> Unit,
    wsParallel: String,
    onWsParallelChange: (String) -> Unit,
    idleDecoySecs: String,
    onIdleDecoySecsChange: (String) -> Unit,
    tlsStack: String,
    onTlsStackChange: (String) -> Unit,
    fingerprint: String,
    onFingerprintChange: (String) -> Unit,
    realityTarget: String,
    onRealityTargetChange: (String) -> Unit,
    realityPublicKey: String,
    onRealityPublicKeyChange: (String) -> Unit,
    realityShortId: String,
    onRealityShortIdChange: (String) -> Unit,
    wsHost: String,
    onWsHostChange: (String) -> Unit,
    wsOrigin: String,
    onWsOriginChange: (String) -> Unit,
    wsUserAgent: String,
    onWsUserAgentChange: (String) -> Unit,
    wsAcceptLanguage: String,
    onWsAcceptLanguageChange: (String) -> Unit,
    screenOffBatterySaver: Boolean,
    onScreenOffBatterySaverChange: (Boolean) -> Unit,
    onBack: (() -> Unit)? = null,
) {
    var settingsTab by remember { mutableStateOf(0) }
    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .background(BgScreen)
            .verticalScroll(scroll)
            .padding(20.dp),
    ) {
        if (onBack != null) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                RoundIconButton(onClick = onBack, symbol = "‹")
                Text(
                    stringResource(R.string.settings_title),
                    color = TextSlate200,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                    fontFamily = Mono,
                    letterSpacing = 0.6.sp,
                )
                Spacer(Modifier.width(40.dp))
            }
            Spacer(Modifier.height(24.dp))
        } else {
            Text(
                stringResource(R.string.config_screen_title),
                color = TextMuted,
                fontFamily = Mono,
                fontSize = 12.sp,
            )
            Spacer(Modifier.height(12.dp))
        }

        SettingsTabsRow(
            selectedIndex = settingsTab,
            onSelect = { settingsTab = it },
        )

        Spacer(Modifier.height(16.dp))

        if (settingsTab == 0) {
        LanguageSettingsBlock()

        Spacer(Modifier.height(16.dp))

        SettingsSection(
            title = stringResource(R.string.section_biba_key),
            subtitle = stringResource(R.string.section_biba_key_sub),
        ) {
            SettingsTextField(
                label = stringResource(R.string.field_biba_key),
                value = bibaInvite,
                onChange = onBibaInviteChange,
                placeholder = stringResource(R.string.placeholder_biba_key),
                singleLine = false,
                maxLines = 4,
            )
            SettingsTextField(
                label = stringResource(R.string.field_passphrase),
                value = invitePassphrase,
                onChange = onInvitePassphraseChange,
                placeholder = stringResource(R.string.placeholder_passphrase),
                isPassword = true,
            )
            Text(
                stringResource(R.string.hint_biba_key_override),
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
                Text(stringResource(R.string.btn_apply_invite), fontWeight = FontWeight.SemiBold)
            }
        }

        Spacer(Modifier.height(16.dp))

        SettingsSection(
            title = stringResource(R.string.section_connection),
            subtitle = stringResource(R.string.section_connection_sub),
        ) {
            SettingsTextField(
                label = stringResource(R.string.field_server),
                value = server,
                onChange = onServerChange,
                placeholder = stringResource(R.string.placeholder_server),
            )
            SettingsTextField(
                label = stringResource(R.string.field_token),
                value = token,
                onChange = onTokenChange,
                placeholder = stringResource(R.string.placeholder_token),
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
                label = stringResource(R.string.field_sni),
                value = sni,
                onChange = onSniChange,
                placeholder = stringResource(R.string.placeholder_sni),
                hint = stringResource(R.string.hint_sni),
            )
            SettingsTextField(
                label = stringResource(R.string.field_psk),
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
                    Text(stringResource(R.string.toggle_insecure_title), color = Color.White, fontSize = 14.sp)
                    Text(stringResource(R.string.toggle_insecure_sub), color = TextMuted, fontSize = 12.sp)
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
            title = stringResource(R.string.section_network),
            subtitle = stringResource(R.string.section_network_sub),
        ) {
            SettingsStaticField(
                label = stringResource(R.string.field_routing_mode),
                value = stringResource(R.string.value_system_vpn),
                hint = stringResource(R.string.hint_routing_mode),
            )
            SettingsTextField(
                label = stringResource(R.string.field_local_socks),
                value = socksBind,
                onChange = onSocksBindChange,
                placeholder = BibaVpnService.SOCKS_LOCAL,
                hint = stringResource(R.string.hint_socks_empty, BibaVpnService.SOCKS_LOCAL),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.toggle_battery_saver_title), color = Color.White, fontSize = 14.sp)
                    Text(
                        stringResource(R.string.toggle_battery_saver_sub),
                        color = TextMuted,
                        fontSize = 12.sp,
                    )
                }
                Switch(
                    checked = screenOffBatterySaver,
                    onCheckedChange = onScreenOffBatterySaverChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Mint,
                        checkedTrackColor = Mint.copy(alpha = 0.4f),
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = TextMuted.copy(alpha = 0.3f),
                    ),
                )
            }
            val settingsCtx = LocalContext.current
            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .border(1.dp, BorderSubtle, RoundedCornerShape(14.dp))
                    .clickable {
                        val act = settingsCtx as? ComponentActivity
                        if (act != null) {
                            openBatteryOptimizationSettings(act)
                        }
                    }
                    .padding(horizontal = 16.dp, vertical = 14.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        stringResource(R.string.battery_row_title),
                        color = Color.White,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.battery_row_sub),
                        color = TextMuted,
                        fontSize = 12.sp,
                    )
                }
                Text("›", color = TextMuted.copy(alpha = 0.55f), fontSize = 22.sp)
            }
        }

        Spacer(Modifier.height(16.dp))

        SettingsSection(
            title = stringResource(R.string.section_transport),
            subtitle = stringResource(R.string.section_transport_sub),
        ) {
            SettingsTextField(
                label = "tls_profile",
                value = tlsProfile,
                onChange = onTlsProfileChange,
                placeholder = "default",
                hint = stringResource(R.string.hint_tls_profile),
            )
            SettingsTextField(
                label = "fingerprint",
                value = fingerprint,
                onChange = onFingerprintChange,
                placeholder = "chrome-132",
                hint = stringResource(R.string.hint_fingerprint),
            )
            SettingsTextField(
                label = "tls_stack",
                value = tlsStack,
                onChange = onTlsStackChange,
                placeholder = "rustls",
                hint = stringResource(R.string.hint_tls_stack),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "proto",
                    value = proto,
                    onChange = onProtoChange,
                    hint = stringResource(R.string.hint_proto),
                    modifier = Modifier.weight(1f),
                )
                Column(modifier = Modifier.weight(2f)) {
                    SettingsTextField(
                        label = "proto_domain",
                        value = protoDomain,
                        onChange = onProtoDomainChange,
                        placeholder = "",
                        hint = stringResource(R.string.hint_proto_domain),
                    )
                }
            }
            SettingsTextField(
                label = "ws_path",
                value = wsPath,
                onChange = onWsPathChange,
                placeholder = "/ws",
                hint = stringResource(R.string.hint_ws_path),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.toggle_tcp_mux_title), color = Color.White, fontSize = 14.sp)
                    Text(stringResource(R.string.toggle_tcp_mux_sub), color = TextMuted, fontSize = 12.sp)
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
                placeholder = stringResource(R.string.placeholder_pad_mode),
                hint = stringResource(R.string.hint_pad_mode),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "max_pad",
                    value = maxPad,
                    onChange = onMaxPadChange,
                    hint = stringResource(R.string.hint_max_pad),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "decoy_max",
                    value = decoyMax,
                    onChange = onDecoyMaxChange,
                    hint = stringResource(R.string.hint_decoy_max),
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
                    hint = stringResource(R.string.hint_ws_ping_jitter),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "ws_send_jitter_ms",
                    value = wsBinaryJitter,
                    onChange = onWsBinaryJitterChange,
                    hint = stringResource(R.string.hint_ws_binary_jitter),
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "ws_jitter_min_ms",
                    value = wsJitterMin,
                    onChange = onWsJitterMinChange,
                    hint = stringResource(R.string.hint_ws_jitter_min),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "ws_jitter_max_ms",
                    value = wsJitterMax,
                    onChange = onWsJitterMaxChange,
                    hint = stringResource(R.string.hint_ws_jitter_max),
                    modifier = Modifier.weight(1f),
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "ws_parallel",
                    value = wsParallel,
                    onChange = onWsParallelChange,
                    hint = stringResource(R.string.hint_ws_parallel),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "idle_decoy_secs",
                    value = idleDecoySecs,
                    onChange = onIdleDecoySecsChange,
                    hint = stringResource(R.string.hint_idle_decoy_secs),
                    modifier = Modifier.weight(1f),
                )
            }
            SettingsTextField(
                label = "stealth_profile",
                value = stealthProfile,
                onChange = onStealthProfileChange,
                placeholder = "default | balanced | aggressive",
                hint = stringResource(R.string.hint_stealth_profile),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "decoy_mode",
                    value = decoyMode,
                    onChange = onDecoyModeChange,
                    hint = stringResource(R.string.hint_decoy_mode),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "desync_mode",
                    value = desyncMode,
                    onChange = onDesyncModeChange,
                    hint = stringResource(R.string.hint_desync_mode),
                    modifier = Modifier.weight(1f),
                )
            }
            SettingsTextField(
                label = "tcp_fooling",
                value = tcpFooling,
                onChange = onTcpFoolingChange,
                placeholder = "",
                hint = stringResource(R.string.hint_tcp_fooling),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("tls_fragment", color = Color.White, fontSize = 14.sp)
                    Text(stringResource(R.string.hint_tls_fragment), color = TextMuted, fontSize = 12.sp)
                }
                Switch(
                    checked = tlsFragment,
                    onCheckedChange = onTlsFragmentChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Mint,
                        checkedTrackColor = Mint.copy(alpha = 0.4f),
                        uncheckedThumbColor = TextMuted,
                        uncheckedTrackColor = TextMuted.copy(alpha = 0.3f),
                    ),
                )
            }
            SettingsTextField(
                label = "reality_target",
                value = realityTarget,
                onChange = onRealityTargetChange,
                placeholder = "",
                hint = stringResource(R.string.hint_reality_target),
            )
            SettingsTextField(
                label = "reality_public_key",
                value = realityPublicKey,
                onChange = onRealityPublicKeyChange,
                singleLine = false,
                maxLines = 3,
                placeholder = "base64, 32 bytes",
                hint = stringResource(R.string.hint_reality_public_key),
            )
            SettingsTextField(
                label = "reality_short_id",
                value = realityShortId,
                onChange = onRealityShortIdChange,
                placeholder = "16 hex",
                hint = stringResource(R.string.hint_reality_short_id),
            )
            SettingsTextField(
                label = "ws_host",
                value = wsHost,
                onChange = onWsHostChange,
                placeholder = "",
            )
            SettingsTextField(
                label = "ws_origin",
                value = wsOrigin,
                onChange = onWsOriginChange,
                placeholder = "",
            )
            SettingsTextField(
                label = "ws_user_agent",
                value = wsUserAgent,
                onChange = onWsUserAgentChange,
                placeholder = "",
            )
            SettingsTextField(
                label = "ws_accept_language",
                value = wsAcceptLanguage,
                onChange = onWsAcceptLanguageChange,
                placeholder = "",
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                SettingsMiniField(
                    label = "udp_max_pad",
                    value = udpMaxPad,
                    onChange = onUdpMaxPadChange,
                    hint = stringResource(R.string.hint_udp_max_pad),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "udp_max_ws",
                    value = udpMaxWsBin,
                    onChange = onUdpMaxWsBinChange,
                    hint = stringResource(R.string.hint_udp_max_ws),
                    modifier = Modifier.weight(1f),
                )
                SettingsMiniField(
                    label = "udp_mux_to",
                    value = udpMuxTimeout,
                    onChange = onUdpMuxTimeoutChange,
                    hint = stringResource(R.string.hint_udp_mux_to),
                    modifier = Modifier.weight(1f),
                )
            }
            SettingsMiniField(
                label = "dummy_interval_secs",
                value = dummyInterval,
                onChange = onDummyIntervalChange,
                hint = stringResource(R.string.hint_dummy_interval),
                modifier = Modifier.fillMaxWidth(),
            )
            SettingsTextField(
                label = "ws_headers",
                value = wsHeaders,
                onChange = onWsHeadersChange,
                singleLine = false,
                maxLines = 5,
                placeholder = stringResource(R.string.placeholder_ws_headers),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.toggle_decoy_gets_title), color = Color.White, fontSize = 14.sp)
                    Text(stringResource(R.string.toggle_decoy_gets_sub), color = TextMuted, fontSize = 12.sp)
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
                    hint = stringResource(R.string.hint_decoy_interval),
                    modifier = Modifier.fillMaxWidth(),
                )
                SettingsTextField(
                    label = "decoy_gets_paths",
                    value = decoyGetsPaths,
                    onChange = onDecoyGetsPathsChange,
                    placeholder = stringResource(R.string.placeholder_decoy_paths),
                    hint = stringResource(R.string.hint_decoy_paths),
                )
            }
            SettingsTextField(
                label = "pin_cert_pem",
                value = pinCertPem,
                onChange = onPinCertPemChange,
                singleLine = false,
                maxLines = 8,
                placeholder = stringResource(R.string.placeholder_pin_cert),
                hint = stringResource(R.string.hint_pin_cert),
            )
        }

        Spacer(Modifier.height(24.dp))
        } else {
            SplitTunnelSettingsPanel()
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun LanguageSettingsBlock() {
    val context = LocalContext.current
    val activity = context as ComponentActivity
    var expanded by remember { mutableStateOf(false) }
    var selectedTag by remember {
        mutableStateOf(AppLocale.getSavedLanguageTag(context))
    }

    val options =
        listOf(
            "" to R.string.lang_system,
            "ru" to R.string.lang_russian,
            "en" to R.string.lang_english,
            "fa-IR" to R.string.lang_persian,
            "es" to R.string.lang_spanish,
            "zh-CN" to R.string.lang_chinese,
        )
    val currentLabelRes =
        options.firstOrNull { it.first == selectedTag }?.second ?: R.string.lang_system

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(28.dp))
            .border(1.dp, BorderSubtle, RoundedCornerShape(28.dp))
            .background(CardBg.copy(alpha = 0.92f))
            .padding(20.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(12.dp))
                .clickable { expanded = !expanded }
                .padding(vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.section_language),
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(4.dp))
                if (expanded) {
                    Text(
                        stringResource(R.string.section_language_sub),
                        color = TextMuted,
                        fontSize = 14.sp,
                    )
                } else {
                    Text(
                        stringResource(currentLabelRes),
                        color = Mint.copy(alpha = 0.92f),
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                    )
                }
            }
            Text(
                if (expanded) "\u25B2" else "\u25BC",
                color = TextMuted.copy(alpha = 0.75f),
                fontSize = 14.sp,
                modifier = Modifier.padding(start = 8.dp),
            )
        }

        if (expanded) {
            Spacer(Modifier.height(16.dp))
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                options.forEach { (tag, labelRes) ->
                    val selected = selectedTag == tag
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(if (selected) Mint.copy(alpha = 0.12f) else Color.Transparent)
                            .clickable {
                                if (tag != selectedTag) {
                                    AppLocale.persist(context, tag)
                                    selectedTag = tag
                                    activity.recreate()
                                }
                            }
                            .padding(horizontal = 12.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text(
                            stringResource(labelRes),
                            color = if (selected) Mint else Color.White,
                            fontSize = 15.sp,
                            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                        )
                        if (selected) {
                            Text("\u2713", color = Mint, fontSize = 16.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsTabsRow(
    selectedIndex: Int,
    onSelect: (Int) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
            .background(Color(0xFF020617).copy(alpha = 0.35f))
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        listOf(
            stringResource(R.string.tab_connection) to 0,
            stringResource(R.string.tab_split_tunnel) to 1,
        ).forEach { (label, idx) ->
            val selected = selectedIndex == idx
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(12.dp))
                    .background(if (selected) Mint.copy(alpha = 0.15f) else Color.Transparent)
                    .clickable { onSelect(idx) }
                    .padding(vertical = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    color = if (selected) Mint else TextMuted,
                    fontSize = 14.sp,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
                )
            }
        }
    }
}

@Composable
private fun SplitTunnelSettingsPanel() {
    val ctx = LocalContext.current
    var enabled by remember { mutableStateOf(BibaVpnService.isSplitTunnelEnabled(ctx)) }
    var selected by remember {
        mutableStateOf(BibaVpnService.getSplitTunnelSelectedPackages(ctx).toMutableSet())
    }
    var expandedGroups by remember {
        mutableStateOf<Set<SplitTunnelGroup>>(emptySet())
    }

    fun persist(
        newEnabled: Boolean = enabled,
        newSelected: Set<String> = selected,
    ) {
        enabled = newEnabled
        selected = newSelected.toMutableSet()
        BibaVpnService.setSplitTunnelConfig(ctx, newEnabled, selected)
    }

    SettingsSection(
        title = stringResource(R.string.split_tunnel_title),
        subtitle = stringResource(R.string.split_tunnel_sub),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.split_enable_title), color = Color.White, fontSize = 14.sp)
                Text(
                    stringResource(R.string.split_enable_sub),
                    color = TextMuted,
                    fontSize = 12.sp,
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = { v ->
                    val sel =
                        if (v && selected.isEmpty()) {
                            SplitTunnelCatalog.allPackageNames().toMutableSet()
                        } else {
                            selected
                        }
                    persist(v, sel)
                },
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Mint,
                    checkedTrackColor = Mint.copy(alpha = 0.4f),
                    uncheckedThumbColor = TextMuted,
                    uncheckedTrackColor = TextMuted.copy(alpha = 0.3f),
                ),
            )
        }

        if (BibaVpnService.isTunnelActive) {
            Text(
                stringResource(R.string.split_reapply_hint),
                color = LabelSky.copy(alpha = 0.85f),
                fontSize = 12.sp,
            )
        }

        if (!enabled) {
            Text(
                stringResource(R.string.split_toggle_groups_hint),
                color = TextMuted,
                fontSize = 12.sp,
            )
            return@SettingsSection
        }

        enumValues<SplitTunnelGroup>().forEach { group ->
            SplitTunnelGroupDropdown(
                group = group,
                expanded = expandedGroups.contains(group),
                onToggleExpand = {
                    expandedGroups =
                        expandedGroups.toMutableSet().apply {
                            if (contains(group)) remove(group) else add(group)
                        }
                },
                entries = SplitTunnelCatalog.forGroup(group),
                selected = selected,
                enabledMaster = enabled,
                onAppCheckedChange = { pkg, checked ->
                    val next = selected.toMutableSet()
                    if (checked) next.add(pkg) else next.remove(pkg)
                    persist(enabled, next)
                },
            )
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun SplitTunnelGroupDropdown(
    group: SplitTunnelGroup,
    expanded: Boolean,
    onToggleExpand: () -> Unit,
    entries: List<SplitTunnelApp>,
    selected: Set<String>,
    enabledMaster: Boolean,
    onAppCheckedChange: (String, Boolean) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .border(1.dp, BorderSubtle, RoundedCornerShape(16.dp))
            .background(Color(0xFF020617).copy(alpha = 0.55f)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onToggleExpand)
                .padding(horizontal = 16.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(group.titleRes),
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    stringResource(
                        R.string.split_selected_count,
                        entries.count { selected.contains(it.packageName) },
                        entries.size,
                    ),
                    color = TextMuted,
                    fontSize = 12.sp,
                )
            }
            Text(
                if (expanded) "\u25B2" else "\u25BC",
                color = TextMuted.copy(alpha = 0.75f),
                fontSize = 14.sp,
            )
        }
        if (expanded) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 8.dp, end = 8.dp, bottom = 8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                entries.forEach { app ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = selected.contains(app.packageName),
                            onCheckedChange = { onAppCheckedChange(app.packageName, it) },
                            enabled = enabledMaster,
                            colors = CheckboxDefaults.colors(
                                checkedColor = Mint,
                                uncheckedColor = TextMuted,
                                checkmarkColor = Color(0xFF020617),
                            ),
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                stringResource(app.labelRes),
                                color = TextSlate200,
                                fontSize = 14.sp,
                            )
                            Text(
                                app.packageName,
                                color = TextMuted.copy(alpha = 0.8f),
                                fontSize = 11.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }
        }
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
    wsJitterMin: Int,
    wsJitterMax: Int,
    udpMaxPad: Int?,
    udpMaxWsBinary: Int?,
    udpMuxTimeout: Long?,
    dummyInterval: Long,
    decoyGets: Boolean,
    decoyGetsInterval: Long,
    decoyGetsPaths: String,
    pinCertPem: String,
    proto: Int,
    protoDomain: String,
    stealthProfile: String,
    decoyMode: String,
    desyncMode: String,
    tcpFooling: String,
    tlsFragment: Boolean,
    wsParallel: Int,
    idleDecoySecs: Long,
    tlsStack: String,
    fingerprint: String,
    realityTarget: String,
    realityPublicKey: String,
    realityShortId: String,
    wsHost: String,
    wsOrigin: String,
    wsUserAgent: String,
    wsAcceptLanguage: String,
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
    // In invite mode, keep the transport identity from the invite unless the app grows
    // an explicit override UX. Mixing invite + stale form values breaks v3 ACK MAC.
    if (!useInvite && sni.isNotBlank()) o.put("sni", sni)
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
    val jMin = wsJitterMin.coerceIn(0, 255)
    val jMax = wsJitterMax.coerceIn(0, 255)
    if (jMin > 0) o.put("ws_jitter_min_ms", jMin)
    if (jMax > 0) o.put("ws_jitter_max_ms", jMax)
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

    val p = proto.coerceIn(1, 255)
    if (p != 3) o.put("proto", p)
    val pd = protoDomain.trim()
    if (!useInvite && pd.isNotEmpty()) o.put("proto_domain", pd)
    val sp = stealthProfile.trim()
    if (sp.isNotEmpty()) o.put("stealth_profile", sp)
    val dm = decoyMode.trim()
    if (dm.isNotEmpty()) o.put("decoy_mode", dm)
    val dsm = desyncMode.trim()
    if (dsm.isNotEmpty()) o.put("desync_mode", dsm)
    val tf = tcpFooling.trim()
    if (tf.isNotEmpty()) o.put("tcp_fooling", tf)
    if (tlsFragment) o.put("tls_fragment", true)
    // Всегда передаём в Rust: при invite иначе парсер брал бы только ws_parallel из ключа, игнорируя форму.
    o.put("ws_parallel", wsParallel.coerceIn(1, 4))
    if (idleDecoySecs > 0) o.put("idle_decoy_secs", idleDecoySecs)
    val tst = tlsStack.trim().lowercase()
    if (tst.isNotEmpty() && tst != "rustls") o.put("tls_stack", tst)
    val fp = fingerprint.trim()
    if (fp.isNotEmpty()) o.put("fingerprint", fp)
    val rt = realityTarget.trim()
    val rpk = realityPublicKey.trim()
    val rsid = realityShortId.trim()
    if (rt.isNotEmpty() && rpk.isNotEmpty()) {
        o.put("reality_target", rt)
        o.put("reality_public_key", rpk)
        if (rsid.isNotEmpty()) o.put("reality_short_id", rsid)
    }
    if (wsHost.isNotEmpty()) o.put("ws_host", wsHost)
    if (wsOrigin.isNotEmpty()) o.put("ws_origin", wsOrigin)
    if (wsUserAgent.isNotEmpty()) o.put("ws_user_agent", wsUserAgent)
    if (wsAcceptLanguage.isNotEmpty()) o.put("ws_accept_language", wsAcceptLanguage)
    return o
}

/** Системный экран: разрешить приложению игнорировать оптимизацию батареи (или запасные настройки). */
private fun openBatteryOptimizationSettings(activity: ComponentActivity) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
        Toast.makeText(activity, activity.getString(R.string.toast_battery_android6), Toast.LENGTH_SHORT).show()
        return
    }
    val pkg = activity.packageName
    try {
        activity.startActivity(
            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$pkg")
            },
        )
    } catch (e: ActivityNotFoundException) {
        Log.w("BibaMain", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", e)
        openBatteryOptimizationFallback(activity, pkg)
    } catch (e: SecurityException) {
        Log.w("BibaMain", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS denied", e)
        openBatteryOptimizationFallback(activity, pkg)
    }
}

private fun openBatteryOptimizationFallback(
    activity: ComponentActivity,
    pkg: String,
) {
    try {
        activity.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    } catch (_: Exception) {
        try {
            activity.startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.fromParts("package", pkg, null)
                },
            )
        } catch (e: Exception) {
            Log.e("BibaMain", "battery optimization settings", e)
            Toast.makeText(activity, activity.getString(R.string.toast_battery_open_failed), Toast.LENGTH_SHORT).show()
        }
    }
}
