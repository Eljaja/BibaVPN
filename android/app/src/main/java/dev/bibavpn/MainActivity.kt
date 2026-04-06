package dev.bibavpn

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

private val Night = Color(0xFF0A0612)
private val DeepPurple = Color(0xFF1A0F2E)
private val Accent = Color(0xFF7C4DFF)
private val AccentGlow = Color(0xFF00E5FF)
private val TextMuted = Color(0xFFB39DDB)
private val CardBg = Color(0xFF1E1530)

class MainActivity : ComponentActivity() {

    private val notifPerm = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { }

    private var pendingConnectJson: String? = null

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val json = pendingConnectJson
        pendingConnectJson = null
        if (result.resultCode == RESULT_OK && json != null) {
            BibaVpnService.startWithJson(this, json)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        setContent {
            MaterialTheme {
                Surface(color = Color.Transparent) {
                    BibaRootScreen(
                        onRequestVpnConnect = { json ->
                            val prep = VpnService.prepare(this@MainActivity)
                            if (prep != null) {
                                pendingConnectJson = json
                                vpnPermission.launch(prep)
                            } else {
                                BibaVpnService.startWithJson(this@MainActivity, json)
                            }
                        },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BibaRootScreen(
    onRequestVpnConnect: (String) -> Unit,
) {
    val context = LocalContext.current
    val scroll = rememberScrollState()
    val last = remember {
        BibaVpnService.getLastConfigJson(context)?.let { runCatching { JSONObject(it) }.getOrNull() }
    }

    var server by remember { mutableStateOf(last?.optString("server") ?: "") }
    var token by remember { mutableStateOf(last?.optString("token") ?: "") }
    var sni by remember { mutableStateOf(last?.optString("sni") ?: "") }
    var psk by remember { mutableStateOf(last?.optString("psk") ?: "") }
    var socksBind by remember {
        mutableStateOf(last?.optString("socks_bind") ?: "")
    }
    var insecure by remember { mutableStateOf(last?.optBoolean("insecure") ?: false) }
    var advancedOpen by remember { mutableStateOf(false) }
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

    val gradient = Brush.verticalGradient(
        listOf(Night, DeepPurple, Color(0xFF120A22)),
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(gradient),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scroll)
                .padding(horizontal = 20.dp, vertical = 28.dp),
        ) {
            Text(
                text = "BibaVPN",
                color = Color.White,
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Сервер и ключи → системный VPN: весь трафик уходит в BibaVPN (как «ключ» Android). " +
                    "Обфускация в «Дополнительно» (max_pad, decoy_max, junk_frames, PSK) действует и для TCP, и для UDP " +
                    "(DNS и прочий UDP через SOCKS5 UDP ASSOCIATE → отдельный WS mux).",
                color = TextMuted,
                fontSize = 14.sp,
                modifier = Modifier.padding(top = 6.dp, bottom = 20.dp),
            )

            Card(
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = CardBg),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp),
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    FieldLabel("Сервер (host:port)")
                    OutlinedTextField(
                        value = server,
                        onValueChange = { server = it },
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text("vpn.example.com:443", color = TextMuted) },
                        singleLine = true,
                        colors = fieldColors(),
                    )
                    Spacer(Modifier.height(12.dp))
                    FieldLabel("Токен (path /b/{token})")
                    OutlinedTextField(
                        value = token,
                        onValueChange = { token = it },
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        colors = fieldColors(),
                    )
                    Spacer(Modifier.height(12.dp))
                    FieldLabel("SNI / TLS имя (пусто = host из сервера)")
                    OutlinedTextField(
                        value = sni,
                        onValueChange = { sni = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = fieldColors(),
                    )
                    Spacer(Modifier.height(12.dp))
                    FieldLabel("PSK (BibaV2, опционально)")
                    OutlinedTextField(
                        value = psk,
                        onValueChange = { psk = it },
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        colors = fieldColors(),
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "С PSK тот же профиль, что и у TCP: задайте decoy_max под сервер (часто 32), иначе UDP mux не сойдётся.",
                        color = TextMuted,
                        fontSize = 12.sp,
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(
                            checked = insecure,
                            onCheckedChange = { insecure = it },
                            colors = CheckboxDefaults.colors(
                                checkedColor = Accent,
                                uncheckedColor = TextMuted,
                            ),
                        )
                        Text("Пропускать проверку TLS (insecure)", color = Color.White)
                    }

                    Spacer(Modifier.height(8.dp))
                    TextButton(onClick = { advancedOpen = !advancedOpen }) {
                        Text(
                            if (advancedOpen) "▼ Дополнительно" else "▶ Дополнительно",
                            color = AccentGlow,
                            fontWeight = FontWeight.Medium,
                        )
                    }
                    AnimatedVisibility(advancedOpen) {
                        Column {
                            FieldLabel("Локальный SOCKS (оставь пустым = ${BibaVpnService.SOCKS_LOCAL})")
                            OutlinedTextField(
                                value = socksBind,
                                onValueChange = { socksBind = it },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                placeholder = { Text(BibaVpnService.SOCKS_LOCAL, color = TextMuted) },
                                colors = fieldColors(),
                            )
                            Spacer(Modifier.height(12.dp))
                            SmallIntField("max_pad", maxPad) { maxPad = it }
                            SmallIntField("decoy_max", decoyMax) { decoyMax = it }
                            SmallIntField("junk_frames", junkFrames) { junkFrames = it }
                            SmallIntField("early_ws_frames", earlyWs) { earlyWs = it }
                            SmallIntField("max_ws_binary", maxWsBin) { maxWsBin = it }
                            SmallIntField("ws_ping_secs", wsPing) { wsPing = it }
                            Spacer(Modifier.height(8.dp))
                            FieldLabel("ws_headers (строки «Name: value»)")
                            OutlinedTextField(
                                value = wsHeaders,
                                onValueChange = { wsHeaders = it },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(120.dp),
                                maxLines = 5,
                                colors = fieldColors(),
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Button(
                    onClick = {
                        val json = buildJson(
                            server = server.trim(),
                            token = token,
                            sni = sni.trim(),
                            psk = psk.trim(),
                            socksBind = socksBind.trim(),
                            insecure = insecure,
                            maxPad = maxPad.toIntOrNull() ?: 64,
                            decoyMax = decoyMax.toIntOrNull() ?: 32,
                            junkFrames = junkFrames.toIntOrNull() ?: 0,
                            earlyWs = earlyWs.toIntOrNull() ?: 0,
                            maxWsBinary = maxWsBin.toIntOrNull() ?: 1400,
                            wsPing = wsPing.toLongOrNull() ?: 25L,
                            wsHeaders = wsHeaders,
                        )
                        onRequestVpnConnect(json.toString())
                    },
                    modifier = Modifier
                        .weight(1f)
                        .height(52.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Accent,
                        contentColor = Color.White,
                    ),
                    contentPadding = PaddingValues(horizontal = 8.dp),
                ) {
                    Text("Подключить", fontWeight = FontWeight.SemiBold)
                }
                Button(
                    onClick = { BibaVpnService.stop(context) },
                    modifier = Modifier
                        .weight(1f)
                        .height(52.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF3D2E5C),
                        contentColor = Color.White,
                    ),
                ) {
                    Text("Стоп", fontWeight = FontWeight.SemiBold)
                }
            }
            Spacer(Modifier.height(16.dp))
            Text(
                text = "Нужно разрешение VPN. Остановка — кнопка «Стоп» или через уведомление.",
                color = TextMuted,
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun FieldLabel(text: String) {
    Text(
        text = text,
        color = AccentGlow,
        fontSize = 12.sp,
        fontWeight = FontWeight.Medium,
        modifier = Modifier.padding(bottom = 4.dp),
    )
}

@Composable
private fun SmallIntField(
    name: String,
    value: String,
    onChange: (String) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(name, color = Color.White, modifier = Modifier.weight(0.45f))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier.weight(0.55f),
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            colors = fieldColors(),
        )
    }
}

@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Color.White,
    unfocusedTextColor = Color.White,
    focusedBorderColor = Accent,
    unfocusedBorderColor = Color(0xFF4A3F6B),
    cursorColor = AccentGlow,
    focusedPlaceholderColor = TextMuted,
)

private fun buildJson(
    server: String,
    token: String,
    sni: String,
    psk: String,
    socksBind: String,
    insecure: Boolean,
    maxPad: Int,
    decoyMax: Int,
    junkFrames: Int,
    earlyWs: Int,
    maxWsBinary: Int,
    wsPing: Long,
    wsHeaders: String,
): JSONObject {
    val o = JSONObject()
    o.put("server", server)
    o.put("token", token)
    if (sni.isNotBlank()) o.put("sni", sni)
    o.put("socks_bind", socksBind.trim().ifBlank { BibaVpnService.SOCKS_LOCAL })
    o.put("insecure", insecure)
    o.put("max_pad", maxPad)
    o.put("decoy_max", decoyMax.coerceIn(0, 255))
    o.put("junk_frames", junkFrames)
    o.put("early_ws_frames", earlyWs)
    o.put("max_ws_binary", maxWsBinary)
    o.put("ws_ping_secs", wsPing)
    if (psk.isNotBlank()) o.put("psk", psk)
    val lines = wsHeaders.lines().map { it.trim() }.filter { it.isNotBlank() }
    if (lines.isNotEmpty()) o.put("ws_headers", JSONArray(lines))
    return o
}
