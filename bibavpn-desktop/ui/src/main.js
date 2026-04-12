import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

/**
 * @typedef {object} StateSnapshot
 * @property {Record<string, unknown>} cfg
 * @property {boolean} connected
 * @property {string} displayHost
 * @property {string} serverSubtitle
 * @property {string | null} [tunnelServer]
 * @property {string | null} [error]
 * @property {boolean} canConnect
 */

const $ = (id) => document.getElementById(id);

const FIELD_IDS = [
  "from_invite",
  "invite_passphrase",
  "server",
  "token",
  "sni",
  "psk",
  "insecure",
  "local_http_port",
  "local_socks_port",
  "max_pad",
  "decoy_max",
  "junk_frames",
  "early_ws_frames",
  "max_ws_binary",
  "ws_ping_secs",
  "use_tcp_mux",
  "ws_path",
  "pad_mode",
  "ws_ping_jitter_percent",
  "ws_binary_send_jitter_ms",
  "dummy_interval_secs",
  "decoy_gets",
  "decoy_gets_interval_secs",
  "decoy_gets_paths",
  "udp_max_pad",
  "udp_max_ws_binary",
  "udp_mux_reply_timeout_secs",
  "pin_cert_pem",
  "ws_headers",
  "tls_profile",
];

/** @param {Partial<Record<string, unknown>>} cfg */
function formToCfg(cfg) {
  const o = { ...cfg };
  for (const key of FIELD_IDS) {
    const el = document.getElementById(`f-${key}`);
    if (!el) continue;
    if (el instanceof HTMLInputElement && el.type === "checkbox") {
      o[key] = el.checked;
    } else if (el instanceof HTMLSelectElement) {
      o[key] = el.value;
    } else if (
      el instanceof HTMLInputElement &&
      (el.type === "number" || el.classList.contains("field-num"))
    ) {
      const n = Number(el.value);
      o[key] = Number.isFinite(n) ? n : 0;
    } else {
      o[key] = el.value;
    }
  }
  return o;
}

/** @param {Record<string, unknown>} cfg */
function cfgToForm(cfg) {
  for (const key of FIELD_IDS) {
    const el = document.getElementById(`f-${key}`);
    if (!el) continue;
    const v = cfg[key];
    if (el instanceof HTMLInputElement && el.type === "checkbox") {
      el.checked = Boolean(v);
    } else if (el instanceof HTMLSelectElement) {
      const s = typeof v === "string" ? v : "default";
      if (s && ![...el.options].some((o) => o.value === s)) {
        const opt = document.createElement("option");
        opt.value = s;
        opt.textContent = s;
        el.appendChild(opt);
      }
      el.value = s;
    } else if (v !== undefined && v !== null) {
      el.value = String(v);
    }
  }
  const decoy = $("decoy-gets-extra");
  const dg = $("f-decoy_gets");
  if (decoy && dg instanceof HTMLInputElement) {
    decoy.hidden = !dg.checked;
  }
}

/** @param {StateSnapshot} s */
function renderHome(s) {
  const home = $("view-home");
  const connected = s.connected;
  if (home) {
    home.classList.toggle("is-connected", connected);
  }

  $("status-title").textContent = connected ? "Подключено" : "Не подключено";
  const subEl = $("status-sub");
  if (subEl) {
    subEl.textContent = connected
      ? `${s.displayHost} · системный прокси`
      : "Нажмите «Подключить», чтобы включить прокси";
  }

  const cta = $("btn-cta");
  const canDisconnect = connected;
  const configOk = s.canConnect;
  const ctaEnabled = canDisconnect || configOk;
  if (cta) {
    cta.disabled = !ctaEnabled;
    cta.classList.toggle("muted", !ctaEnabled);
    $("cta-title").textContent = canDisconnect ? "Отключить" : "Подключить";
    $("cta-sub").textContent = canDisconnect
      ? "Защищено · отключить прокси"
      : "Трафик через локальный HTTP + SOCKS и системный прокси";
  }

  $("server-title").textContent = s.displayHost || "—";
  $("server-sub").textContent = s.serverSubtitle || "";

  const warn = $("warn-server-changed");
  const inviteMode =
    String(s.cfg?.from_invite || "").trim() !== "" &&
    String(s.cfg?.invite_passphrase || "").trim() !== "";
  const serverMismatch =
    connected &&
    s.tunnelServer &&
    !inviteMode &&
    String(s.cfg?.server || "").trim() !== String(s.tunnelServer).trim();
  if (warn) {
    warn.hidden = !serverMismatch;
    if (serverMismatch) {
      warn.textContent =
        "Адрес сервера изменился — нажмите «Отключить», затем «Подключить».";
    }
  }

  const ar = $("active-remote");
  if (ar) {
    const show = connected && s.tunnelServer;
    ar.hidden = !show;
    if (show) {
      ar.textContent = `Активный сервер: ${s.tunnelServer}`;
    }
  }

  const err = $("error-banner");
  if (err) {
    const msg = s.error;
    err.hidden = !msg;
    err.textContent = msg || "";
  }
}

let latest = /** @type {StateSnapshot | null} */ (null);

async function refresh() {
  try {
    const s = await invoke("get_state");
    latest = /** @type {StateSnapshot} */ (s);
    if (latest.cfg) {
      cfgToForm(/** @type {Record<string, unknown>} */ (latest.cfg));
    }
    renderHome(latest);
    return latest;
  } catch (e) {
    console.error(e);
    const err = $("error-banner");
    if (err) {
      err.hidden = false;
      err.textContent = String(e);
    }
    return null;
  }
}

function showSettings() {
  $("view-home").hidden = true;
  $("view-settings").hidden = false;
  if (latest?.cfg) {
    cfgToForm(/** @type {Record<string, unknown>} */ (latest.cfg));
  }
}

function showHome() {
  $("view-settings").hidden = true;
  $("view-home").hidden = false;
}

async function saveFromForm() {
  if (!latest) await refresh();
  const base = latest?.cfg ? { ...latest.cfg } : {};
  const merged = formToCfg(/** @type {Record<string, unknown>} */ (base));
  try {
    const s = await invoke("save_config_cmd", { cfg: merged });
    latest = /** @type {StateSnapshot} */ (s);
    renderHome(latest);
  } catch (e) {
    console.error(e);
  }
}

document.getElementById("btn-settings")?.addEventListener("click", () => {
  showSettings();
});

document.getElementById("btn-server-card")?.addEventListener("click", () => {
  showSettings();
});

document.getElementById("btn-back")?.addEventListener("click", async () => {
  await saveFromForm();
  showHome();
});

document.getElementById("f-decoy_gets")?.addEventListener("change", (ev) => {
  const t = ev.target;
  const box = $("decoy-gets-extra");
  if (box && t instanceof HTMLInputElement) {
    box.hidden = !t.checked;
  }
});

document.getElementById("btn-apply-invite")?.addEventListener("click", async () => {
  await saveFromForm();
  try {
    const s = await invoke("apply_invite_cmd");
    latest = /** @type {StateSnapshot} */ (s);
    cfgToForm(/** @type {Record<string, unknown>} */ (latest.cfg));
    renderHome(latest);
  } catch (e) {
    await refresh();
    console.error(e);
  }
});

document.getElementById("btn-cta")?.addEventListener("click", async () => {
  const st = await refresh();
  if (!st) return;
  try {
    if (st.connected) {
      const s = await invoke("disconnect_cmd");
      latest = /** @type {StateSnapshot} */ (s);
    } else {
      const s = await invoke("connect_cmd");
      latest = /** @type {StateSnapshot} */ (s);
    }
    renderHome(latest);
  } catch (e) {
    await refresh();
    console.error(e);
  }
});

document.getElementById("error-banner")?.addEventListener("click", async () => {
  try {
    const s = await invoke("clear_error_cmd");
    latest = /** @type {StateSnapshot} */ (s);
    renderHome(latest);
  } catch (_) {
    /* ignore */
  }
});

listen("vpn-state", (ev) => {
  latest = /** @type {StateSnapshot} */ (ev.payload);
  renderHome(latest);
  if (!$("view-settings").hidden && latest.cfg) {
    cfgToForm(/** @type {Record<string, unknown>} */ (latest.cfg));
  }
}).catch(() => {
  /* dev without tauri */
});

refresh();
