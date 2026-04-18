/** @typedef {"ru" | "en"} Lang */

/** @type {Record<Lang, Record<string, string>>} */
const MESSAGES = {
  ru: {
    app_title: "BibaVPN",
    settings_aria: "Настройки",
    back_aria: "Назад",
    wordmark_alt: "BibaVPN",
    status_disconnected: "Не подключено",
    status_connected: "Подключено",
    status_via_proxy: "системный прокси",
    status_sub_disconnected: "Нажмите «Подключить», чтобы включить прокси",
    cta_connect: "Подключить",
    cta_disconnect: "Отключить",
    cta_sub_connected: "Защищено · отключить прокси",
    cta_sub_disconnected: "Трафик через локальный HTTP + SOCKS и системный прокси",
    server_label: "SERVER",
    warn_server_changed:
      "Адрес сервера изменился — нажмите «Отключить», затем «Подключить».",
    active_server: "Активный сервер: {host}",
    settings_heading: "Настройки",
    group_lang: "Язык интерфейса",
    lang_label: "Язык",
    lang_auto: "Как в системе",
    lang_ru: "Русский",
    lang_en: "English",
    group_biba_key: "Ключ Biba (как в Android)",
    label_invite_uri: "biba://…",
    label_passphrase: "Passphrase",
    btn_apply_invite: "Применить к полям",
    group_connection: "Подключение",
    label_server: "Сервер",
    group_credentials: "Учётные данные",
    label_token: "Токен",
    label_sni: "SNI",
    label_psk: "PSK",
    insecure_tls: "Без проверки TLS (insecure)",
    group_local_ports: "Локальные порты",
    label_http: "HTTP",
    label_socks: "SOCKS",
    hint_socks: "SOCKS: 0 = автоматически HTTP+1",
    more_summary: "Дополнительно",
    group_udp_mux: "UDP mux (пусто = по умолчанию)",
    decoy_interval_s: "decoy interval (с)",
    tls_default: "По умолчанию (rustls)",
    tls_randomized_no_alpn: "Randomized без ALPN",
    display_invite: "Ключ Biba",
    display_dash: "—",
    server_undecided: "Не задан сервер",
    ws_path_ph: "/ws",
    pad_mode_ph: "random / http-buckets",
    ws_headers_ph: "Header: value",
  },
  en: {
    app_title: "BibaVPN",
    settings_aria: "Settings",
    back_aria: "Back",
    wordmark_alt: "BibaVPN",
    status_disconnected: "Disconnected",
    status_connected: "Connected",
    status_via_proxy: "system proxy",
    status_sub_disconnected: "Tap Connect to enable the proxy",
    cta_connect: "Connect",
    cta_disconnect: "Disconnect",
    cta_sub_connected: "Protected · turn off proxy",
    cta_sub_disconnected: "Traffic via local HTTP + SOCKS and system proxy",
    server_label: "SERVER",
    warn_server_changed:
      "Server address changed — tap Disconnect, then Connect.",
    active_server: "Active server: {host}",
    settings_heading: "Settings",
    group_lang: "Interface language",
    lang_label: "Language",
    lang_auto: "System default",
    lang_ru: "Русский",
    lang_en: "English",
    group_biba_key: "Biba key (same as Android)",
    label_invite_uri: "biba://…",
    label_passphrase: "Passphrase",
    btn_apply_invite: "Apply to fields",
    group_connection: "Connection",
    label_server: "Server",
    group_credentials: "Credentials",
    label_token: "Token",
    label_sni: "SNI",
    label_psk: "PSK",
    insecure_tls: "Disable TLS verification (insecure)",
    group_local_ports: "Local ports",
    label_http: "HTTP",
    label_socks: "SOCKS",
    hint_socks: "SOCKS: 0 = auto HTTP+1",
    more_summary: "Advanced",
    group_udp_mux: "UDP mux (empty = defaults)",
    decoy_interval_s: "decoy interval (s)",
    tls_default: "Default (rustls)",
    tls_randomized_no_alpn: "Randomized without ALPN",
    display_invite: "Biba key",
    display_dash: "—",
    server_undecided: "No server configured",
    ws_path_ph: "/ws",
    pad_mode_ph: "random / http-buckets",
    ws_headers_ph: "Header: value",
  },
};

/** @type {Lang} */
let currentLang = "ru";

/** @param {unknown} cfg */
export function resolveLang(cfg) {
  const v = String(cfg?.ui_locale ?? "auto").trim().toLowerCase();
  if (v === "en") return "en";
  if (v === "ru") return "ru";
  const nav = (typeof navigator !== "undefined" && navigator.language) || "";
  return nav.toLowerCase().startsWith("en") ? "en" : "ru";
}

/** @param {unknown} cfg */
export function setLanguageFromCfg(cfg) {
  currentLang = resolveLang(cfg);
  if (typeof document !== "undefined") {
    document.documentElement.lang = currentLang === "en" ? "en" : "ru";
    document.title = t("app_title");
  }
}

/** @param {string} key @param {Record<string, string>} [params] */
export function t(key, params) {
  const table = MESSAGES[currentLang] || MESSAGES.ru;
  let s = table[key] ?? MESSAGES.ru[key] ?? key;
  if (params) {
    for (const [k, val] of Object.entries(params)) {
      s = s.replaceAll(`{${k}}`, val);
    }
  }
  return s;
}

export function getLang() {
  return currentLang;
}

export function applyStaticI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const k = el.getAttribute("data-i18n");
    if (k) el.textContent = t(k);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const k = el.getAttribute("data-i18n-placeholder");
    if (!k) return;
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
      el.placeholder = t(k);
    }
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const k = el.getAttribute("data-i18n-aria");
    if (k) el.setAttribute("aria-label", t(k));
  });
  document.querySelectorAll("[data-i18n-alt]").forEach((el) => {
    const k = el.getAttribute("data-i18n-alt");
    if (k && el instanceof HTMLImageElement) el.alt = t(k);
  });
  refreshLangSelectOptions();
}

function refreshLangSelectOptions() {
  const sel = document.getElementById("f-ui_locale");
  if (!(sel instanceof HTMLSelectElement)) return;
  const v = sel.value;
  for (const opt of sel.querySelectorAll("option[data-i18n-opt]")) {
    const k = opt.getAttribute("data-i18n-opt");
    if (k) opt.textContent = t(k);
  }
  if ([...sel.options].some((o) => o.value === v)) sel.value = v;
}

/** TLS profile <option> labels (value stays technical). */
export function refreshTlsProfileOptions() {
  const sel = document.getElementById("f-tls_profile");
  if (!(sel instanceof HTMLSelectElement)) return;
  const v = sel.value;
  const specs = [
    ["default", "tls_default"],
    ["chrome70", "Chrome 70"],
    ["firefox65", "Firefox 65"],
    ["firefox63", "Firefox 63"],
    ["randomized", "Randomized"],
    ["randomized-alpn", "Randomized + ALPN"],
    ["randomized-no-alpn", "tls_randomized_no_alpn"],
  ];
  sel.innerHTML = "";
  for (const [value, key] of specs) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = key.startsWith("tls_") ? t(key) : key;
    sel.appendChild(opt);
  }
  if ([...sel.options].some((o) => o.value === v)) sel.value = v;
}
