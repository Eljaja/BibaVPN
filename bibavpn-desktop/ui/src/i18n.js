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
    status_handshaking: "РУКОПОЖАТИЕ",
    status_via_proxy: "системный прокси",
    status_sub_disconnected: "Нажмите «Подключить», чтобы установить соединение",
    cta_connect: "Подключить",
    cta_disconnect: "Отключить",
    cta_sub_connected: "Защищено · нажмите, чтобы отключить",
    cta_sub_disconnected: "Туннель не активен",
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
    split_tunnel_title: "Раздельный туннель",
    split_tunnel_presets_summary: "Сервисы и сайты",
    split_tunnel_enable: "Включить обход для отмеченных ниже",
    split_tunnel_reconnect:
      "Если VPN уже включён — отключите и снова подключитесь, чтобы применить список.",
    split_group_government: "Госуслуги",
    split_group_social: "Мессенджеры и соцсети",
    split_group_banks: "Банки",
    split_group_shops: "Магазины и сервисы",
    split_group_delivery: "Доставка и такси",
    split_preset_gosuslugi: "Госуслуги",
    split_preset_max: "MAX",
    split_preset_vk: "ВКонтакте",
    split_preset_tinkoff: "Тинькофф",
    split_preset_sber: "Сбер",
    split_preset_yandex_bank: "Яндекс Банк",
    split_preset_banki: "Банки.ру",
    split_preset_bog: "Банк Грузии (BOG)",
    split_preset_vtb: "ВТБ",
    split_preset_alfa: "Альфа-Банк",
    split_preset_ozon: "Ozon",
    split_preset_yandex_market: "Яндекс Маркет",
    split_preset_steam: "Steam (магазин и клиент)",
    split_preset_yandex_taxi: "Яндекс Такси / Яндекс Go",
    split_preset_yandex_vezet: "Яндекс Везёт",
    split_preset_deliveryclub: "Delivery Club",
    split_preset_yandex_eda: "Яндекс Еда",
    split_preset_yandex_lavka: "Яндекс Лавка",
    split_preset_samokat: "Самокат",
    nav_connect: "Канал",
    nav_profiles: "Профили",
    nav_settings: "Настройки",
    profile_active: "Активен",
    profile_new: "Новый профиль",
    profile_delete: "Удалить",
    profile_rename: "Имя",
    btn_save: "Сохранить",
    settings_group_profile: "Профиль / инвайт",
    settings_group_endpoint: "Узел и доступ",
    settings_group_transport: "Транспорт",
    settings_group_shaping: "Формирование трафика",
    settings_group_udp: "UDP mux",
    settings_group_tls: "TLS / доверие",
    settings_group_stealth: "Stealth / desync",
    settings_group_reality: "REALITY",
    settings_group_ws_http: "WS метаданные",
    settings_group_split: "Раздельный туннель",
    settings_group_platform: "Платформа",
    settings_group_ports: "Локальные порты (десктоп)",
    android_split_note:
      "Выбор приложений для обхода настраивается в Android через системный диалог (Tauri).",
    boring_unavailable: "Сборка без BoringTLS — значение будет проигнорировано.",
    pin_rustls_only: "pin_cert_pem только для rustls",
    tls_stack_label: "Стек TLS",
    proto_label: "Протокол (proto)",
    proto_domain_label: "proto_domain",
    stealth_profile_label: "stealth_profile",
    decoy_mode_label: "decoy_mode",
    desync_mode_label: "desync_mode",
    tcp_fooling_label: "tcp_fooling",
    tls_fragment_label: "tls_fragment (эксп.)",
    ws_parallel_label: "ws_parallel",
    idle_decoy_label: "idle_decoy_secs",
    fingerprint_label: "fingerprint",
    reality_target_label: "reality_target",
    reality_pk_label: "reality_public_key",
    reality_sid_label: "reality_short_id",
    ws_host_label: "ws_host",
    ws_origin_label: "ws_origin",
    ws_ua_label: "ws_user_agent",
    ws_al_label: "ws_accept_language",
    ws_jmin_label: "ws_jitter_min_ms",
    ws_jmax_label: "ws_jitter_max_ms",
    android_routing_mode_label: "Режим маршрутизации VPN",
    android_battery_saver_label: "Экономия при выключенном экране",
    android_packages_label: "Пакеты в обход туннеля",
    android_packages_hint:
      "По одному package name на строку (как в системном Android). Пустой список при включённом обходе означает, что пакеты нужно добавить перед подключением.",
  },
  en: {
    app_title: "BibaVPN",
    settings_aria: "Settings",
    back_aria: "Back",
    wordmark_alt: "BibaVPN",
    status_disconnected: "Disconnected",
    status_connected: "Connected",
    status_handshaking: "HANDSHAKING",
    status_via_proxy: "system proxy",
    status_sub_disconnected: "Tap Connect to establish the tunnel",
    cta_connect: "Connect",
    cta_disconnect: "Disconnect",
    cta_sub_connected: "Protected · tap to disconnect",
    cta_sub_disconnected: "Tunnel inactive",
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
    split_tunnel_title: "Split tunneling",
    split_tunnel_presets_summary: "Services & sites",
    split_tunnel_enable: "Enable bypass for the selections below",
    split_tunnel_reconnect:
      "If VPN is already on — disconnect and connect again to apply the list.",
    split_group_government: "Government",
    split_group_social: "Messengers & social",
    split_group_banks: "Banks",
    split_group_shops: "Shops & services",
    split_group_delivery: "Delivery & taxi",
    split_preset_gosuslugi: "Gosuslugi",
    split_preset_max: "MAX",
    split_preset_vk: "VK",
    split_preset_tinkoff: "Tinkoff",
    split_preset_sber: "Sber",
    split_preset_yandex_bank: "Yandex Bank",
    split_preset_banki: "Banki.ru",
    split_preset_bog: "Bank of Georgia (BOG)",
    split_preset_vtb: "VTB",
    split_preset_alfa: "Alfa-Bank",
    split_preset_ozon: "Ozon",
    split_preset_yandex_market: "Yandex Market",
    split_preset_steam: "Steam (store & client)",
    split_preset_yandex_taxi: "Yandex Taxi / Yandex Go",
    split_preset_yandex_vezet: "Yandex Vezet",
    split_preset_deliveryclub: "Delivery Club",
    split_preset_yandex_eda: "Yandex Eda",
    split_preset_yandex_lavka: "Yandex Lavka",
    split_preset_samokat: "Samokat",
    nav_connect: "Connect",
    nav_profiles: "Profiles",
    nav_settings: "Settings",
    profile_active: "Active",
    profile_new: "New profile",
    profile_delete: "Delete",
    profile_rename: "Name",
    btn_save: "Save",
    settings_group_profile: "Profile / invite",
    settings_group_endpoint: "Endpoint & auth",
    settings_group_transport: "Transport",
    settings_group_shaping: "Traffic shaping",
    settings_group_udp: "UDP mux",
    settings_group_tls: "TLS / trust",
    settings_group_stealth: "Stealth / desync",
    settings_group_reality: "REALITY",
    settings_group_ws_http: "WS metadata",
    settings_group_split: "Split tunneling",
    settings_group_platform: "Platform",
    settings_group_ports: "Local ports (desktop)",
    android_split_note:
      "Per-app bypass on Android is configured via the system UI (Tauri bridge).",
    boring_unavailable: "This build has no BoringTLS — value may be ignored.",
    pin_rustls_only: "pin_cert_pem is rustls-only",
    tls_stack_label: "TLS stack",
    proto_label: "Protocol (proto)",
    proto_domain_label: "proto_domain",
    stealth_profile_label: "stealth_profile",
    decoy_mode_label: "decoy_mode",
    desync_mode_label: "desync_mode",
    tcp_fooling_label: "tcp_fooling",
    tls_fragment_label: "tls_fragment (experimental)",
    ws_parallel_label: "ws_parallel",
    idle_decoy_label: "idle_decoy_secs",
    fingerprint_label: "fingerprint",
    reality_target_label: "reality_target",
    reality_pk_label: "reality_public_key",
    reality_sid_label: "reality_short_id",
    ws_host_label: "ws_host",
    ws_origin_label: "ws_origin",
    ws_ua_label: "ws_user_agent",
    ws_al_label: "ws_accept_language",
    ws_jmin_label: "ws_jitter_min_ms",
    ws_jmax_label: "ws_jitter_max_ms",
    android_routing_mode_label: "VPN routing mode",
    android_battery_saver_label: "Screen-off battery saver",
    android_packages_label: "Per-app bypass (package names)",
    android_packages_hint:
      "One Android package name per line. If bypass is on and the list is empty, add packages before connecting.",
  },
};

/** @returns {readonly [string, string][]} value, i18n key or literal label */
export function tlsProfileSpecs() {
  return [
    ["default", "tls_default"],
    ["chrome70", "Chrome 70"],
    ["firefox65", "Firefox 65"],
    ["firefox63", "Firefox 63"],
    ["randomized", "Randomized"],
    ["randomized-alpn", "Randomized + ALPN"],
    ["randomized-no-alpn", "tls_randomized_no_alpn"],
  ];
}

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

/** TLS profile <option> labels (value stays technical). Legacy DOM helper. */
export function refreshTlsProfileOptions() {
  const sel = document.getElementById("f-tls_profile");
  if (!(sel instanceof HTMLSelectElement)) return;
  const v = sel.value;
  sel.innerHTML = "";
  for (const [value, key] of tlsProfileSpecs()) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = key.startsWith("tls_") ? t(key) : key;
    sel.appendChild(opt);
  }
  if ([...sel.options].some((o) => o.value === v)) sel.value = v;
}
