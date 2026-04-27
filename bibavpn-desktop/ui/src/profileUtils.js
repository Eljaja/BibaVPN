export function newProfileId() {
  return `p-${Date.now()}`;
}

/** @returns {TunnelProfile} */
export function emptyTunnelProfile(id, name) {
  return {
    id,
    name,
    server: "",
    token: "",
    psk: "",
    sni: "",
    insecure: false,
    max_pad: 64,
    decoy_max: 32,
    max_ws_binary: 262144,
    tls_profile: "default",
    from_invite: "",
    invite_passphrase: "",
    junk_frames: 0,
    early_ws_frames: 0,
    ws_ping_secs: 25,
    ws_headers: "",
    use_tcp_mux: true,
    ws_path: "",
    pad_mode: "",
    ws_ping_jitter_percent: 0,
    ws_binary_send_jitter_ms: 0,
    udp_max_pad: "",
    udp_max_ws_binary: "",
    udp_mux_reply_timeout_secs: "",
    dummy_interval_secs: 0,
    decoy_gets: false,
    decoy_gets_interval_secs: 30,
    decoy_gets_paths: "",
    pin_cert_pem: "",
    split_tunnel_enabled: false,
    split_tunnel_preset_ids: [],
    proto: 3,
    proto_domain: "",
    stealth_profile: "",
    decoy_mode: "",
    desync_mode: "",
    tcp_fooling: "",
    tls_fragment: false,
    ws_parallel: 1,
    idle_decoy_secs: 0,
    tls_stack: "rustls",
    fingerprint: "",
    reality_target: "",
    reality_public_key: "",
    reality_short_id: "",
    ws_host: "",
    ws_origin: "",
    ws_user_agent: "",
    ws_accept_language: "",
    ws_jitter_min_ms: 0,
    ws_jitter_max_ms: 0,
    android_socks_bind: "",
    android_split_tunnel_packages: [],
    android_vpn_routing_mode: "system_vpn",
    android_screen_off_battery_saver: false,
  };
}

/** @param {SavedConfig} cfg */
export function getActiveProfile(cfg) {
  if (!cfg?.profiles?.length) return null;
  const id = cfg.active_profile_id;
  return cfg.profiles.find((p) => p.id === id) ?? cfg.profiles[0];
}

/** @param {SavedConfig} cfg @param {Partial<TunnelProfile>} patch @returns {SavedConfig} */
export function patchActiveProfile(cfg, patch) {
  const activeId = cfg.active_profile_id;
  return {
    ...cfg,
    profiles: cfg.profiles.map((p) =>
      p.id === activeId ? { ...p, ...patch } : p,
    ),
  };
}

/** @param {SavedConfig} cfg @param {string} profileId @returns {SavedConfig} */
export function setActiveProfileId(cfg, profileId) {
  return { ...cfg, active_profile_id: profileId };
}

/** @param {SavedConfig} cfg @returns {SavedConfig} */
export function addProfile(cfg) {
  const id = newProfileId();
  const n = cfg.profiles.length + 1;
  const profile = emptyTunnelProfile(id, `Profile ${n}`);
  return {
    ...cfg,
    active_profile_id: id,
    profiles: [...cfg.profiles, profile],
  };
}

/** @param {SavedConfig} cfg @param {string} profileId @returns {SavedConfig} */
export function removeProfile(cfg, profileId) {
  const rest = cfg.profiles.filter((p) => p.id !== profileId);
  if (!rest.length) {
    const id = newProfileId();
    return {
      ...cfg,
      active_profile_id: id,
      profiles: [emptyTunnelProfile(id, "Default")],
    };
  }
  let active = cfg.active_profile_id;
  if (active === profileId) active = rest[0].id;
  return { ...cfg, profiles: rest, active_profile_id: active };
}
