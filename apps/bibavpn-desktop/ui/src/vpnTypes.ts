/** JSDoc typedefs for Tauri payloads (snake_case matches Rust serde). */

/** Full profile for Settings / Profiles editing (`get_edit_config`, `save_config_cmd`). */
export type TunnelProfile = {
  id: string;
  name: string;
  server: string;
  token: string;
  psk: string;
  sni: string;
  insecure: boolean;
  max_pad: number;
  decoy_max: number;
  max_ws_binary: number;
  tls_profile: string;
  from_invite: string;
  invite_passphrase: string;
  junk_frames: number;
  early_ws_frames: number;
  ws_ping_secs: number;
  ws_headers: string;
  use_tcp_mux: boolean;
  ws_path: string;
  pad_mode: string;
  ws_ping_jitter_percent: number;
  ws_binary_send_jitter_ms: number;
  udp_max_pad: string;
  udp_max_ws_binary: string;
  udp_mux_reply_timeout_secs: string;
  dummy_interval_secs: number;
  decoy_gets: boolean;
  decoy_gets_interval_secs: number;
  decoy_gets_paths: string;
  pin_cert_pem: string;
  split_tunnel_enabled: boolean;
  split_tunnel_preset_ids: string[];
  proto: number;
  proto_domain: string;
  stealth_profile: string;
  decoy_mode: string;
  desync_mode: string;
  tcp_fooling: string;
  tls_fragment: boolean;
  ws_parallel: number;
  idle_decoy_secs: number;
  tls_stack: string;
  fingerprint: string;
  reality_target: string;
  reality_public_key: string;
  reality_short_id: string;
  ws_host: string;
  ws_origin: string;
  ws_user_agent: string;
  ws_accept_language: string;
  ws_jitter_min_ms: number;
  ws_jitter_max_ms: number;
  control_plane_instance_id: number;
  control_plane_config_version: string;
  control_plane_base_url: string;
  android_socks_bind: string;
  /** Итог для JNI: пресеты + ручные пакеты */
  android_split_tunnel_packages: string[];
  /** Пакеты не из пресетов (выбор с телефона или ввод вручную) */
  android_manual_split_packages: string[];
  android_vpn_routing_mode: string;
  android_screen_off_battery_saver: boolean;
};

/** Poll snapshot profile — secrets omitted, presence flags only. */
export type PublicTunnelProfile = Omit<
  TunnelProfile,
  "token" | "psk" | "from_invite" | "invite_passphrase" | "pin_cert_pem"
> & {
  has_token: boolean;
  has_psk: boolean;
  has_from_invite: boolean;
  has_invite_passphrase: boolean;
  has_invite: boolean;
  has_pin_cert: boolean;
};

export type SavedConfig = {
  version: number;
  ui_locale: string;
  local_http_port: number;
  local_socks_port: number;
  active_profile_id: string;
  profiles: TunnelProfile[];
};

export type PublicSavedConfig = {
  version: number;
  ui_locale: string;
  local_http_port: number;
  local_socks_port: number;
  active_profile_id: string;
  profiles: PublicTunnelProfile[];
};

export type ClientCapabilities = {
  boring_tls_available: boolean;
};

export type StateSnapshot = {
  cfg: PublicSavedConfig;
  connected: boolean;
  displayHost: string;
  serverSubtitle: string;
  tunnelServer: string | null;
  error: string | null;
  canConnect: boolean;
  capabilities: ClientCapabilities;
  /** Android: секунды с момента поднятия tun2socks (устойчиво к перезапуску UI). На desktop не приходит. */
  vpnSessionUptimeSecs?: number | null;
};
