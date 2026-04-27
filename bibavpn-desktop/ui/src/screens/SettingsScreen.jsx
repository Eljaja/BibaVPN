import React, { useMemo } from "react";
import { useT } from "../ThemeContext.jsx";
import {
  Btn,
  ExpandSection,
  Field,
  CheckRow,
} from "../ui/primitives.jsx";
import { t, tlsProfileSpecs } from "../i18n.js";
import { setLanguageFromCfg } from "../i18n.js";
import { getActiveProfile, patchActiveProfile } from "../profileUtils.js";
import { SPLIT_TUNNEL_GROUPS, allSplitPresetIds } from "../splitPresets.js";
import { SEMANTIC } from "../theme.js";

/** @param {{ cfg: import('../vpnTypes').SavedConfig, setCfg: (fn: (c: import('../vpnTypes').SavedConfig) => import('../vpnTypes').SavedConfig) => void, boringAvailable: boolean, onBack: () => void, onSave: () => Promise<void>, onApplyInvite: () => Promise<void>, lastError: string | null, onClearError: () => Promise<void> }} props */
export function SettingsScreen({
  cfg,
  setCfg,
  boringAvailable,
  onBack,
  onSave,
  onApplyInvite,
  lastError,
  onClearError,
}) {
  const { theme, accent } = useT();
  const p = getActiveProfile(cfg);
  const isAndroid = useMemo(
    () => /Android/i.test(typeof navigator !== "undefined" ? navigator.userAgent : ""),
    [],
  );

  if (!p) return null;

  function patchP(patch) {
    setCfg((c) => patchActiveProfile(c, patch));
  }

  function setSplitEnabled(on) {
    setCfg((c) => {
      const cur = getActiveProfile(c);
      if (!cur) return c;
      let ids = [...cur.split_tunnel_preset_ids];
      if (on && ids.length === 0) ids = allSplitPresetIds();
      return patchActiveProfile(c, {
        split_tunnel_enabled: on,
        split_tunnel_preset_ids: ids,
      });
    });
  }

  function togglePreset(id, on) {
    setCfg((c) => {
      const cur = getActiveProfile(c);
      if (!cur) return c;
      const set = new Set(cur.split_tunnel_preset_ids);
      if (on) set.add(id);
      else set.delete(id);
      return patchActiveProfile(c, {
        split_tunnel_preset_ids: [...set],
      });
    });
  }

  async function handleApplyInvite() {
    await onSave();
    await onApplyInvite();
  }

  const boringWarn = p.tls_stack === "boring" && !boringAvailable;

  return (
    <div
      style={{
        minHeight: "100%",
        background: theme.bg,
        display: "flex",
        flexDirection: "column",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "14px 16px",
          borderBottom: `1px solid ${theme.line}`,
        }}
      >
        <Btn
          kind="ghost"
          onClick={async () => {
            await onSave();
            onBack();
          }}
        >
          ←
        </Btn>
        <span
          style={{
            fontFamily: "IBM Plex Mono",
            fontSize: 13,
            letterSpacing: 1.5,
            color: theme.text,
            textTransform: "uppercase",
          }}
        >
          {t("settings_heading")}
        </span>
      </header>

      <div
        style={{
          flex: 1,
          overflow: "auto",
          padding: "14px 16px 100px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        {lastError && (
          <div
            style={{
              padding: "10px 12px",
              borderRadius: 4,
              border: `1px solid ${SEMANTIC.err}`,
              background: "rgba(255,90,90,0.08)",
              color: SEMANTIC.err,
              fontFamily: "IBM Plex Mono",
              fontSize: 11,
              display: "flex",
              flexDirection: "column",
              gap: 8,
            }}
          >
            <span>{lastError}</span>
            <button
              type="button"
              onClick={() => onClearError()}
              style={{
                alignSelf: "flex-start",
                background: "transparent",
                border: `1px solid ${SEMANTIC.err}`,
                color: SEMANTIC.err,
                fontFamily: "IBM Plex Mono",
                fontSize: 10,
                padding: "6px 10px",
                cursor: "pointer",
                textTransform: "uppercase",
              }}
            >
              {t("btn_clear")}
            </button>
          </div>
        )}
        <ExpandSection label={t("settings_group_profile")} summary={p.name} defaultOpen>
          <Field
            label={t("profile_rename")}
            value={p.name}
            onChange={(v) => patchP({ name: v })}
          />
          <Field
            label={t("label_invite_uri")}
            value={p.from_invite}
            onChange={(v) => patchP({ from_invite: v })}
          />
          <Field
            label={t("label_passphrase")}
            value={p.invite_passphrase}
            type="password"
            onChange={(v) => patchP({ invite_passphrase: v })}
          />
          <Btn kind="primary" block onClick={handleApplyInvite}>
            {t("btn_apply_invite")}
          </Btn>
        </ExpandSection>

        <ExpandSection label={t("settings_group_endpoint")} summary={p.server || t("display_invite")}>
          <Field label={t("label_server")} value={p.server} onChange={(v) => patchP({ server: v })} />
          <Field label={t("label_token")} value={p.token} onChange={(v) => patchP({ token: v })} />
          <Field label={t("label_sni")} value={p.sni} onChange={(v) => patchP({ sni: v })} />
          <Field
            label={t("label_psk")}
            value={p.psk}
            type="password"
            onChange={(v) => patchP({ psk: v })}
          />
          <CheckRow
            label={t("insecure_tls")}
            checked={p.insecure}
            onChange={(v) => patchP({ insecure: v })}
          />
        </ExpandSection>

        <ExpandSection label={t("settings_group_transport")} summary={`mux · ${p.ws_path || "/"}`}>
          <CheckRow
            label="use_tcp_mux"
            checked={p.use_tcp_mux}
            onChange={(v) => patchP({ use_tcp_mux: v })}
          />
          <Field label="ws_path" value={p.ws_path} placeholder={t("ws_path_ph")} onChange={(v) => patchP({ ws_path: v })} />
          <Field label="pad_mode" value={p.pad_mode} placeholder={t("pad_mode_ph")} onChange={(v) => patchP({ pad_mode: v })} />
          <Field
            label="ws_headers"
            value={p.ws_headers}
            rows={3}
            placeholder={t("ws_headers_ph")}
            onChange={(v) => patchP({ ws_headers: v })}
          />
          <Field
            label="ws_ping_secs"
            type="number"
            value={String(p.ws_ping_secs)}
            onChange={(v) => patchP({ ws_ping_secs: Number(v) || 0 })}
          />
        </ExpandSection>

        <ExpandSection label={t("settings_group_shaping")} summary={`pad ${p.max_pad} · decoy ${p.decoy_max}`}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <Field
              label="max_pad"
              type="number"
              value={String(p.max_pad)}
              onChange={(v) => patchP({ max_pad: Math.min(255, Math.max(0, Number(v) || 0)) })}
            />
            <Field
              label="decoy_max"
              type="number"
              value={String(p.decoy_max)}
              onChange={(v) => patchP({ decoy_max: Math.min(255, Math.max(0, Number(v) || 0)) })}
            />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <Field
              label="junk_frames"
              type="number"
              value={String(p.junk_frames)}
              onChange={(v) => patchP({ junk_frames: Number(v) || 0 })}
            />
            <Field
              label="early_ws_frames"
              type="number"
              value={String(p.early_ws_frames)}
              onChange={(v) => patchP({ early_ws_frames: Math.min(255, Number(v) || 0) })}
            />
          </div>
          <Field
            label="max_ws_binary"
            type="number"
            value={String(p.max_ws_binary)}
            onChange={(v) => patchP({ max_ws_binary: Math.max(1024, Number(v) || 0) })}
          />
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
            <Field
              label="ping jitter %"
              type="number"
              value={String(p.ws_ping_jitter_percent)}
              onChange={(v) =>
                patchP({ ws_ping_jitter_percent: Math.min(50, Math.max(0, Number(v) || 0)) })
              }
            />
            <Field
              label="bin jitter ms"
              type="number"
              value={String(p.ws_binary_send_jitter_ms)}
              onChange={(v) =>
                patchP({ ws_binary_send_jitter_ms: Math.min(255, Math.max(0, Number(v) || 0)) })
              }
            />
            <Field
              label="dummy_interval_secs"
              type="number"
              value={String(p.dummy_interval_secs)}
              onChange={(v) => patchP({ dummy_interval_secs: Number(v) || 0 })}
            />
          </div>
          <CheckRow
            label="decoy_gets"
            checked={p.decoy_gets}
            onChange={(v) => patchP({ decoy_gets: v })}
          />
          {p.decoy_gets && (
            <>
              <Field
                label={t("decoy_interval_s")}
                type="number"
                value={String(p.decoy_gets_interval_secs)}
                onChange={(v) =>
                  patchP({ decoy_gets_interval_secs: Math.max(1, Number(v) || 1) })
                }
              />
              <Field
                label="decoy_gets_paths"
                value={p.decoy_gets_paths}
                onChange={(v) => patchP({ decoy_gets_paths: v })}
              />
            </>
          )}
        </ExpandSection>

        <ExpandSection label={t("settings_group_udp")} summary="assoc / timeout">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8 }}>
            <Field label="udp_max_pad" value={p.udp_max_pad} onChange={(v) => patchP({ udp_max_pad: v })} />
            <Field
              label="udp_max_ws_binary"
              value={p.udp_max_ws_binary}
              onChange={(v) => patchP({ udp_max_ws_binary: v })}
            />
            <Field
              label="udp_mux_reply_timeout_secs"
              value={p.udp_mux_reply_timeout_secs}
              onChange={(v) => patchP({ udp_mux_reply_timeout_secs: v })}
            />
          </div>
        </ExpandSection>

        <ExpandSection label={t("settings_group_tls")} summary={p.tls_profile}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontFamily: "IBM Plex Mono", fontSize: 10, color: theme.textDim }}>
              tls_profile
            </span>
            <select
              value={p.tls_profile}
              onChange={(e) => patchP({ tls_profile: e.target.value })}
              style={{
                padding: "10px 12px",
                borderRadius: 4,
                border: `1px solid ${theme.line}`,
                background: theme.bgInk,
                color: theme.text,
              }}
            >
              {tlsProfileSpecs().map(([val, key]) => (
                <option key={val} value={val}>
                  {key.startsWith("tls_") ? t(key) : key}
                </option>
              ))}
            </select>
          </label>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontFamily: "IBM Plex Mono", fontSize: 10, color: theme.textDim }}>
              {t("tls_stack_label")}
            </span>
            <select
              value={p.tls_stack || "rustls"}
              onChange={(e) => patchP({ tls_stack: e.target.value })}
              style={{
                padding: "10px 12px",
                borderRadius: 4,
                border: `1px solid ${theme.line}`,
                background: theme.bgInk,
                color: theme.text,
              }}
            >
              <option value="rustls">rustls</option>
              <option value="boring" disabled={!boringAvailable}>
                boring {!boringAvailable ? "(off)" : ""}
              </option>
            </select>
          </label>
          {boringWarn && (
            <p style={{ color: SEMANTIC.warn, fontFamily: "IBM Plex Mono", fontSize: 11, margin: 0 }}>
              {t("boring_unavailable")}
            </p>
          )}
          <p style={{ color: theme.textDim, fontSize: 11, margin: 0 }}>{t("pin_rustls_only")}</p>
          <Field
            label="pin_cert_pem"
            value={p.pin_cert_pem}
            rows={4}
            onChange={(v) => patchP({ pin_cert_pem: v })}
            disabled={p.tls_stack === "boring"}
          />
          <Field
            label={t("fingerprint_label")}
            value={p.fingerprint}
            onChange={(v) => patchP({ fingerprint: v })}
          />
        </ExpandSection>

        <ExpandSection label={t("settings_group_stealth")} summary={p.stealth_profile || "—"}>
          <Field
            label={t("proto_label")}
            type="number"
            value={String(p.proto)}
            onChange={(v) => patchP({ proto: Math.min(255, Math.max(1, Number(v) || 3)) })}
          />
          <Field
            label={t("proto_domain_label")}
            value={p.proto_domain}
            onChange={(v) => patchP({ proto_domain: v })}
          />
          <Field
            label={t("stealth_profile_label")}
            value={p.stealth_profile}
            onChange={(v) => patchP({ stealth_profile: v })}
          />
          <Field
            label={t("decoy_mode_label")}
            value={p.decoy_mode}
            onChange={(v) => patchP({ decoy_mode: v })}
          />
          <Field
            label={t("desync_mode_label")}
            value={p.desync_mode}
            onChange={(v) => patchP({ desync_mode: v })}
          />
          <Field
            label={t("tcp_fooling_label")}
            value={p.tcp_fooling}
            onChange={(v) => patchP({ tcp_fooling: v })}
          />
          <CheckRow
            label={t("tls_fragment_label")}
            checked={p.tls_fragment}
            onChange={(v) => patchP({ tls_fragment: v })}
          />
          <Field
            label={t("ws_parallel_label")}
            type="number"
            value={String(p.ws_parallel)}
            onChange={(v) => patchP({ ws_parallel: Math.min(4, Math.max(1, Number(v) || 1)) })}
          />
          <Field
            label={t("idle_decoy_label")}
            type="number"
            value={String(p.idle_decoy_secs)}
            onChange={(v) => patchP({ idle_decoy_secs: Number(v) || 0 })}
          />
        </ExpandSection>

        <ExpandSection label={t("settings_group_reality")} summary={p.reality_target || "—"}>
          <Field
            label={t("reality_target_label")}
            value={p.reality_target}
            onChange={(v) => patchP({ reality_target: v })}
          />
          <Field
            label={t("reality_pk_label")}
            value={p.reality_public_key}
            onChange={(v) => patchP({ reality_public_key: v })}
          />
          <Field
            label={t("reality_sid_label")}
            value={p.reality_short_id}
            onChange={(v) => patchP({ reality_short_id: v })}
          />
        </ExpandSection>

        <ExpandSection label={t("settings_group_ws_http")} summary={p.ws_host || "auto"}>
          <Field label={t("ws_host_label")} value={p.ws_host} onChange={(v) => patchP({ ws_host: v })} />
          <Field label={t("ws_origin_label")} value={p.ws_origin} onChange={(v) => patchP({ ws_origin: v })} />
          <Field label={t("ws_ua_label")} value={p.ws_user_agent} onChange={(v) => patchP({ ws_user_agent: v })} />
          <Field
            label={t("ws_al_label")}
            value={p.ws_accept_language}
            onChange={(v) => patchP({ ws_accept_language: v })}
          />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <Field
              label={t("ws_jmin_label")}
              type="number"
              value={String(p.ws_jitter_min_ms)}
              onChange={(v) =>
                patchP({ ws_jitter_min_ms: Math.min(255, Math.max(0, Number(v) || 0)) })
              }
            />
            <Field
              label={t("ws_jmax_label")}
              type="number"
              value={String(p.ws_jitter_max_ms)}
              onChange={(v) =>
                patchP({ ws_jitter_max_ms: Math.min(255, Math.max(0, Number(v) || 0)) })
              }
            />
          </div>
        </ExpandSection>

        <ExpandSection label={t("settings_group_split")} summary={p.split_tunnel_enabled ? "on" : "off"}>
          {isAndroid && (
            <p style={{ color: theme.textDim, fontSize: 12 }}>{t("android_split_note")}</p>
          )}
          <CheckRow
            label={t("split_tunnel_enable")}
            checked={p.split_tunnel_enabled}
            onChange={setSplitEnabled}
          />
          <p style={{ color: theme.textDim, fontSize: 11, margin: 0 }}>{t("split_tunnel_reconnect")}</p>
          {isAndroid && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 10 }}>
              <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                <span style={{ fontFamily: "IBM Plex Mono", fontSize: 10, color: theme.textDim }}>
                  {t("android_routing_mode_label")}
                </span>
                <select
                  value={p.android_vpn_routing_mode?.trim() || "system_vpn"}
                  onChange={(e) => patchP({ android_vpn_routing_mode: e.target.value })}
                  style={{
                    padding: "10px 12px",
                    borderRadius: 4,
                    border: `1px solid ${theme.line}`,
                    background: theme.bgInk,
                    color: theme.text,
                  }}
                >
                  <option value="system_vpn">system_vpn</option>
                </select>
              </label>
              <CheckRow
                label={t("android_battery_saver_label")}
                checked={Boolean(p.android_screen_off_battery_saver)}
                onChange={(v) => patchP({ android_screen_off_battery_saver: v })}
              />
              {p.split_tunnel_enabled && (
                <Field
                  label={t("android_packages_label")}
                  value={(p.android_split_tunnel_packages || []).join("\n")}
                  onChange={(v) =>
                    patchP({
                      android_split_tunnel_packages: v
                        .split(/\r?\n/)
                        .map((x) => x.trim())
                        .filter(Boolean),
                    })
                  }
                  rows={8}
                  hint={t("android_packages_hint")}
                />
              )}
            </div>
          )}
          {p.split_tunnel_enabled && !isAndroid && (
            <div style={{ display: "flex", flexDirection: "column", gap: 14, marginTop: 8 }}>
              {SPLIT_TUNNEL_GROUPS.map((g) => (
                <div key={g.groupKey}>
                  <div
                    style={{
                      fontFamily: "IBM Plex Mono",
                      fontSize: 10,
                      color: theme.textDim,
                      marginBottom: 8,
                      textTransform: "uppercase",
                    }}
                  >
                    {t(g.groupKey)}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {g.ids.map((id) => (
                      <CheckRow
                        key={id}
                        label={t(`split_preset_${id}`)}
                        checked={p.split_tunnel_preset_ids.includes(id)}
                        onChange={(on) => togglePreset(id, on)}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </ExpandSection>

        <ExpandSection label={t("settings_group_platform")} summary={cfg.ui_locale}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <span style={{ fontFamily: "IBM Plex Mono", fontSize: 10, color: theme.textDim }}>
              {t("lang_label")}
            </span>
            <select
              value={cfg.ui_locale}
              onChange={(e) => {
                const ui_locale = e.target.value;
                setCfg((c) => ({ ...c, ui_locale }));
                setLanguageFromCfg({ ui_locale });
              }}
              style={{
                padding: "10px 12px",
                borderRadius: 4,
                border: `1px solid ${theme.line}`,
                background: theme.bgInk,
                color: theme.text,
              }}
            >
              <option value="auto">{t("lang_auto")}</option>
              <option value="ru">{t("lang_ru")}</option>
              <option value="en">{t("lang_en")}</option>
            </select>
          </label>
        </ExpandSection>
      </div>

      <div
        style={{
          position: "sticky",
          bottom: 0,
          left: 0,
          right: 0,
          padding: "12px 16px 20px",
          borderTop: `1px solid ${theme.line}`,
          background: theme.bgInk,
        }}
      >
        <Btn kind="solid" block onClick={onSave}>
          {t("btn_save")}
        </Btn>
      </div>
    </div>
  );
}
