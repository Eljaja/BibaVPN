import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useT } from "../ThemeContext.jsx";
import { SEMANTIC, MONO, SANS } from "../theme.js";
import { StatusDot } from "../ui/primitives.jsx";
import { t } from "../i18n.js";
import { getActiveProfile } from "../profileUtils.js";
import { startVisiblePolling } from "../visiblePolling.js";

/** Длительность сессии с момента перехода в connected (локальные часы). */
function formatSessionUptime(elapsedMs) {
  if (elapsedMs <= 0) return "0:00";
  const totalSec = Math.floor(elapsedMs / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

/**
 * ПиНГ и аптайм живут в отдельном компоненте: их секундные тики и опрос статуса
 * не должны перерисовывать весь экран подключения (на Android WebView это
 * заметно как «подвисание» интерфейса).
 */
function ConnectStats({ snap }) {
  const { theme } = useT();
  const sessionStartedAt = snap?.sessionStartedAt ?? null;
  /** Ререндер только этого компонента раз в секунду для локального аптайма. */
  const [, setTick] = useState(0);
  const [rttMs, setRttMs] = useState(null);

  const connected = Boolean(snap?.connected);

  useEffect(() => {
    if (!connected) setRttMs(null);
  }, [connected]);

  useEffect(() => {
    if (!connected || sessionStartedAt == null) return;
    return startVisiblePolling({ task: () => setTick((x) => x + 1), intervalMs: 1000 });
  }, [connected, sessionStartedAt]);

  useEffect(() => {
    if (!connected) return;
    let cancelled = false;
    async function probe() {
      try {
        const v = await invoke("measure_server_rtt_cmd");
        if (!cancelled) setRttMs(typeof v === "number" ? v : null);
      } catch {
        if (!cancelled) setRttMs(null);
      }
    }
    const stop = startVisiblePolling({ task: probe, intervalMs: 30000 });
    return () => {
      cancelled = true;
      stop();
    };
  }, [connected]);

  const uptimeStr = connected && sessionStartedAt != null
    ? formatSessionUptime(Date.now() - sessionStartedAt)
    : "—";

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(3, 1fr)",
        borderTop: `1px solid ${theme.line}`,
        borderBottom: `1px solid ${theme.line}`,
      }}
    >
      {[
        {
          l: t("connect_stat_latency"),
          v: connected && typeof rttMs === "number" ? String(rttMs) : "—",
          u: connected && typeof rttMs === "number" ? "ms" : "",
        },
        {
          l: t("connect_stat_uptime"),
          v: uptimeStr,
          u: "",
        },
        {
          l: t("connect_stat_down"),
          v: "—",
          u: "",
        },
      ].map((s, i) => (
        <div
          key={s.l}
          style={{
            padding: "14px 6px",
            textAlign: "center",
            borderLeft: i > 0 ? `1px solid ${theme.line}` : "none",
          }}
        >
          <div
            style={{
              fontFamily: SANS,
              fontSize: 9,
              color: theme.textDim,
              letterSpacing: 1.3,
              textTransform: "uppercase",
              marginBottom: 6,
            }}
          >
            {s.l}
          </div>
          <div style={{ fontFamily: SANS, fontSize: 18, color: theme.text, fontWeight: 500 }}>
            {s.v}
            {s.u && (
              <span style={{ fontSize: 10, color: theme.textDim, marginLeft: 3 }}>{s.u}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/** @param {{ snap: import('../vpnTypes').StateSnapshot, connectPending: boolean, busy: boolean, cancelable: boolean, reconnecting: boolean, onSettings: () => void, onToggleConnect: () => void, onClearError: () => void }} props */
export function ConnectScreen({
  snap,
  connectPending,
  busy,
  cancelable,
  reconnecting,
  onSettings,
  onToggleConnect,
  onToggleMesh,
  meshBusy,
  meshError,
  onClearError,
}) {
  const { theme, accent } = useT();

  if (!snap) return null;

  const cs = snap.error
    ? "error"
    : snap.connected
      ? "connected"
      : connectPending
        ? "connecting"
        : "idle";

  const profile = getActiveProfile(snap.cfg);
  const meshEnabled = Boolean(profile?.yb_mesh_enabled);
  const meshDisabled = busy || meshBusy || connectPending || (!profile?.yb_mesh_endpoint && !meshEnabled);
  const ringColor =
    cs === "connected"
      ? accent.hex
      : cs === "connecting"
        ? SEMANTIC.warn
        : cs === "error"
          ? SEMANTIC.err
          : theme.lineHi;
  const ringGlow =
    cs === "connected"
      ? accent.glow
      : cs === "connecting"
        ? "rgba(255,184,77,0.35)"
        : cs === "error"
          ? "rgba(255,90,90,0.35)"
          : "transparent";

  const connectingLabel = reconnecting ? t("status_reconnecting") : t("status_handshaking");
  const stateLabel =
    cs === "connected"
      ? t("status_connected")
      : cs === "connecting"
        ? connectingLabel
        : cs === "error"
          ? t("status_disconnected") + " · !"
          : t("status_disconnected");

  // Пока туннель поднимается/пересобирается, кнопка — «Отменить», а не заблокированный круг:
  // блокируем её только на время самого invoke.
  const btnLabel = snap.connected
    ? t("cta_disconnect")
    : cancelable
      ? t("cta_cancel")
      : t("cta_connect");
  const canTap = snap.connected || cancelable || snap.canConnect;
  const tapDisabled = !canTap || busy;

  const serverName = profile?.yb_mesh_enabled ? (profile.name || snap.displayHost) : snap.displayHost;
  const subtitle = snap.connected ? serverName : t("status_sub_disconnected");

  const inviteMode = Boolean(profile?.has_invite);
  const serverMismatch =
    snap.connected &&
    snap.tunnelServer &&
    !inviteMode &&
    String(profile?.server || "").trim() !== String(snap.tunnelServer).trim();

  /** Короткая строка для правого блока хедера (как united-design-new MobileHeader). */
  const headerStatusShort =
    cs === "connected"
      ? t("status_connected")
      : cs === "connecting"
        ? connectingLabel
        : cs === "error"
          ? "!"
          : t("status_disconnected");

  const safeTop = "env(safe-area-inset-top, 0px)";

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
        overflow: "hidden",
        boxSizing: "border-box",
        background: "transparent",
      }}
    >
      {/* united-design-new/app/mobile.jsx MobileHeader */}
      <header
        style={{
          flexShrink: 0,
          padding: `calc(8px + ${safeTop}) 18px 14px`,
          borderBottom: `1px solid ${theme.line}`,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
        }}
      >
        <div>
          <div
            style={{
              fontFamily: MONO,
              fontSize: 22,
              color: theme.text,
              letterSpacing: 1,
              lineHeight: 1.1,
            }}
          >
            {t("brand_header")}
            <span style={{ color: accent.hex }}>_</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <StatusDot state={cs} size={8} animate={false} />
          <span
            style={{
              fontFamily: MONO,
              fontSize: 10,
              letterSpacing: 1.2,
              color: theme.textDim,
              textTransform: "uppercase",
              maxWidth: 140,
              textAlign: "right",
            }}
          >
            {headerStatusShort}
          </span>
        </div>
      </header>

      {/* united-design-new/app/mobile-calm.jsx MobileConnectCalm */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          overflow: "auto",
          WebkitOverflowScrolling: "touch",
          padding: "44px 22px 24px",
          display: "flex",
          flexDirection: "column",
          gap: 26,
          boxSizing: "border-box",
        }}
      >
        <div
          style={{
            alignSelf: "center",
            display: "inline-flex",
            alignItems: "center",
            gap: 8,
            padding: "6px 12px",
            borderRadius: 999,
            background: cs === "connected" ? accent.soft : "rgba(255,255,255,0.04)",
            border: `1px solid ${cs === "connected" ? accent.hex : theme.line}`,
          }}
        >
          <StatusDot state={cs} size={7} animate={false} />
          <span
            style={{
              fontFamily: SANS,
              fontSize: 11,
              letterSpacing: 0.8,
              color: cs === "connected" ? accent.hex : theme.textDim,
              textTransform: "uppercase",
              fontWeight: 500,
            }}
          >
            {stateLabel}
          </span>
        </div>

        <div style={{ display: "flex", justifyContent: "center", padding: "8px 0 4px" }}>
          <button
            type="button"
            disabled={tapDisabled}
            onClick={onToggleConnect}
            style={{
              width: 220,
              height: 220,
              borderRadius: "50%",
              background: "transparent",
              border: `1.5px solid ${ringColor}`,
              cursor: tapDisabled ? "not-allowed" : "pointer",
              padding: 0,
              position: "relative",
              transition: "border-color 200ms ease, opacity 160ms ease, transform 160ms ease",
              opacity: !canTap ? 0.45 : 1,
              boxShadow: `0 0 0 10px rgba(255,255,255,0.015), 0 0 36px ${ringGlow}`,
            }}
          >
            <div
              style={{
                position: "absolute",
                inset: 14,
                borderRadius: "50%",
                background:
                  cs === "connected"
                    ? `radial-gradient(circle at 50% 40%, ${accent.soft}, transparent 70%), #0a0d11`
                    : cs === "connecting"
                      ? `radial-gradient(circle at 50% 40%, rgba(255,184,77,0.18), transparent 70%), #0a0d11`
                      : cs === "error"
                        ? `radial-gradient(circle at 50% 40%, rgba(255,90,90,0.18), transparent 70%), #0a0d11`
                        : "#0a0d11",
                border: `1px solid ${cs === "connected" ? accent.hex : theme.line}`,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <svg width="48" height="48" viewBox="0 0 48 48" fill="none" aria-hidden>
                <path
                  d="M24 8 V24"
                  stroke={ringColor}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                />
                <path
                  d="M14 16 a14 14 0 1 0 20 0"
                  stroke={ringColor}
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  fill="none"
                />
              </svg>
              <div
                style={{
                  fontFamily: SANS,
                  fontSize: 12,
                  letterSpacing: 1.5,
                  color: ringColor,
                  marginTop: 10,
                  textTransform: "uppercase",
                  fontWeight: 500,
                }}
              >
                {btnLabel}
              </div>
            </div>
            {cs === "connecting" && (
              <div
                aria-hidden
                style={{
                  position: "absolute",
                  inset: -4,
                  borderRadius: "50%",
                  border: `1.5px solid ${SEMANTIC.warn}`,
                  animation: "biba-ping 1.55s ease-out infinite",
                  pointerEvents: "none",
                  willChange: "transform, opacity",
                  transform: "translateZ(0)",
                  backfaceVisibility: "hidden",
                }}
              />
            )}
          </button>
        </div>

        <button
          type="button"
          aria-pressed={meshEnabled}
          disabled={meshDisabled}
          onClick={() => onToggleMesh(!meshEnabled)}
          style={{
            alignSelf: "center",
            minWidth: 112,
            minHeight: 44,
            padding: "10px 20px",
            border: `1px solid ${meshEnabled ? theme.text : theme.line}`,
            borderRadius: 4,
            background: meshEnabled ? theme.text : theme.panel,
            color: meshEnabled ? theme.panel : theme.textDim,
            fontFamily: SANS,
            fontSize: 14,
            fontWeight: 500,
            cursor: meshDisabled ? "not-allowed" : "pointer",
            opacity: meshDisabled ? 0.55 : 1,
            transition: "background 160ms ease, color 160ms ease, border-color 160ms ease",
          }}
        >
          {t("mesh_toggle")}
        </button>
        {!profile?.yb_mesh_endpoint && <div style={{ alignSelf: "center", color: theme.textDim, fontFamily: SANS, fontSize: 12 }}>{t("mesh_missing_endpoint")}</div>}
        {meshError && <div role="alert" style={{ alignSelf: "center", color: SEMANTIC.err, fontFamily: SANS, fontSize: 12 }}>{meshError}</div>}

        <button
          type="button"
          onClick={onSettings}
          style={{
            alignSelf: "center",
            textAlign: "center",
            maxWidth: 300,
            width: "100%",
            background: theme.panel,
            border: `1px solid ${theme.line}`,
            borderRadius: 4,
            padding: "12px 16px",
            cursor: "pointer",
            color: theme.text,
          }}
        >
          <div
            style={{
              fontFamily: MONO,
              fontSize: 10,
              color: theme.textDim,
              letterSpacing: 1.5,
              textTransform: "uppercase",
              marginBottom: 4,
            }}
          >
            {t("server_label")}
          </div>
          <div style={{ fontFamily: SANS, fontSize: 16, fontWeight: 500 }}>
            {serverName}
          </div>
          <div
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: theme.textDim,
              marginTop: 4,
            }}
          >
            {snap.serverSubtitle}
          </div>
        </button>

        <ConnectStats snap={snap} />

        <p
          style={{
            fontFamily: SANS,
            fontSize: 12,
            color: theme.textDim,
            textAlign: "center",
            margin: 0,
          }}
        >
          {subtitle}
        </p>

        {serverMismatch && (
          <p
            style={{
              color: SEMANTIC.warn,
              fontFamily: MONO,
              fontSize: 11,
              textAlign: "center",
              margin: 0,
            }}
          >
            {t("warn_server_changed")}
          </p>
        )}

        {snap.connected && snap.tunnelServer && (
          <p
            style={{
              color: theme.textDim,
              fontFamily: MONO,
              fontSize: 11,
              textAlign: "center",
              margin: 0,
            }}
          >
            {t("active_server", { host: snap.tunnelServer })}
          </p>
        )}

        {snap.error && (
          <button
            type="button"
            onClick={onClearError}
            style={{
              background: "rgba(255,90,90,0.12)",
              border: `1px solid ${SEMANTIC.err}`,
              color: SEMANTIC.err,
              borderRadius: 4,
              padding: "10px 12px",
              fontFamily: MONO,
              fontSize: 11,
              cursor: "pointer",
              textAlign: "center",
            }}
          >
            {snap.error}
          </button>
        )}
      </div>
    </div>
  );
}
