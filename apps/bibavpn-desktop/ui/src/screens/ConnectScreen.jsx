import React, { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useT } from "../ThemeContext.jsx";
import { SEMANTIC, MONO, SANS } from "../theme.js";
import { StatusDot } from "../ui/primitives.jsx";
import { t } from "../i18n.js";
import { getActiveProfile } from "../profileUtils.js";

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

/** @param {{ snap: import('../vpnTypes').StateSnapshot, connectPending: boolean, refresh: () => Promise<void>, onSettings: () => void, onToggleConnect: () => void, onClearError: () => void }} props */
export function ConnectScreen({
  snap,
  connectPending,
  refresh,
  onSettings,
  onToggleConnect,
  onClearError,
}) {
  const { theme, accent } = useT();
  const [sessionStartedAt, setSessionStartedAt] = useState(null);
  /** Ререндер раз в секунду для uptime */
  const [, setTick] = useState(0);
  const [rttMs, setRttMs] = useState(null);

  useEffect(() => {
    if (!snap || !snap.connected) {
      setSessionStartedAt(null);
      setRttMs(null);
      return;
    }
    if (typeof snap.vpnSessionUptimeSecs === "number") {
      setSessionStartedAt(null);
      return;
    }
    setSessionStartedAt((prev) => (prev == null ? Date.now() : prev));
  }, [snap?.connected, snap?.vpnSessionUptimeSecs]);

  /** Android: uptime из JNI обновляем через get_state каждую секунду. Desktop: локальный таймер от первого connected в этом процессе. */
  useEffect(() => {
    const backend =
      snap?.connected && typeof snap.vpnSessionUptimeSecs === "number";
    if (!snap?.connected) return;
    if (backend) {
      const id = setInterval(() => {
        refresh();
      }, 1000);
      return () => clearInterval(id);
    }
    if (sessionStartedAt != null) {
      const id = setInterval(() => setTick((x) => x + 1), 1000);
      return () => clearInterval(id);
    }
  }, [snap?.connected, snap?.vpnSessionUptimeSecs, sessionStartedAt, refresh]);

  useEffect(() => {
    if (!snap?.connected) return;
    let cancelled = false;
    async function probe() {
      try {
        const v = await invoke("measure_server_rtt_cmd");
        if (cancelled) return;
        setRttMs(typeof v === "number" ? v : null);
      } catch {
        if (!cancelled) setRttMs(null);
      }
    }
    probe();
    const id = setInterval(probe, 8000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [snap?.connected]);

  if (!snap) return null;

  const uptimeStr =
    snap.connected && typeof snap.vpnSessionUptimeSecs === "number"
      ? formatSessionUptime(snap.vpnSessionUptimeSecs * 1000)
      : snap.connected && sessionStartedAt != null
        ? formatSessionUptime(Date.now() - sessionStartedAt)
        : "—";

  const cs = snap.error
    ? "error"
    : snap.connected
      ? "connected"
      : connectPending
        ? "connecting"
        : "idle";

  const profile = getActiveProfile(snap.cfg);
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

  const stateLabel =
    cs === "connected"
      ? t("status_connected")
      : cs === "connecting"
        ? t("status_handshaking")
        : cs === "error"
          ? t("status_disconnected") + " · !"
          : t("status_disconnected");

  const btnLabel = snap.connected ? t("cta_disconnect") : t("cta_connect");
  const canTap = snap.connected || snap.canConnect;

  const subtitle = snap.connected ? snap.displayHost : t("status_sub_disconnected");

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
        ? t("status_handshaking")
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
          <StatusDot state={cs} size={8} />
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
          <StatusDot state={cs} size={7} />
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
            disabled={!canTap || connectPending}
            onClick={onToggleConnect}
            style={{
              width: 220,
              height: 220,
              borderRadius: "50%",
              background: "transparent",
              border: `1.5px solid ${ringColor}`,
              cursor: !canTap || connectPending ? "not-allowed" : "pointer",
              padding: 0,
              position: "relative",
              transition: "all 200ms ease",
              opacity: !canTap ? 0.45 : 1,
              boxShadow: `0 0 0 10px rgba(255,255,255,0.015), 0 0 60px ${ringGlow}`,
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
              <>
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
                <div
                  aria-hidden
                  style={{
                    position: "absolute",
                    inset: -4,
                    borderRadius: "50%",
                    border: `1px solid ${SEMANTIC.warn}`,
                    animation: "biba-ping 1.55s ease-out infinite",
                    animationDelay: "0.78s",
                    pointerEvents: "none",
                    willChange: "transform, opacity",
                    transform: "translateZ(0)",
                    backfaceVisibility: "hidden",
                    opacity: 0.85,
                  }}
                />
              </>
            )}
          </button>
        </div>

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
            {snap.displayHost}
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
              v:
                snap.connected && typeof rttMs === "number"
                  ? String(rttMs)
                  : "—",
              u: snap.connected && typeof rttMs === "number" ? "ms" : "",
            },
            {
              l: t("connect_stat_uptime"),
              v: uptimeStr,
              u: "",
            },
            {
              l: t("connect_stat_down"),
              v: snap.connected ? "—" : "—",
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
