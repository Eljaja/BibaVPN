import React from "react";
import { useT } from "../ThemeContext.jsx";
import { SEMANTIC, MONO, SANS } from "../theme.js";
import { StatusDot } from "../ui/primitives.jsx";
import { t } from "../i18n.js";
import { getActiveProfile } from "../profileUtils.js";

/** @param {{ snap: import('../vpnTypes').StateSnapshot, connectPending: boolean, onSettings: () => void, onProfiles: () => void, onToggleConnect: () => void, onClearError: () => void }} props */
export function ConnectScreen({
  snap,
  connectPending,
  onSettings,
  onProfiles,
  onToggleConnect,
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

  const inviteMode =
    String(profile?.from_invite || "").trim() !== "" &&
    String(profile?.invite_passphrase || "").trim() !== "";
  const serverMismatch =
    snap.connected &&
    snap.tunnelServer &&
    !inviteMode &&
    String(profile?.server || "").trim() !== String(snap.tunnelServer).trim();

  return (
    <div
      style={{
        padding: "36px 20px 24px",
        display: "flex",
        flexDirection: "column",
        gap: 22,
        minHeight: "100%",
        boxSizing: "border-box",
        background: theme.bg,
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <button
          type="button"
          onClick={onProfiles}
          style={{
            background: "transparent",
            border: `1px solid ${theme.line}`,
            borderRadius: 4,
            color: theme.textDim,
            padding: "8px 10px",
            cursor: "pointer",
            fontFamily: MONO,
            fontSize: 11,
          }}
        >
          {t("nav_profiles")}
        </button>
        <button
          type="button"
          onClick={onSettings}
          style={{
            background: "transparent",
            border: `1px solid ${theme.line}`,
            borderRadius: 4,
            color: theme.textDim,
            padding: "8px 10px",
            cursor: "pointer",
            fontFamily: MONO,
            fontSize: 11,
          }}
        >
          {t("nav_settings")}
        </button>
      </header>

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

      <div style={{ display: "flex", justifyContent: "center", padding: "4px 0" }}>
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
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
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
              style={{
                position: "absolute",
                inset: -4,
                borderRadius: "50%",
                border: `1.5px solid ${SEMANTIC.warn}`,
                animation: "biba-ping 1.6s ease-out infinite",
                pointerEvents: "none",
              }}
            />
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
  );
}
