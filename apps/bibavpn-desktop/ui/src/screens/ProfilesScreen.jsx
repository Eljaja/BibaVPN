import React from "react";
import { useT } from "../ThemeContext.jsx";
import { Btn } from "../ui/primitives.jsx";
import { t } from "../i18n.js";
import { addProfile, removeProfile, setActiveProfileId } from "../profileUtils.js";

/** @param {{ cfg: import('../vpnTypes').SavedConfig, onSave: (c: import('../vpnTypes').SavedConfig) => Promise<void> }} props */
export function ProfilesScreen({ cfg, onSave }) {
  const { theme, accent } = useT();

  async function handleAdd() {
    const next = addProfile(cfg);
    await onSave(next);
  }

  async function handleSelect(id) {
    const next = setActiveProfileId(cfg, id);
    await onSave(next);
  }

  async function handleDelete(id) {
    const next = removeProfile(cfg, id);
    await onSave(next);
  }

  return (
    <div
      style={{
        flex: 1,
        minHeight: 0,
        background: theme.bg,
        display: "flex",
        flexDirection: "column",
        padding: "20px 18px 24px",
        gap: 14,
        overflow: "auto",
      }}
    >
      <h1
        style={{
          fontFamily: "IBM Plex Mono",
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: 1.5,
          color: theme.text,
          textTransform: "uppercase",
          margin: 0,
        }}
      >
        {t("nav_profiles")}
      </h1>

      <Btn kind="primary" block onClick={handleAdd}>
        + {t("profile_new")}
      </Btn>

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {cfg.profiles.map((p) => {
          const isActive = p.id === cfg.active_profile_id;
          return (
            <div
              key={p.id}
              style={{
                border: `1px solid ${isActive ? accent.hex : theme.line}`,
                borderRadius: 4,
                padding: 12,
                background: theme.panel,
                display: "flex",
                flexDirection: "column",
                gap: 8,
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                <button
                  type="button"
                  onClick={() => handleSelect(p.id)}
                  style={{
                    flex: 1,
                    textAlign: "left",
                    background: "transparent",
                    border: "none",
                    color: theme.text,
                    cursor: "pointer",
                    padding: 0,
                  }}
                >
                  <div style={{ fontFamily: "IBM Plex Sans", fontWeight: 600 }}>{p.name}</div>
                  <div style={{ fontFamily: "IBM Plex Mono", fontSize: 11, color: theme.textDim }}>
                    {p.server.trim() || (p.from_invite.trim() ? t("display_invite") : "—")}
                  </div>
                </button>
                {isActive && (
                  <span
                    style={{
                      fontFamily: "IBM Plex Mono",
                      fontSize: 10,
                      color: accent.hex,
                    }}
                  >
                    ● {t("profile_active")}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                {!isActive && (
                  <Btn kind="ghost" onClick={() => handleSelect(p.id)}>
                    {t("profile_active")}
                  </Btn>
                )}
                <Btn
                  kind="ghost"
                  danger
                  disabled={cfg.profiles.length <= 1}
                  onClick={() => handleDelete(p.id)}
                >
                  {t("profile_delete")}
                </Btn>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
