import React, { useRef, useState } from "react";
import { useT } from "../ThemeContext.jsx";
import { Btn } from "../ui/primitives.jsx";
import { t } from "../i18n.js";
import { addProfile, removeProfile, setActiveProfileId } from "../profileUtils.js";
import { SEMANTIC } from "../theme.js";

/** @param {{ cfg: import('../vpnTypes').SavedConfig, saveError?: { message: string, at: number } | null, onSave: (c: import('../vpnTypes').SavedConfig) => Promise<void> }} props */
export function ProfilesScreen({ cfg, saveError, onSave }) {
  const { theme, accent } = useT();
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);

  /** Одна операция за раз: иначе два быстрых тапа сохранят один и тот же старый `cfg`. */
  async function run(mutate) {
    if (pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    try {
      await onSave(mutate(cfg));
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
  }

  const handleAdd = () => run(addProfile);
  const handleSelect = (id) => run((c) => setActiveProfileId(c, id));
  const handleDelete = (id) => run((c) => removeProfile(c, id));

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

      {saveError && (
        <div
          role="alert"
          style={{
            padding: "10px 12px",
            borderRadius: 4,
            border: `1px solid ${SEMANTIC.err}`,
            background: "rgba(255,90,90,0.08)",
            color: SEMANTIC.err,
            fontFamily: "IBM Plex Mono",
            fontSize: 11,
          }}
        >
          {t("profile_save_failed", { error: saveError.message })}
        </div>
      )}

      <Btn kind="primary" block onClick={handleAdd} disabled={pending}>
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
                  disabled={pending}
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
                    {p.server.trim() ||
                      (String(p.from_invite || "").trim() ? t("display_invite") : "—")}
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
                  <Btn kind="ghost" disabled={pending} onClick={() => handleSelect(p.id)}>
                    {t("profile_active")}
                  </Btn>
                )}
                <Btn
                  kind="ghost"
                  danger
                  disabled={pending || cfg.profiles.length <= 1}
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
