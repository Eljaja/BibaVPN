import React from "react";
import { useT } from "../ThemeContext.jsx";
import { MONO } from "../theme.js";
import { t } from "../i18n.js";

/** united-design-new/app/mobile.jsx MobileTabs — ◈ ◉ ▤ */
export function BottomNav({ value, onChange }) {
  const { theme, accent } = useT();
  const items = [
    { id: "connect", label: t("nav_connect"), glyph: "◈" },
    { id: "profiles", label: t("nav_profiles"), glyph: "◉" },
    { id: "settings", label: t("nav_settings"), glyph: "▤" },
  ];
  return (
    <nav
      role="navigation"
      aria-label={t("wordmark_alt")}
      style={{
        position: "relative",
        zIndex: 100,
        flexShrink: 0,
        display: "flex",
        alignItems: "stretch",
        borderTop: `1px solid ${theme.line}`,
        background: theme.bgInk,
        boxShadow: "0 -8px 24px rgba(0,0,0,0.45)",
        padding: "8px 6px max(16px, env(safe-area-inset-bottom, 0px))",
      }}
    >
      {items.map(({ id, label, glyph }) => {
        const active = value === id;
        return (
          <button
            key={id}
            type="button"
            onClick={() => onChange(/** @type {typeof id} */ (id))}
            style={{
              flex: 1,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              gap: 4,
              background: "transparent",
              border: "none",
              cursor: "pointer",
              padding: "6px 2px 0",
            }}
          >
            <span
              style={{
                fontFamily: MONO,
                fontSize: 16,
                color: active ? accent.hex : theme.textDim,
                lineHeight: 1,
              }}
              aria-hidden
            >
              {glyph}
            </span>
            <span
              style={{
                fontFamily: MONO,
                fontSize: 9.5,
                letterSpacing: 1,
                color: active ? accent.hex : theme.textDim,
                textTransform: "uppercase",
                fontWeight: active ? 600 : 500,
              }}
            >
              {label}
            </span>
          </button>
        );
      })}
    </nav>
  );
}
