import React, { useState } from "react";
import { useT } from "../ThemeContext.jsx";
import { SEMANTIC, MONO, SANS } from "../theme.js";

export function StatusDot({ state, size = 8 }) {
  const { accent } = useT();
  const color =
    state === "connected"
      ? accent.hex
      : state === "connecting"
        ? SEMANTIC.warn
        : state === "error"
          ? SEMANTIC.err
          : "#4b5761";
  const pulse = state === "connecting";
  return (
    <span
      style={{
        position: "relative",
        display: "inline-flex",
        width: size,
        height: size,
      }}
    >
      <span
        style={{
          position: "absolute",
          inset: 0,
          borderRadius: "50%",
          background: color,
          boxShadow:
            state === "idle" ? "none" : `0 0 ${size}px ${color}`,
        }}
      />
      {pulse && (
        <span
          style={{
            position: "absolute",
            inset: 0,
            borderRadius: "50%",
            background: color,
            animation: "biba-ping 1.2s ease-out infinite",
          }}
        />
      )}
    </span>
  );
}

export function Btn({
  kind = "ghost",
  block,
  children,
  onClick,
  disabled,
  danger,
}) {
  const { theme, accent } = useT();
  const base = {
    fontFamily: MONO,
    fontSize: 12,
    letterSpacing: 1.5,
    textTransform: "uppercase",
    padding: "12px 18px",
    borderRadius: 4,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.4 : 1,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
    width: block ? "100%" : "auto",
    border: "1px solid transparent",
    fontWeight: 500,
    transition: "all 120ms",
    userSelect: "none",
  };
  let sx;
  if (kind === "primary") {
    sx = {
      background: danger ? `rgba(255,90,90,0.14)` : accent.soft,
      border: `1px solid ${danger ? SEMANTIC.err : accent.hex}`,
      color: danger ? SEMANTIC.err : accent.hex,
    };
  } else if (kind === "solid") {
    sx = { background: accent.hex, color: "#061000", fontWeight: 600 };
  } else {
    sx = {
      background: "transparent",
      border: `1px solid ${theme.line}`,
      color: theme.text,
    };
  }
  return (
    <button
      type="button"
      onClick={disabled ? undefined : onClick}
      style={{ ...base, ...sx }}
    >
      {children}
    </button>
  );
}

export function TermHeading({ children, muted, style }) {
  const { theme, accent } = useT();
  return (
    <div
      style={{
        fontFamily: MONO,
        fontSize: 11,
        letterSpacing: 1.5,
        textTransform: "uppercase",
        display: "flex",
        gap: 8,
        alignItems: "center",
        color: muted ? theme.textDim : theme.text,
        ...style,
      }}
    >
      <span style={{ color: accent.hex }}>&gt;</span>
      <span>{children}</span>
    </div>
  );
}

export function KV({ label, value, accent: useAccent, mono = true, hint }) {
  const { theme, accent } = useT();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
      <div
        style={{
          fontFamily: MONO,
          fontSize: 9.5,
          letterSpacing: 1.3,
          textTransform: "uppercase",
          color: theme.textDim,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <span>{label}</span>
        {hint && (
          <span
            style={{
              color: theme.textMute,
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            {hint}
          </span>
        )}
      </div>
      <div
        style={{
          fontFamily: mono ? MONO : SANS,
          fontSize: 15,
          fontWeight: 500,
          color: useAccent ? accent.hex : theme.text,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {value}
      </div>
    </div>
  );
}

export function ExpandSection({ label, summary, defaultOpen = false, children }) {
  const { theme, accent } = useT();
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div
      style={{
        border: `1px solid ${theme.line}`,
        borderRadius: 4,
        background: theme.panel,
        overflow: "hidden",
      }}
    >
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          padding: "14px 14px",
          background: "transparent",
          border: "none",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
          cursor: "pointer",
          color: theme.text,
        }}
      >
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-start",
            gap: 3,
          }}
        >
          <span
            style={{
              fontFamily: MONO,
              fontSize: 11,
              color: theme.textDim,
              letterSpacing: 1.5,
              textTransform: "uppercase",
            }}
          >
            {label}
          </span>
          {summary && (
            <span
              style={{
                fontFamily: MONO,
                fontSize: 11,
                color: accent.hex,
                letterSpacing: 0.5,
              }}
            >
              {summary}
            </span>
          )}
        </div>
        <span
          style={{
            fontFamily: MONO,
            fontSize: 11,
            color: theme.textDim,
            transition: "transform .2s",
            transform: open ? "rotate(90deg)" : "rotate(0deg)",
          }}
        >
          ›
        </span>
      </button>
      {open && (
        <div style={{ borderTop: `1px solid ${theme.line}`, padding: 14 }}>
          {children}
        </div>
      )}
    </div>
  );
}

export function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  rows,
  disabled,
  hint,
}) {
  const { theme } = useT();
  const common = {
    width: "100%",
    padding: "10px 12px",
    borderRadius: 4,
    border: `1px solid ${theme.line}`,
    background: theme.bgInk,
    color: theme.text,
    outline: "none",
  };
  return (
    <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <span
        style={{
          fontFamily: MONO,
          fontSize: 10,
          letterSpacing: 1.2,
          color: theme.textDim,
          textTransform: "uppercase",
        }}
      >
        {label}
      </span>
      {rows ? (
        <textarea
          style={{ ...common, resize: "vertical", minHeight: rows * 22 }}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          rows={rows}
          disabled={disabled}
        />
      ) : (
        <input
          style={common}
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
        />
      )}
      {hint && (
        <span style={{ fontFamily: MONO, fontSize: 10, color: theme.textDim, lineHeight: 1.4 }}>
          {hint}
        </span>
      )}
    </label>
  );
}

export function CheckRow({ label, checked, onChange, disabled }) {
  const { theme, accent } = useT();
  return (
    <label
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        cursor: disabled ? "default" : "pointer",
        fontFamily: MONO,
        fontSize: 12,
        color: theme.text,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        style={{ accentColor: accent.hex }}
      />
      {label}
    </label>
  );
}
