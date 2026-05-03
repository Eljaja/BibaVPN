import React, { createContext, useContext, useMemo } from "react";
import { ACCENTS, THEMES } from "./theme.js";

const ThemeCtx = createContext(null);

export function ThemeProvider({ children }) {
  const value = useMemo(
    () => ({
      theme: THEMES.dark,
      accent: ACCENTS.white,
    }),
    [],
  );
  return <ThemeCtx.Provider value={value}>{children}</ThemeCtx.Provider>;
}

export function useT() {
  const v = useContext(ThemeCtx);
  if (!v) throw new Error("useT outside ThemeProvider");
  return v;
}
