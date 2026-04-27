/**
 * Shared design tokens — mirrors veil-desktop/src/app.css palette.
 * Mobile uses StyleSheet (no Tailwind yet); keep this file as the
 * single source of truth so a future move to NativeWind is mechanical.
 */

export const colors = {
  window: "#1E1F22",
  island: "#2B2D31",
  background: "#111117",

  foreground: "#ededf0",
  mutedForeground: "#7a7a90",

  primary: "#7c6bf5",
  primaryDeep: "#6955e0",
  primaryHi: "#9b8afb",

  border: "rgba(255,255,255,0.06)",
  borderSoft: "rgba(255,255,255,0.04)",
  surface: "rgba(30,31,34,0.88)",
  surfaceSolid: "rgba(30,31,34,0.95)",
  surfaceLow: "rgba(255,255,255,0.04)",
  surfaceLowHover: "rgba(255,255,255,0.07)",

  textHi: "rgba(255,255,255,0.9)",
  textMd: "rgba(255,255,255,0.6)",
  textLo: "rgba(255,255,255,0.35)",
  textXLo: "rgba(255,255,255,0.2)",

  destructive: "#f04848",
  destructiveBg: "rgba(240,72,72,0.08)",
  destructiveBorder: "rgba(240,72,72,0.2)",

  warning: "#fbbf24",
  warningBg: "rgba(251,191,36,0.05)",
  warningBorder: "rgba(251,191,36,0.12)",

  success: "#34d399",
  successBg: "rgba(52,211,153,0.08)",
  successBorder: "rgba(52,211,153,0.2)",
};

export const radii = {
  sm: 6,
  md: 10,
  lg: 14,
  xl: 20,
  pill: 999,
};

export const spacing = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 28,
};

export const typography = {
  // Mono fallbacks — RN uses platform monospace if "monospace" alias.
  mono: "monospace",
};

/** Common easings for Reanimated/Animated. */
export const motion = {
  enterMs: 350,
  leaveMs: 350,
  taglineFadeMs: 400,
  taglineIntervalMs: 4000,
};
