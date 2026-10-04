/**
 * Source adaptation: Rocket.Chat.ReactNative 4.77.0, commit
 * 0a7df3d82a2e9d20e37f9ec5651fd3c74b98ab36.
 * app/lib/constants/colors.ts (dark palette), app/views/Styles.ts.
 * Copyright (c) 2015-2018 Rocket.Chat Technologies Corp. MIT.
 * See third-party/rocket-chat-reactnative/LICENSE and SOURCE_INVENTORY.md.
 * Changes: selected tokens only; platform system fonts replace upstream Inter.
 */
import { Platform } from "react-native";

export const rocketColors = {
  surfaceLight: "#262931",
  surfaceTint: "#1F2329",
  surfaceRoom: "#1F2329",
  surfaceSelected: "#3C3F44",
  strokeLight: "#333842",
  strokeHighlight: "#3976D1",
  fontDefault: "#C1C7D0",
  fontTitlesLabels: "#F2F3F5",
  fontSecondaryInfo: "#9EA2A8",
  fontAnnotation: "#9EA2A8",
  fontDanger: "#CF6E7A",
} as const;

export const rocketText = {
  textAlign: "left" as const,
  backgroundColor: "transparent",
  fontVariant: ["tabular-nums" as const],
  ...Platform.select({ android: { includeFontPadding: false } }),
};
