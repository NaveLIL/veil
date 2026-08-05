import React from "react";
import Svg, { Path, Rect } from "react-native-svg";

interface PhaseShiftMarkProps {
  size?: number;
  label?: string;
  testID?: string;
}

/**
 * Code-native rendering of Veil's canonical Phase Shift mark.
 *
 * Keep this geometry synchronized with assets/brand/phase-shift-mark.svg and
 * the desktop VeilMark component. The glyph identifies Veil; it must not be
 * repurposed as a security-state icon.
 */
export function PhaseShiftMark({
  size = 24,
  label,
  testID,
}: PhaseShiftMarkProps) {
  return (
    <Svg
      testID={testID}
      accessible={Boolean(label)}
      accessibilityRole={label ? "image" : undefined}
      accessibilityLabel={label}
      importantForAccessibility={label ? "yes" : "no-hide-descendants"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
    >
      <Rect
        x="0.5"
        y="0.5"
        width="23"
        height="23"
        rx="5.5"
        fill="#0d0e14"
        stroke="#2e2e50"
      />
      <Path
        fill="#a78bfa"
        d="M4 4H8V11.8L4 13ZM4 16L8 14.8V20H4ZM10 2H14V10.5L10 11.7ZM10 14.7L14 13.5V22H10ZM16 5H20V8.2L16 9.4ZM16 12.4L20 11.2V19H16Z"
      />
    </Svg>
  );
}
