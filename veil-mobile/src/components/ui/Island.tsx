import React from "react";
import { Platform, StyleSheet, View, ViewProps, ViewStyle } from "react-native";
import { BlurView } from "expo-blur";
import { colors, radii } from "../../lib/theme";

/**
 * Island — the signature Veil surface.
 *
 * On Android 12+ we get real backdrop blur via BlurView's
 * experimental method; on older devices we fall back gracefully to a
 * semi-transparent solid surface (still readable, just no glass).
 */
export interface IslandProps extends ViewProps {
  variant?: "default" | "solid";
  glow?: boolean;
  padding?: number;
}

export const Island: React.FC<IslandProps> = ({
  children,
  style,
  variant = "default",
  glow = true,
  padding,
  ...rest
}) => {
  const supportsBlur = Platform.OS === "ios" || Platform.Version >= 31;

  const containerStyle: ViewStyle = {
    borderRadius: radii.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    overflow: "hidden",
    backgroundColor: supportsBlur
      ? variant === "solid"
        ? "rgba(30,31,34,0.7)"
        : "rgba(30,31,34,0.55)"
      : variant === "solid"
        ? colors.surfaceSolid
        : colors.surface,
    ...(glow ? styles.glow : null),
    ...(padding != null ? { padding } : null),
  };

  const inner = (
    <View {...rest} style={[containerStyle, style]}>
      {children}
    </View>
  );

  if (!supportsBlur) return inner;

  return (
    <View
      style={[
        { borderRadius: radii.xl, overflow: "hidden" },
        glow ? styles.glow : null,
        style,
      ]}
    >
      <BlurView
        intensity={32}
        tint="dark"
        experimentalBlurMethod="dimezisBlurView"
        style={StyleSheet.absoluteFill}
      />
      <View
        {...rest}
        style={[
          {
            borderRadius: radii.xl,
            borderWidth: StyleSheet.hairlineWidth,
            borderColor: colors.border,
            backgroundColor:
              variant === "solid"
                ? "rgba(30,31,34,0.55)"
                : "rgba(30,31,34,0.35)",
            ...(padding != null ? { padding } : null),
          },
        ]}
      >
        {children}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  glow: {
    shadowColor: "#000",
    shadowOpacity: 0.45,
    shadowRadius: 24,
    shadowOffset: { width: 0, height: 8 },
    elevation: 12,
  },
});
