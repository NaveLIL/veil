import React from "react";
import {
  ActivityIndicator,
  Pressable,
  StyleSheet,
  Text,
  View,
  ViewStyle,
} from "react-native";
import { LinearGradient } from "expo-linear-gradient";
import { colors, radii } from "../../lib/theme";

export interface IslandButtonProps {
  label: string;
  onPress?: () => void;
  variant?: "primary" | "secondary" | "ghost";
  loading?: boolean;
  disabled?: boolean;
  icon?: React.ReactNode;
  style?: ViewStyle;
}

export const IslandButton: React.FC<IslandButtonProps> = ({
  label,
  onPress,
  variant = "primary",
  loading,
  disabled,
  icon,
  style,
}) => {
  const isPrimary = variant === "primary";
  const isGhost = variant === "ghost";

  return (
    <Pressable
      onPress={onPress}
      disabled={disabled || loading}
      android_ripple={
        isGhost
          ? { color: "rgba(255,255,255,0.06)", borderless: false }
          : { color: "rgba(255,255,255,0.18)", borderless: false }
      }
      style={({ pressed }) => [
        styles.base,
        !isPrimary && styles.secondary,
        isGhost && styles.ghost,
        pressed && { transform: [{ translateY: -1 }] },
        disabled && { opacity: 0.5 },
        style,
      ]}
    >
      {isPrimary ? (
        <LinearGradient
          colors={[colors.primary, colors.primaryDeep]}
          start={{ x: 0, y: 0 }}
          end={{ x: 1, y: 1 }}
          style={StyleSheet.absoluteFill}
        />
      ) : null}
      <View style={styles.content}>
        {loading ? (
          <ActivityIndicator color={isPrimary ? "#fff" : colors.textMd} size="small" />
        ) : (
          <>
            {icon ? <View style={styles.icon}>{icon}</View> : null}
            <Text
              style={[
                styles.label,
                !isPrimary && { color: colors.textMd },
                isGhost && { color: colors.textLo, fontWeight: "500" },
              ]}
            >
              {label}
            </Text>
          </>
        )}
      </View>
    </Pressable>
  );
};

const styles = StyleSheet.create({
  base: {
    height: 50,
    borderRadius: radii.md + 2,
    overflow: "hidden",
    justifyContent: "center",
    alignItems: "center",
    // primary glow
    shadowColor: colors.primary,
    shadowOpacity: 0.35,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 4 },
    elevation: 6,
  },
  secondary: {
    backgroundColor: "rgba(255,255,255,0.04)",
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    shadowOpacity: 0,
    elevation: 0,
  },
  ghost: {
    backgroundColor: "transparent",
    borderWidth: 0,
  },
  content: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    gap: 10,
    paddingHorizontal: 16,
  },
  icon: {
    width: 18,
    height: 18,
    alignItems: "center",
    justifyContent: "center",
  },
  label: {
    color: "#fff",
    fontSize: 14,
    fontWeight: "600",
    letterSpacing: 0.2,
  },
});
