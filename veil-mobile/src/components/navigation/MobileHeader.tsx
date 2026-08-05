import React from "react";
import {
  Pressable,
  StyleSheet,
  Text,
  View,
  type GestureResponderEvent,
} from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { ChevronLeft, type LucideIcon } from "lucide-react-native";

import { colors, radii, spacing } from "../../lib/theme";
import { PhaseShiftMark } from "../brand/PhaseShiftMark";

interface HeaderAction {
  label: string;
  accessibilityLabel?: string;
  onPress: (event: GestureResponderEvent) => void;
  icon?: LucideIcon;
  iconOnly?: boolean;
}

interface MobileHeaderProps {
  title: string;
  subtitle?: string;
  backAction?: HeaderAction;
  action?: HeaderAction;
  showBrand?: boolean;
}

export function MobileHeader({
  title,
  subtitle,
  backAction,
  action,
  showBrand = false,
}: MobileHeaderProps) {
  const insets = useSafeAreaInsets();

  return (
    <View
      style={[
        styles.safeWrap,
        {
          paddingTop: insets.top + spacing.md,
          paddingLeft: Math.max(insets.left, spacing.md),
          paddingRight: Math.max(insets.right, spacing.md),
        },
      ]}
    >
      <View style={styles.island}>
        {backAction ? (
          <HeaderButton action={backAction} back />
        ) : showBrand ? (
          <PhaseShiftMark size={30} label="Veil" />
        ) : null}
        <View style={styles.titleBox}>
          <Text accessibilityRole="header" numberOfLines={1} style={styles.title}>
            {title}
          </Text>
          {subtitle ? (
            <Text numberOfLines={1} style={styles.subtitle}>
              {subtitle}
            </Text>
          ) : null}
        </View>
        {action ? <HeaderButton action={action} /> : null}
      </View>
    </View>
  );
}

function HeaderButton({ action, back = false }: { action: HeaderAction; back?: boolean }) {
  const Icon = action.icon;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={action.accessibilityLabel ?? action.label}
      hitSlop={8}
      onPress={action.onPress}
      style={({ pressed }) => [styles.action, pressed && styles.actionPressed]}
    >
      {back ? <ChevronLeft size={17} strokeWidth={2.2} color={colors.primaryHi} /> : null}
      {Icon ? <Icon size={17} strokeWidth={2} color={colors.primaryHi} /> : null}
      {!action.iconOnly ? (
        <Text numberOfLines={1} style={styles.actionText}>{action.label}</Text>
      ) : null}
    </Pressable>
  );
}

const styles = StyleSheet.create({
  safeWrap: {
    paddingBottom: spacing.md,
    backgroundColor: colors.background,
  },
  island: {
    minHeight: 58,
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm,
    borderRadius: radii.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.surfaceSolid,
  },
  titleBox: { flex: 1, minWidth: 0 },
  title: {
    color: colors.textHi,
    fontSize: 17,
    fontWeight: "800",
    letterSpacing: 0.15,
  },
  subtitle: {
    color: colors.textLo,
    fontSize: 11,
    marginTop: 1,
  },
  action: {
    minHeight: 44,
    minWidth: 44,
    alignItems: "center",
    justifyContent: "center",
    flexDirection: "row",
    gap: 3,
    paddingHorizontal: spacing.sm,
    borderRadius: radii.pill,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.surfaceLow,
  },
  actionPressed: { opacity: 0.7 },
  actionText: { flexShrink: 1, color: colors.primaryHi, fontSize: 12, fontWeight: "700", textAlign: "center" },
});
