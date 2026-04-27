import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { colors, radii, spacing } from "../../lib/theme";
import { Island } from "../ui/Island";

export interface PageMeta {
  key: string;
  label: string;
  icon: string;
}

interface TopRailProps {
  pages: PageMeta[];
  activeIndex: number;
  onPress: (index: number) => void;
  title: string;
  subtitle?: string;
}

export const TopRail: React.FC<TopRailProps> = ({
  pages,
  activeIndex,
  onPress,
  title,
  subtitle,
}) => {
  const insets = useSafeAreaInsets();
  return (
    <View style={[styles.wrap, { paddingTop: insets.top + 8 }]}>
      <Island padding={0} style={styles.island}>
        <View style={styles.row}>
          <View style={styles.titleBox}>
            <Text numberOfLines={1} style={styles.title}>
              {title}
            </Text>
            {subtitle ? (
              <Text numberOfLines={1} style={styles.subtitle}>
                {subtitle}
              </Text>
            ) : null}
          </View>
          <View style={styles.dots}>
            {pages.map((p, i) => {
              const active = i === activeIndex;
              return (
                <Pressable
                  key={p.key}
                  onPress={() => onPress(i)}
                  hitSlop={10}
                  style={[styles.dot, active && styles.dotActive]}
                >
                  <Text style={[styles.dotIcon, active && styles.dotIconActive]}>{p.icon}</Text>
                </Pressable>
              );
            })}
          </View>
        </View>
      </Island>
    </View>
  );
};

const styles = StyleSheet.create({
  wrap: {
    paddingHorizontal: spacing.md,
    paddingBottom: spacing.sm,
  },
  island: {
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.sm + 2,
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    gap: spacing.md,
  },
  titleBox: { flex: 1, minWidth: 0 },
  title: {
    color: colors.textHi,
    fontSize: 16,
    fontWeight: "700",
    letterSpacing: 0.2,
  },
  subtitle: {
    color: colors.textMd,
    fontSize: 11,
    marginTop: 1,
  },
  dots: { flexDirection: "row", gap: 4 },
  dot: {
    width: 30,
    height: 30,
    borderRadius: radii.pill,
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "transparent",
  },
  dotActive: {
    backgroundColor: "rgba(124,107,245,0.18)",
  },
  dotIcon: {
    color: colors.textLo,
    fontSize: 14,
  },
  dotIconActive: {
    color: colors.primary,
  },
});
