import React from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { Bell, House, Layers, type LucideIcon } from "lucide-react-native";

import { colors, radii, spacing } from "../../lib/theme";

const DOCK_INSET = 3;

export type RootDestination = "home" | "spaces" | "updates";

interface RootDestinationDefinition {
  key: RootDestination;
  label: string;
  icon: LucideIcon;
}

const HOME_DESTINATION: RootDestinationDefinition = {
  key: "home",
  label: "Home",
  icon: House,
};

const DESIGN_PREVIEW_DESTINATIONS: readonly RootDestinationDefinition[] = [
  HOME_DESTINATION,
  { key: "spaces", label: "Spaces", icon: Layers },
  { key: "updates", label: "Updates", icon: Bell },
];

export function rootDestinations(
  _designPreviewEnabled?: boolean,
): readonly RootDestinationDefinition[] {
  return DESIGN_PREVIEW_DESTINATIONS;
}

export function RootDock({
  active,
  onSelect,
}: {
  active: RootDestination;
  onSelect: (destination: RootDestination) => void;
}) {
  const insets = useSafeAreaInsets();
  const destinations = rootDestinations(__DEV__);

  if (destinations.length < 2) return null;

  return (
    <View
      testID="root-dock-wrap"
      style={[
        styles.wrap,
        {
          paddingBottom: Math.max(insets.bottom, DOCK_INSET),
        },
      ]}
    >
      <View accessibilityRole="tablist" style={styles.island} testID="root-dock-island">
        {destinations.map((destination) => {
          const selected = destination.key === active;
          const Icon = destination.icon;
          return (
            <Pressable
              key={destination.key}
              accessibilityRole="tab"
              accessibilityState={{ selected }}
              accessibilityLabel={destination.label}
              onPress={() => onSelect(destination.key)}
              style={({ pressed }) => [
                styles.item,
                selected && styles.itemSelected,
                pressed && styles.itemPressed,
              ]}
            >
              <Icon
                size={20}
                strokeWidth={2}
                color={selected ? colors.primaryHi : colors.textLo}
              />
              <Text
                numberOfLines={1}
                style={[styles.label, selected && styles.labelSelected]}
              >
                {destination.label}
              </Text>
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: {
    paddingTop: 0,
    backgroundColor: colors.surfaceSolid,
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: colors.border,
  },
  island: {
    height: 54,
    flexDirection: "row",
    alignItems: "stretch",
    paddingHorizontal: spacing.md,
  },
  item: {
    flex: 1,
    minWidth: 0,
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: 4,
  },
  itemSelected: {},
  itemPressed: { opacity: 0.68 },
  label: { flexShrink: 1, color: colors.textLo, fontSize: 10, fontWeight: "600", textAlign: "center" },
  labelSelected: { color: colors.primaryHi },
});
