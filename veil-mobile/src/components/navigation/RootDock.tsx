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
  designPreviewEnabled: boolean,
): readonly RootDestinationDefinition[] {
  return designPreviewEnabled ? DESIGN_PREVIEW_DESTINATIONS : [HOME_DESTINATION];
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

  // Until native Spaces/Updates projections exist, release builds expose only
  // Home and therefore do not render a misleading one-item navigation dock.
  if (destinations.length < 2) return null;

  return (
    <View
      testID="root-dock-wrap"
      style={[
        styles.wrap,
        {
          paddingBottom: Math.max(insets.bottom, spacing.md),
          paddingLeft: Math.max(insets.left, spacing.md),
          paddingRight: Math.max(insets.right, spacing.md),
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
                size={16}
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
    backgroundColor: colors.background,
  },
  island: {
    minHeight: 54,
    flexDirection: "row",
    alignItems: "stretch",
    padding: DOCK_INSET,
    borderRadius: radii.xl,
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: colors.border,
    backgroundColor: colors.surfaceSolid,
  },
  item: {
    flex: 1,
    minWidth: 0,
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    // Keep the selected surface concentric with the dock island.
    borderRadius: radii.xl - DOCK_INSET,
    gap: 5,
  },
  itemSelected: { backgroundColor: "rgba(124,107,245,0.13)" },
  itemPressed: { opacity: 0.68 },
  label: { flexShrink: 1, color: colors.textLo, fontSize: 10, fontWeight: "700", textAlign: "center" },
  labelSelected: { color: colors.textHi },
});
