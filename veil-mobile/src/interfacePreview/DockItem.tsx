import React from 'react';
import { Pressable, View } from 'react-native';
import { Search } from 'lucide-react-native';
import { geometry, Palette } from './appearance';
import { Label } from './Primitives';
import { styles } from './navigationStyles';
type IconComponent = typeof Search;
export function DockItem({
  label,
  icon: Icon,
  initials,
  selected,
  onPress,
  c,
}: {
  label: string;
  icon?: IconComponent;
  initials?: string;
  selected: boolean;
  onPress: () => void;
  c: Palette;
}) {
  return (
    <View style={styles.dockItem}>
      <View
        style={[
          styles.activePill,
          { backgroundColor: selected ? c.accent : 'transparent' },
        ]}
      />
      <Pressable
        accessibilityRole="tab"
        accessibilityLabel={label}
        accessibilityState={{ selected }}
        onPress={onPress}
        style={({ pressed }) => [
          styles.dockButton,
          {
            backgroundColor: selected ? c.accent : c.surface,
            borderRadius: geometry.radius,
          },
          pressed && styles.pressed,
        ]}
      >
        {Icon ? (
          <Icon
            size={23}
            color={selected ? '#101015' : c.muted}
            strokeWidth={1.8}
          />
        ) : (
          <Label
            color={selected ? '#101015' : c.accent}
            importantForAccessibility="no"
            style={styles.dockInitial}
          >
            {initials}
          </Label>
        )}
      </Pressable>
    </View>
  );
}

