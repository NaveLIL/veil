import React, { useRef } from 'react';
import { Pressable, Text, View } from 'react-native';
import { ChevronDown } from 'lucide-react-native';
import { styles } from './profileStyles';
import { Palette } from './appearance';
import { useAccessibilityFocus } from './AccessibilityFocusBoundary';
export function FloatingProfile({
  c,
  profile,
  onOpen,
  caption = "Ваш профиль · демо",
  avatar,
}: {
  c: Palette;
  profile: { name: string };
  caption?: string;
  avatar?: React.ReactNode;
  onOpen: (handle?: number) => void;
}) {
  const trigger = useRef<View>(null);
  const focus = useAccessibilityFocus();
  return (
    <View
      testID="floating-profile"
      style={[
        styles.floating,
        { backgroundColor: c.surface, borderColor: c.line },
      ]}
    >
      <Pressable
        ref={trigger}
        accessibilityRole="button"
        accessibilityLabel="Раскрыть свой профиль"
        onPress={() => onOpen(focus.remember(trigger))}
        style={({ pressed }) => [styles.summary, pressed && styles.pressed]}
      >
        {avatar ?? <View importantForAccessibility="no-hide-descendants" style={[styles.avatar, { backgroundColor: c.tint, borderColor: c.accent }]}>
          <Text style={[styles.initial, {color:c.accent}]}>{profile.name.slice(0,1).toLocaleUpperCase('ru') || 'В'}</Text>
          <View style={[styles.statusDot, {borderColor:c.bg}]} />
        </View>}
        <View style={styles.flex}>
          <Text numberOfLines={1} style={[styles.name, { color: c.text }]}>
            {profile.name}
          </Text>
          <Text style={[styles.caption, { color: c.muted }]}>
            {caption}
          </Text>
        </View>
        <ChevronDown size={18} color={c.muted} />
      </Pressable>
    </View>
  );
}
