import React from 'react';
import {
  Platform,
  Pressable,
  StyleSheet,
  Switch,
  Text,
  View,
} from 'react-native';
import { Search } from 'lucide-react-native';
import type { TimelineConversation } from './conversationContract';
import { useAccessibilityFocus } from './AccessibilityFocusBoundary';
import { geometry, Palette, typography } from './appearance';
type IconComponent = typeof Search;
export function Label({
  color,
  style,
  ...props
}: React.ComponentProps<typeof Text> & { color?: string }) {
  return <Text {...props} style={[styles.text, { color }, style]} />;
}
export function IconButton({
  icon: Icon,
  label,
  onPress,
  color,
}: {
  icon: IconComponent;
  label: string;
  onPress: (handle?: number) => void;
  color: string;
}) {
  const trigger = React.useRef<View>(null);
  const focus = useAccessibilityFocus();
  return (
    <Pressable
      ref={trigger}
      onPress={() => onPress(focus.remember(trigger))}
      accessibilityRole="button"
      accessibilityLabel={label}
      style={({ pressed }) => [styles.iconButton, pressed && styles.pressed]}
    >
      <Icon accessible={false} size={22} color={color} strokeWidth={1.8} />
    </Pressable>
  );
}
export function Avatar({
  chat,
  size = 42,
}: {
  chat: Pick<TimelineConversation, 'initials' | 'color'>;
  size?: number;
}) {
  return (
    <View
      accessible={false}
      importantForAccessibility="no-hide-descendants"
      accessibilityElementsHidden
      style={[
        styles.avatar,
        {
          width: size,
          height: size,
          borderRadius: size / 2,
          backgroundColor: chat.color,
        },
      ]}
    >
      <Label color="#FFFFFF" style={styles.avatarText} allowFontScaling={false}>
        {chat.initials}
      </Label>
    </View>
  );
}
export function Button({
  label,
  accessibilityLabel = label,
  onPress,
  c,
  disabled = false,
}: {
  label: string;
  accessibilityLabel?: string;
  onPress: () => void;
  c: Palette;
  disabled?: boolean;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      disabled={disabled}
      accessibilityState={{ disabled }}
      onPress={onPress}
      accessibilityLabel={accessibilityLabel}
      style={({ pressed }) => [
        styles.button,
        { backgroundColor: c.raised },
        pressed && styles.pressed,
      ]}
    >
      <Label color={c.accent} style={styles.buttonText}>
        {label}
      </Label>
    </Pressable>
  );
}
export function SettingSwitch({
  label,
  value,
  onChange,
  c,
}: {
  label: string;
  value: boolean;
  onChange: (value: boolean) => void;
  c: Palette;
}) {
  return (
    <View style={[styles.settingRow, { borderBottomColor: c.line }]}>
      <Label color={c.text} style={styles.flex}>
        {label}
      </Label>
      <View style={styles.switchTarget}>
        <Switch
          accessibilityLabel={label}
          value={value}
          onValueChange={onChange}
          trackColor={{ false: c.line, true: c.accent }}
          thumbColor={value ? c.text : c.muted}
        />
      </View>
    </View>
  );
}
export function Stepper({
  label,
  value,
  onMinus,
  onPlus,
  c,
}: {
  label: string;
  value: string;
  onMinus: () => void;
  onPlus: () => void;
  c: Palette;
}) {
  return (
    <View style={[styles.settingRow, { borderBottomColor: c.line }]}>
      <View style={styles.flex}>
        <Label color={c.text}>{label}</Label>
        <Label color={c.muted} style={styles.caption}>
          {value}
        </Label>
      </View>
      <Button
        label="−"
        accessibilityLabel={`Уменьшить: ${label}, сейчас ${value}`}
        onPress={onMinus}
        c={c}
      />
      <Button
        label="+"
        accessibilityLabel={`Увеличить: ${label}, сейчас ${value}`}
        onPress={onPlus}
        c={c}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  text: {
    ...typography.body,
    ...Platform.select({ android: { includeFontPadding: false } }),
  },
  pressed: { opacity: 0.7 },
  iconButton: {
    minWidth: geometry.touchTarget,
    minHeight: geometry.touchTarget,
    borderRadius: geometry.radius,
    alignItems: 'center',
    justifyContent: 'center',
  },
  caption: { ...typography.caption },
  buttonText: { ...typography.button, fontWeight: '600' },
  avatar: { alignItems: 'center', justifyContent: 'center' },
  avatarText: { ...typography.initials, fontWeight: '600' },
  settingRow: {
    minHeight: 60,
    paddingVertical: 8,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
  switchTarget: {
    minWidth: geometry.touchTarget,
    minHeight: geometry.touchTarget,
    alignItems: 'center',
    justifyContent: 'center',
  },
  button: {
    minHeight: geometry.touchTarget,
    minWidth: geometry.touchTarget,
    paddingHorizontal: 12,
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: geometry.radius,
    marginVertical: 4,
  },
});
