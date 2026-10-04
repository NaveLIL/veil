import React from 'react';
import { Animated, StyleSheet, View } from 'react-native';
import { LockKeyhole } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { Button, Label } from './Primitives';
type Props = {
  c: Palette;
  animatedStyle: React.ComponentProps<typeof Animated.View>['style'];
  onClose: () => void;
};
export function LockPreview({ c, animatedStyle, onClose }: Props) {
  return (
    <Animated.View style={[styles.lockScreen, animatedStyle]}>
      <View
        style={[
          styles.lockCard,
          { backgroundColor: c.bg, borderColor: c.line },
        ]}
      >
        <View style={[styles.logo, { backgroundColor: c.tint }]}>
          <Label color={c.accent} style={styles.logoMark}>
            Ⅵ
          </Label>
        </View>
        <Label color={c.text} style={styles.lockBrand}>
          VEIL
        </Label>
        <LockKeyhole size={18} color={c.muted} />
        <Label color={c.muted} style={styles.centered}>
          Предпросмотр блокировки
        </Label>
        <View style={[styles.pinPreview, { borderColor: c.line }]}>
          <Label color={c.muted}>● ● ● ● ● ●</Label>
        </View>
        <View style={styles.keypad}>
          {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((key) => (
            <View
              key={key}
              accessible={false}
              style={[styles.key, { backgroundColor: c.surface }]}
            >
              <Label color={c.text} style={styles.keyText}>
                {key}
              </Label>
            </View>
          ))}
        </View>
        <Button label="Вернуться в макет" onPress={onClose} c={c} />
        <Label color={c.muted} style={styles.smallCentered}>
          Демо · PIN не требуется
        </Label>
      </View>
    </Animated.View>
  );
}
const styles = StyleSheet.create({
  lockScreen: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  lockCard: {
    width: 270,
    borderRadius: geometry.radius,
    borderWidth: 1,
    padding: 22,
    alignItems: 'center',
    gap: 10,
  },
  logo: {
    width: geometry.touchTarget,
    height: geometry.touchTarget,
    borderRadius: geometry.radius,
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoMark: { fontSize: 24, lineHeight: 30, fontWeight: '700' },
  lockBrand: {
    fontSize: 17,
    lineHeight: 24,
    fontWeight: '600',
    letterSpacing: 3,
  },
  centered: { textAlign: 'center', fontSize: 13, lineHeight: 21 },
  pinPreview: {
    width: '100%',
    minHeight: geometry.touchTarget,
    borderWidth: 1,
    borderRadius: geometry.radius,
    alignItems: 'center',
    justifyContent: 'center',
  },
  keypad: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    justifyContent: 'center',
    width: 200,
  },
  key: {
    width: 56,
    height: geometry.touchTarget,
    borderRadius: geometry.radius,
    alignItems: 'center',
    justifyContent: 'center',
  },
  keyText: { fontSize: 17 },
  smallCentered: {
    ...typography.micro,
    textAlign: 'center',
    paddingTop: 6,
  },
});
