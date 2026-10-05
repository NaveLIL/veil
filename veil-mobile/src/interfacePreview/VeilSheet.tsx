import React, { useImperativeHandle } from 'react';
import { Animated, Modal, Pressable, StyleSheet, View, ViewStyle, useWindowDimensions } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { geometry, Palette } from './appearance';
import { LiveBlur, useModalBackdrop } from './LiveBlur';
import { useSheetMotion } from './useSheetMotion';

/** Fixed modal window; only the sheet moves. A grip exposes dismiss without a cross. */
export type VeilSheetControls = { dismiss: () => void };
export function VeilSheet({ visible = true, c, reduceMotion, onClose, onShow, onBack, dismissRef,
  closeLabel = 'Закрыть панель', style, children,
}: { visible?: boolean; c: Palette; reduceMotion: boolean; onClose: () => void;
  onShow?: () => void; onBack?: () => void; dismissRef?: React.Ref<VeilSheetControls>; closeLabel?: string; style?: ViewStyle; children: React.ReactNode }) {
  const { height } = useWindowDimensions();
  const sheet = useSheetMotion(visible, reduceMotion, height, onClose);
  useImperativeHandle(dismissRef, () => ({ dismiss: sheet.dismiss }), [sheet.dismiss]);
  const underlayBlur = useModalBackdrop(sheet.presented);
  return <Modal visible={sheet.presented} transparent animationType="none" statusBarTranslucent
    navigationBarTranslucent onRequestClose={() => sheet.back(onBack)} onShow={() => { sheet.onShow(); onShow?.(); }}>
    <SafeAreaView edges={['top']} style={styles.root}>
      <Pressable testID="veil-sheet-outside" accessible={false} importantForAccessibility="no" onPress={sheet.dismiss}
        style={StyleSheet.absoluteFillObject} />
      <Animated.View accessibilityViewIsModal style={[styles.panel, { backgroundColor: c.bg,
        borderColor: c.line }, style, { transform: [{ translateY: sheet.translate }] }]}>
        <LiveBlur blurRadius={underlayBlur} style={style?.height ? styles.flex : undefined}>
        <View {...sheet.panHandlers}>
        <Pressable accessibilityRole="button" accessibilityLabel={closeLabel}
          accessibilityHint="Смахните панель вниз или активируйте, чтобы закрыть"
          accessibilityActions={[{ name: 'dismiss', label: closeLabel }]}
          onAccessibilityAction={sheet.dismiss} onPress={sheet.dismiss} style={styles.handleTouch}>
          <View importantForAccessibility="no-hide-descendants" style={[styles.handle, { backgroundColor: c.muted }]} />
        </Pressable>
        </View>
        {children}
        </LiveBlur>
      </Animated.View>
    </SafeAreaView>
  </Modal>;
}
const styles = StyleSheet.create({
  flex: { flex: 1 },
  root: { flex: 1, justifyContent: 'flex-end' },
  panel: { borderRadius: geometry.radius, borderWidth: geometry.borderWidth, overflow: 'hidden' },
  handleTouch: { height: geometry.touchTarget, alignItems: 'center', justifyContent: 'center' },
  handle: { width: 32, height: 4, borderRadius: 2 },
});
