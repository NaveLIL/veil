import React, { useEffect, useRef } from 'react';
import { Animated, Modal, PanResponder, Pressable, StyleSheet, View, ViewStyle, useWindowDimensions } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { geometry, motion, Palette } from './appearance';
import { LiveBlur, useModalBackdrop } from './LiveBlur';

/** Fixed modal window; only the sheet moves. A grip exposes dismiss without a cross. */
export function VeilSheet({ visible = true, c, reduceMotion, onClose, onShow,
  closeLabel = 'Закрыть панель', style, children,
}: { visible?: boolean; c: Palette; reduceMotion: boolean; onClose: () => void;
  onShow?: () => void; closeLabel?: string; style?: ViewStyle; children: React.ReactNode }) {
  const underlayBlur = useModalBackdrop(visible);
  const { height } = useWindowDimensions();
  const translate = useRef(new Animated.Value(0)).current;
  const closing = useRef(false);
  const delivered = useRef(false);
  const alive = useRef(true), visibleRef = useRef(visible); visibleRef.current = visible;
  const latest = useRef(onClose); latest.current = onClose;
  useEffect(() => { closing.current = false; delivered.current = false; translate.setValue(0); }, [visible, translate]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; translate.stopAnimation(); }; }, [translate]);
  const complete = () => { if (alive.current && visibleRef.current && !delivered.current) { delivered.current = true; latest.current(); } };
  useEffect(() => {
    if (!reduceMotion) return;
    translate.stopAnimation();
    if (closing.current) complete();
    else translate.setValue(0);
    // onClose is read through its current ref; a scope change does not replay dismissal.
  }, [reduceMotion, translate]);
  function dismiss() {
    if (closing.current) return;
    closing.current = true;
    if (reduceMotion) { complete(); return; }
    Animated.timing(translate, { toValue: height, duration: motion.transitionDuration,
      useNativeDriver: true }).start(() => complete());
  }
  function closeImmediately() {
    if (closing.current) return;
    closing.current = true;
    translate.stopAnimation();
    complete();
  }
  const pan = PanResponder.create({
    onMoveShouldSetPanResponder: (_, g) => g.dy > 10 && Math.abs(g.dy) > Math.abs(g.dx),
    onPanResponderMove: (_, g) => translate.setValue(Math.max(0, g.dy)),
    onPanResponderRelease: (_, g) => {
      if (g.dy > 70 || g.vy > 0.6) dismiss();
      else Animated.spring(translate, { toValue: 0, ...motion.spring, useNativeDriver: true }).start();
    },
    onPanResponderTerminate: () => translate.setValue(0),
  });
  return <Modal visible={visible} transparent animationType="none" statusBarTranslucent
    navigationBarTranslucent onRequestClose={closeImmediately} onShow={() => {
      translate.setValue(reduceMotion ? 0 : height);
      if (!reduceMotion) Animated.timing(translate, { toValue: 0,
        duration: motion.transitionDuration, useNativeDriver: true }).start();
      onShow?.();
    }}>
    <SafeAreaView edges={['top']} style={styles.root}>
      <Pressable accessible={false} importantForAccessibility="no" onPress={closeImmediately}
        style={StyleSheet.absoluteFillObject} />
      <Animated.View accessibilityViewIsModal style={[styles.panel, { backgroundColor: c.bg,
        borderColor: c.line }, style, { transform: [{ translateY: translate }] }]}>
        <LiveBlur blurRadius={underlayBlur} style={style?.height ? styles.flex : undefined}>
        <View {...pan.panHandlers}>
        <Pressable accessibilityRole="button" accessibilityLabel={closeLabel}
          accessibilityHint="Смахните панель вниз или активируйте, чтобы закрыть"
          accessibilityActions={[{ name: 'dismiss', label: closeLabel }]}
          onAccessibilityAction={closeImmediately} onPress={closeImmediately} style={styles.handleTouch}>
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
