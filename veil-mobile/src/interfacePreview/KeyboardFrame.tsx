import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Keyboard,
  KeyboardAvoidingView,
  KeyboardMetrics,
  Platform,
  StyleSheet,
  View,
} from 'react-native';

/** One keyboard owner around the full viewport. Native resize is accounted for by measurement. */
export function KeyboardFrame({ children }: { children: React.ReactNode }) {
  return Platform.OS === 'ios' ? (
    <KeyboardAvoidingView behavior="padding" style={styles.root}>
      {children}
    </KeyboardAvoidingView>
  ) : (
    <AndroidKeyboardFrame>{children}</AndroidKeyboardFrame>
  );
}
function AndroidKeyboardFrame({ children }: { children: React.ReactNode }) {
  const frame = useRef<View>(null);
  const keyboard = useRef<KeyboardMetrics | undefined>(
    Keyboard.isVisible() ? Keyboard.metrics() : undefined,
  );
  const mounted = useRef(true);
  const [bottom, setBottom] = useState(0);
  const measure = useCallback(() => {
    frame.current?.measure((_x, _y, _width, height, _pageX, pageY) => {
      if (!mounted.current) return;
      // Read current metrics inside the callback: a late measurement cannot reopen a hidden keyboard.
      const metrics = keyboard.current;
      // measureInWindow subtracts Android's visible-window inset, whereas keyboard screenY does not.
      setBottom(metrics ? Math.max(0, pageY + height - metrics.screenY) : 0);
    });
  }, []);
  useEffect(() => {
    mounted.current = true;
    const show = Keyboard.addListener('keyboardDidShow', (event) => {
      keyboard.current = event.endCoordinates;
      measure();
    });
    // Android hide coordinates may still exclude the navigation bar. Hide means exactly zero overlap.
    const hide = Keyboard.addListener('keyboardDidHide', () => {
      keyboard.current = undefined;
      setBottom(0);
    });
    return () => {
      mounted.current = false;
      show.remove();
      hide.remove();
    };
  }, [measure]);
  return (
    <View
      ref={frame}
      collapsable={false}
      onLayout={measure}
      style={[styles.root, { paddingBottom: bottom }]}
    >
      {children}
    </View>
  );
}
const styles = StyleSheet.create({ root: { flex: 1 } });
