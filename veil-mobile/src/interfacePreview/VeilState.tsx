import React from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';
import { Palette, geometry, typography } from './appearance';
import { Button } from './Primitives';
import { usePresentation } from './PresentationContext';

export type VeilStateKind = 'empty' | 'loading' | 'unavailable' | 'error' | 'capability' | 'offline';
/** Public presentation facts only; no exceptions, message content or native implementation. */
export function VeilState({ kind, title, detail, c, action, testID }: {
  kind: VeilStateKind; title: string; detail: string; c: Palette; testID?: string;
  action?: { label: string; onPress: () => void; pending?: boolean };
}) {
  const { reduceMotion } = usePresentation();
  return <View testID={testID} style={styles.root} accessibilityLiveRegion={kind === 'empty' ? 'none' : 'polite'}>
    {kind === 'loading' && !reduceMotion && <ActivityIndicator color={c.accent} accessible={false} />}
    <Text accessibilityRole="header" style={[styles.title, { color: c.text }]}>{title}</Text>
    <Text style={[styles.detail, { color: c.muted }]}>{detail}</Text>
    {action && <Button label={action.label} onPress={action.onPress} c={c} disabled={action.pending} />}
  </View>;
}
const styles = StyleSheet.create({
  root: { flexGrow: 1, alignItems: 'center', justifyContent: 'center', padding: 24, gap: 12 },
  title: { ...typography.body, fontWeight: '600', textAlign: 'center' },
  detail: { ...typography.caption, textAlign: 'center', marginBottom: geometry.inset },
});
