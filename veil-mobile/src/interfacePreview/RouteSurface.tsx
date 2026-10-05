import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { ArrowLeft } from 'lucide-react-native';
import { geometry, typography } from './appearance';
import { IconButton } from './Primitives';
import { usePresentation } from './PresentationContext';

/** The same island/header language for full-screen secondary routes. No data source. */
export function RouteSurface({ title, subtitle, onBack, background, children, testID }: {
  title: string; subtitle?: string; onBack: () => void; background?: React.ReactNode;
  children: React.ReactNode; testID?: string;
}) {
  const { c } = usePresentation();
  return <View testID={testID} style={[styles.root, { backgroundColor: c.bg }]}>
    {background}
    <SafeAreaView edges={['top', 'bottom', 'left', 'right']} style={styles.safe}>
      <View style={[styles.island, { backgroundColor: c.bg, borderColor: c.line }]}>
        <View style={[styles.header, { borderBottomColor: c.line }]}>
          <IconButton icon={ArrowLeft} label="Назад" color={c.text} onPress={onBack} />
          <View style={styles.meta}>
            <Text accessibilityRole="header" style={[styles.title, { color: c.text }]}>{title}</Text>
            {subtitle && <Text style={[styles.subtitle, { color: c.muted }]}>{subtitle}</Text>}
          </View>
        </View>
        {children}
      </View>
    </SafeAreaView>
  </View>;
}
const styles = StyleSheet.create({
  root: { flex: 1 }, safe: { flex: 1, padding: geometry.inset },
  island: { flex: 1, borderRadius: geometry.radius, borderWidth: geometry.borderWidth, overflow: 'hidden' },
  header: { flexDirection: 'row', alignItems: 'center', padding: geometry.inset, gap: geometry.inset, borderBottomWidth: StyleSheet.hairlineWidth },
  meta: { flex: 1, minWidth: 0, paddingVertical: geometry.inset },
  title: { ...typography.heading, fontWeight: '600' }, subtitle: { ...typography.caption },
});
