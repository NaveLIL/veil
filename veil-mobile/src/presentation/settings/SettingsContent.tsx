import React from 'react';
import { Linking, Pressable, ScrollView, StyleSheet, Switch, Text, View, useWindowDimensions } from 'react-native';
import { ChevronRight } from 'lucide-react-native';
import { geometry, typography } from '../../interfacePreview/appearance';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { useRuntimeGateStore } from '../../stores/runtime';
import { useMobileSettingsStore } from '../../stores/settings';
import { AccountAppearanceSettings } from '../appearance/AccountAppearance';
import type { SettingsSectionKey } from '../account/routes';
import { SETTINGS_SECTIONS, settingsDefinition, type DetailRowProps } from './definitions';

/** One settings tree for the profile sheet and full-screen routes. */
export function SettingsContent({ section, onSection, testID }: {
  section?: SettingsSectionKey; onSection: (section: SettingsSectionKey) => void; testID?: string;
}) {
  const { c } = usePresentation();
  const snapshot = useRuntimeGateStore(s => s.snapshot);
  const allowReadyScreenshots = useMobileSettingsStore(s => s.allowReadyScreenshots);
  const setAllowReadyScreenshots = useMobileSettingsStore(s => s.setAllowReadyScreenshots);
  if (section === 'appearance') return <AccountAppearanceSettings
    onLock={() => onSection('account')} onAbout={() => onSection('about')} />;
  const definition = section ? settingsDefinition(section, snapshot, {
    allowReadyScreenshots, setAllowReadyScreenshots,
    openAndroidSettings: () => { void Linking.openSettings().catch(() => undefined); },
    openProjectWebsite: () => { void Linking.openURL('https://veil.erez.pro').catch(() => undefined); },
  }) : null;
  return <ScrollView testID={testID} keyboardShouldPersistTaps="handled" contentContainerStyle={styles.content}>
    {definition ? definition.groups.map(group => <View key={group.title}
      style={[styles.group, { backgroundColor: c.surface, borderColor: c.line }]}>
      <Text accessibilityRole="header" style={[styles.groupTitle, { color: c.muted }]}>{group.title}</Text>
      {group.rows.map((row, i) => <SettingsFactRow key={row.label} {...row} divided={i > 0} />)}
      {group.note && <Text style={[styles.note, { color: c.muted }]}>{group.note}</Text>}
    </View>) : <>
      <View style={[styles.group, { backgroundColor: c.surface, borderColor: c.line }]}>
        {SETTINGS_SECTIONS.map((item, i) => <Pressable key={item.key} accessibilityRole="button"
          accessibilityLabel={`${item.title}. ${item.summary}`} onPress={() => onSection(item.key)}
          style={({ pressed }) => [styles.section, i > 0 && { borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: c.line }, pressed && styles.pressed]}>
          <View importantForAccessibility="no-hide-descendants" style={[styles.mark, { backgroundColor: c.tint }]}><item.icon size={21} color={c.accent} /></View>
          <View style={styles.meta}><Text style={[styles.name, { color: c.text }]}>{item.title}</Text>
            <Text style={[styles.note, { color: c.muted }]}>{item.summary}</Text></View>
          <ChevronRight accessible={false} color={c.muted} size={20} />
        </Pressable>)}
      </View>
      <Text style={[styles.note, { color: c.muted }]}>Доступны только действия, поддерживаемые текущим native runtime. Остальные возможности обозначены явно.</Text>
    </>}
  </ScrollView>;
}
function SettingsFactRow({ label, value, detail, tone, mono, selectable, onPress,
  switchValue, onSwitchChange, switchDisabled, divided }: DetailRowProps & { divided: boolean }) {
  const { c } = usePresentation(), { fontScale, width } = useWindowDimensions();
  const stacked = fontScale > 1.2 || width < 360 || mono;
  const rowStyle = [styles.row, stacked && styles.stacked, divided && { borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: c.line }];
  const content = <>
    <View style={styles.meta}><Text style={[styles.name, { color: c.text }]}>{label}</Text>
      {detail && <Text style={[styles.note, { color: c.muted }]}>{detail}</Text>}</View>
    {switchValue !== undefined && onSwitchChange ? <View importantForAccessibility="no-hide-descendants">
      <Switch accessible={false} pointerEvents="none" disabled={switchDisabled} value={switchValue}
        trackColor={{ false: c.line, true: c.accent }} thumbColor={c.text} />
    </View> : value && <Text selectable={selectable} style={[styles.value, stacked && styles.stackedValue,
      { color: tone === 'positive' ? c.accent : tone === 'warning' ? c.danger : tone === 'muted' ? c.muted : c.text }, mono && styles.mono]}>{value}</Text>}
    {onPress && <ChevronRight accessible={false} color={c.muted} size={20} />}
  </>;
  if (switchValue !== undefined && onSwitchChange) return <Pressable accessibilityRole="switch"
    accessibilityLabel={label} accessibilityHint={detail} accessibilityState={{ checked: switchValue, disabled: switchDisabled }}
    disabled={switchDisabled} onPress={() => onSwitchChange(!switchValue)}
    style={({ pressed }) => [...rowStyle, pressed && !switchDisabled && styles.pressed]}>{content}</Pressable>;
  if (onPress) return <Pressable accessibilityRole="button" accessibilityLabel={label} accessibilityHint={detail}
    onPress={onPress} style={({ pressed }) => [...rowStyle, pressed && styles.pressed]}>{content}</Pressable>;
  return <View style={rowStyle}>{content}</View>;
}
const styles = StyleSheet.create({
  content: { padding: 12, paddingBottom: 24, gap: 12 }, group: { borderRadius: geometry.radius, borderWidth: geometry.borderWidth, padding: 12 },
  groupTitle: { ...typography.caption, fontWeight: '600', marginBottom: 6 },
  section: { minHeight: geometry.touchTarget, flexDirection: 'row', gap: 12, alignItems: 'center', paddingVertical: 12 },
  mark: { padding: 8, borderRadius: geometry.radius }, meta: { flex: 1, minWidth: 0 }, name: { ...typography.body, fontWeight: '500' }, note: { ...typography.caption, marginTop: 4 },
  row: { minHeight: geometry.touchTarget, flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 12 }, stacked: { flexDirection: 'column', alignItems: 'stretch' },
  value: { ...typography.caption, flexShrink: 1, maxWidth: '46%', textAlign: 'right' }, stackedValue: { maxWidth: '100%', textAlign: 'left' }, mono: { fontFamily: 'monospace' }, pressed: { opacity: 0.7 },
});
