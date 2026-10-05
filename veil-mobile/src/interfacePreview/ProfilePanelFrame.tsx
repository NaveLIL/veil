import React, { useEffect } from 'react';
import { AccessibilityInfo, Pressable, Text, View } from 'react-native';
import { ArrowLeft } from 'lucide-react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Palette } from './appearance';
import { styles } from './profileStyles';
import { VeilSheet } from './VeilSheet';
import { useModalAccessibility } from './useModalAccessibility';

export function ProfilePanelFrame({ open, onClose, c, reduceMotion, title, tab, onTab,
  onBack, returnFocus, children }: { open: boolean; onClose: () => void; c: Palette;
  reduceMotion: boolean; title: string; tab: 'profile' | 'settings';
  onTab: (tab: 'profile' | 'settings') => void; onBack?: () => void;
  returnFocus?: number; children: React.ReactNode }) {
  const focus = useModalAccessibility(open, returnFocus);
  useEffect(() => { if (open && focus.heading.current) AccessibilityInfo.sendAccessibilityEvent(focus.heading.current, 'focus'); }, [open, title, focus.heading]);
  return <VeilSheet visible={open} c={c} reduceMotion={reduceMotion} onClose={onClose}
    onBack={onBack}
    onShow={focus.onShow} closeLabel="Закрыть свой профиль" style={{ height: '86%' }}>
    <SafeAreaView edges={['bottom']} style={{ flex: 1, backgroundColor: c.bg }}>
      <View style={styles.panelHeading}>
        {onBack && <Pressable accessibilityRole="button" accessibilityLabel="Назад к настройкам профиля"
          onPress={onBack} style={styles.icon}><ArrowLeft color={c.text} size={22} /></Pressable>}
        <Text ref={focus.heading} accessible accessibilityRole="header"
          style={[styles.title, styles.flex, { color: c.text }]}>{title}</Text>
      </View>
      <View style={[styles.tabs, { borderBottomColor: c.line }]}>
        {([{ id: 'profile', name: 'Профиль' }, { id: 'settings', name: 'Настройки' }] as const).map(item =>
          <Pressable key={item.id} accessibilityRole="tab" accessibilityLabel={item.name}
            accessibilityState={{ selected: tab === item.id }} onPress={() => onTab(item.id)}
            style={[styles.tab, { borderBottomColor: tab === item.id ? c.accent : 'transparent' }]}>
            <Text style={[styles.tabText, { color: tab === item.id ? c.accent : c.muted }]}>{item.name}</Text>
          </Pressable>)}
      </View>
      {children}
    </SafeAreaView>
  </VeilSheet>;
}
