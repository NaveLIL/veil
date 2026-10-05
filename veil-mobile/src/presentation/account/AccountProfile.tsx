import React, { useState } from 'react';
import { ScrollView, Text, View } from 'react-native';
import { Shield } from 'lucide-react-native';
import { ProfilePanelFrame } from '../../interfacePreview/ProfilePanelFrame';
import { styles } from '../../interfacePreview/profileStyles';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { SettingsContent } from '../settings/SettingsContent';
import { SETTINGS_SECTIONS } from '../settings/definitions';
import type { SettingsSectionKey } from './routes';
import { useChatStore } from '../../stores/chat';
import { UserAvatar } from '../../components/identity/UserAvatar';

export function AccountProfile({ open, onClose, returnFocus }: {
  open: boolean; onClose: () => void; returnFocus?: number;
}) {
  const { c, reduceMotion } = usePresentation();
  const binding = useChatStore(s => s.runtimeBinding);
  const [tab, setTab] = useState<'profile' | 'settings'>('profile');
  const [sections, setSections] = useState<SettingsSectionKey[]>([]);
  const section = sections[sections.length - 1];
  const back = tab === 'settings' ? () => {
    if (sections.length) setSections(s => s.slice(0, -1)); else setTab('profile');
  } : undefined;
  return <ProfilePanelFrame open={open} onClose={onClose} c={c} reduceMotion={reduceMotion}
    tab={tab} onTab={next => { setTab(next); setSections([]); }}
    title={tab === 'profile' ? 'Ваш профиль' : section ? SETTINGS_SECTIONS.find(s => s.key === section)!.title : 'Настройки приложения'}
    onBack={back} returnFocus={returnFocus}>
    {tab === 'settings' ? <SettingsContent section={section} onSection={next => setSections(s => [...s, next])} /> :
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        <>
          <View style={[styles.banner, { backgroundColor: c.tint }]}>
            <View style={[styles.bannerStripe, { backgroundColor: c.accent }]} />
            <Text style={[styles.bannerBrand, { color: c.accent }]}>VEIL</Text>
          </View>
          <View style={styles.identity}>
            {binding && <UserAvatar canonicalServerOrigin={binding.canonicalServerOrigin} userId={binding.userId}
              technicalUsername={binding.userId} size={64} />}
            <View style={styles.flex}><Text style={[styles.profileName, { color: c.text }]}>Текущий аккаунт</Text>
              <Text style={[styles.caption, { color: c.muted }]}>Идентичность этого устройства</Text></View>
          </View>
          <Text selectable style={[styles.body, { color: c.text }]}>{binding?.userId}</Text>
          <Text selectable style={[styles.caption, { color: c.muted }]}>{binding?.canonicalServerOrigin}</Text>
          <View style={[styles.note, { backgroundColor: c.surface }]}><Shield color={c.accent} size={20} />
            <Text style={[styles.body, styles.flex, { color: c.muted }]}>Имя и аватар — контекст. Проверка ключей собеседника доступна в его профиле; этот экран не подтверждает собственную личность.</Text></View>
        </>
      </ScrollView>}
  </ProfilePanelFrame>;
}
