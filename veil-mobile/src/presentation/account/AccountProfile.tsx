import React, { useState } from 'react';
import { ScrollView, Text, View } from 'react-native';
import { Shield, Palette as PaletteIcon, Settings2 } from 'lucide-react-native';
import { ProfilePanelFrame } from '../../interfacePreview/ProfilePanelFrame';
import { styles } from '../../interfacePreview/profileStyles';
import { Button } from '../../interfacePreview/Primitives';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { AccountAppearanceSettings } from '../appearance/AccountAppearance';
import { useChatStore } from '../../stores/chat';
import { UserAvatar } from '../../components/identity/UserAvatar';

export function AccountProfile({ open, onClose, onSettings, returnFocus }: {
  open: boolean; onClose: () => void; onSettings: () => void; returnFocus?: number;
}) {
  const { c, reduceMotion } = usePresentation();
  const binding = useChatStore(s => s.runtimeBinding);
  const [tab, setTab] = useState<'profile' | 'settings'>('profile'), [appearance, setAppearance] = useState(false);
  const openSettings = () => { onClose(); onSettings(); };
  return <ProfilePanelFrame open={open} onClose={onClose} c={c} reduceMotion={reduceMotion}
    tab={tab} onTab={next => { setTab(next); setAppearance(false); }}
    title={tab === 'profile' ? 'Ваш профиль' : appearance ? 'Внешний вид' : 'Настройки приложения'}
    onBack={appearance ? () => setAppearance(false) : undefined} returnFocus={returnFocus}>
    {appearance ? <AccountAppearanceSettings onLock={openSettings} onAbout={openSettings} /> :
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        {tab === 'profile' ? <>
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
        </> : <>
          <View style={styles.setting}><PaletteIcon color={c.accent} size={21} />
            <Button label="Внешний вид" c={c} onPress={() => setAppearance(true)} /></View>
          <View style={styles.setting}><Settings2 color={c.accent} size={21} />
            <Button label="Аккаунт и безопасность" c={c} onPress={openSettings} /></View>
          <Text style={[styles.body, { color: c.muted }]}>Оформление хранится локально для этого устройства, отдельно от аккаунта и сервера.</Text>
        </>}
      </ScrollView>}
  </ProfilePanelFrame>;
}
