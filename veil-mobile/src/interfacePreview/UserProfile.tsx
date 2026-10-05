import React, { useState } from 'react';
import { ProfilePanelFrame } from './ProfilePanelFrame';
import {
  Pressable,
  ScrollView,
  Switch,
  Text,
  TextInput,
  View,
} from 'react-native';
import {
  Bell,
  ChevronRight,
  LockKeyhole,
  MessageCircle,
  Palette as PaletteIcon,
  Settings2,
  Shield,
  Wifi,
} from 'lucide-react-native';
import { styles } from './profileStyles';
import { Palette } from './appearance';

type DemoProfile = { name: string; bio: string };
function Avatar({
  c,
  name,
  large = false,
}: {
  c: Palette;
  name: string;
  large?: boolean;
}) {
  return (
    <View
      importantForAccessibility="no-hide-descendants"
      accessibilityElementsHidden
      style={[
        styles.avatar,
        large && styles.largeAvatar,
        { backgroundColor: c.tint, borderColor: c.accent },
      ]}
    >
      <Text style={[styles.initial, { color: c.accent }]}>
        {name.slice(0, 1).toLocaleUpperCase('ru') || 'В'}
      </Text>
      <View style={[styles.statusDot, { borderColor: c.bg }]} />
    </View>
  );
}
export { FloatingProfile } from './ProfileEntry';
export function ProfilePanel({
  open,
  onClose,
  c,
  reduceMotion,
  profile,
  onProfileChange,
  appearance,
  onLock,
  onAbout,
  onScenarios,
  returnFocus,
}: {
  open: boolean;
  onClose: () => void;
  c: Palette;
  reduceMotion: boolean;
  profile: DemoProfile;
  onProfileChange: (profile: DemoProfile) => void;
  appearance: React.ReactNode;
  onLock: () => void;
  onAbout: () => void;
  onScenarios: () => void;
  returnFocus?: number;
}) {
  const [tab, setTab] = useState<'profile' | 'settings'>('profile');
  const [section, setSection] = useState<
    'all' | 'appearance' | 'security' | 'notifications' | 'network'
  >('all');
  const [editing, setEditing] = useState(false);
  const [quiet, setQuiet] = useState(false);
  function close() {
    setEditing(false);
    onClose();
  }
  const labels = {
    all: 'Настройки приложения',
    appearance: 'Внешний вид',
    security: 'Безопасность',
    notifications: 'Уведомления',
    network: 'Сеть',
  };
  return (
    <ProfilePanelFrame open={open} onClose={close} c={c} reduceMotion={reduceMotion}
      title={tab === 'profile' ? 'Ваш профиль' : labels[section]} tab={tab}
      onTab={(next) => {setTab(next);setSection('all');}}
      onBack={tab === 'settings' && section !== 'all' ? () => setSection('all') : undefined}
      returnFocus={returnFocus}>
          {tab === 'settings' && section === 'appearance' ? (
            <View style={styles.appearance}>{appearance}</View>
          ) : (
            <ScrollView
              keyboardShouldPersistTaps="handled"
              contentContainerStyle={styles.content}
            >
              {tab === 'profile' ? (
                <>
                  <View style={[styles.banner, { backgroundColor: c.tint }]}>
                    <View
                      style={[
                        styles.bannerStripe,
                        { backgroundColor: c.accent },
                      ]}
                    />
                    <Text style={[styles.bannerBrand, { color: c.accent }]}>
                      VEIL
                    </Text>
                  </View>
                  <View style={styles.identity}>
                    <Avatar c={c} name={profile.name} large />
                    <View style={styles.flex}>
                      <Text style={[styles.profileName, { color: c.text }]}>
                        {profile.name}
                      </Text>
                      <Text style={[styles.caption, { color: c.muted }]}>
                        @veil.demo · вымышленный профиль
                      </Text>
                    </View>
                  </View>
                  {editing ? (
                    <>
                      <TextInput
                        accessibilityLabel="Имя демо-профиля"
                        value={profile.name}
                        maxLength={48}
                        onChangeText={(name) =>
                          onProfileChange({ ...profile, name })
                        }
                        placeholder="Имя"
                        placeholderTextColor={c.muted}
                        style={[
                          styles.input,
                          { color: c.text, backgroundColor: c.surface },
                        ]}
                      />
                      <TextInput
                        accessibilityLabel="Описание демо-профиля"
                        value={profile.bio}
                        maxLength={300}
                        multiline
                        onChangeText={(bio) =>
                          onProfileChange({ ...profile, bio })
                        }
                        placeholder="О себе"
                        placeholderTextColor={c.muted}
                        style={[
                          styles.input,
                          { color: c.text, backgroundColor: c.surface },
                        ]}
                      />
                    </>
                  ) : (
                    <Text style={[styles.body, { color: c.muted }]}>
                      {profile.bio}
                    </Text>
                  )}
                  <Row
                    label={editing ? 'Готово' : 'Редактировать демо-профиль'}
                    icon={Settings2}
                    onPress={() => setEditing((v) => !v)}
                    c={c}
                  />
                  <View style={[styles.note, { backgroundColor: c.surface }]}>
                    <Shield size={20} color={c.accent} />
                    <Text
                      style={[styles.body, styles.flex, { color: c.muted }]}
                    >
                      Это локальный вымышленный профиль, без публикации на
                      сервере. Настройки оформления сохраняются отдельно.
                      Проверка личности в настоящем Veil — отдельное сравнение
                      ключей.
                    </Text>
                  </View>
                </>
              ) : section === 'all' ? (
                <>
                  <Row
                    label="Внешний вид"
                    icon={PaletteIcon}
                    onPress={() => setSection('appearance')}
                    c={c}
                  />
                  <Row
                    label="Безопасность"
                    icon={Shield}
                    onPress={() => setSection('security')}
                    c={c}
                  />
                  <Row
                    label="Уведомления"
                    icon={Bell}
                    onPress={() => setSection('notifications')}
                    c={c}
                  />
                  <Row
                    label="Сеть"
                    icon={Wifi}
                    onPress={() => setSection('network')}
                    c={c}
                  />
                  <Row
                    label="Сценарии сообщений"
                    icon={MessageCircle}
                    onPress={onScenarios}
                    c={c}
                  />
                  <Row
                    label="О дизайн-макете"
                    icon={Shield}
                    onPress={onAbout}
                    c={c}
                  />
                </>
              ) : section === 'security' ? (
                <>
                  <Text style={[styles.body, { color: c.muted }]}>
                    Здесь согласуем оформление настроек безопасности. У макета
                    нет настоящего аккаунта, PIN, recovery-фразы или ключей.
                    Защита настоящего Veil настраивается в основном приложении.
                  </Text>
                  <Row
                    label="Посмотреть экран блокировки"
                    icon={LockKeyhole}
                    onPress={onLock}
                    c={c}
                  />
                </>
              ) : section === 'notifications' ? (
                <>
                  <View style={styles.switchRow}>
                    <Text style={[styles.body, styles.flex, { color: c.text }]}>
                      Тихий режим макета
                    </Text>
                    <View style={styles.icon}>
                      <Switch
                        accessibilityLabel="Тихий режим макета"
                        value={quiet}
                        onValueChange={setQuiet}
                        trackColor={{ false: c.line, true: c.accent }}
                      />
                    </View>
                  </View>
                  <Text style={[styles.body, { color: c.muted }]}>
                    Локальный предпросмотр переключателя. Макет не запрашивает
                    системных уведомлений и не подключён к push.
                  </Text>
                </>
              ) : (
                <Text style={[styles.body, { color: c.muted }]}>
                  К серверу мессенджера не подключены. В Live-версии интерфейс
                  приходит с ПК через USB и локальный Metro; офлайн-версия
                  использует встроенный интерфейс.
                </Text>
              )}
              <Text style={[styles.footnote, { color: c.muted }]}>
                Veil Design · настройки макета
              </Text>
            </ScrollView>
          )}
    </ProfilePanelFrame>
  );
}
function Row({
  label,
  icon: Icon,
  onPress,
  c,
}: {
  label: string;
  icon: typeof Shield;
  onPress: () => void;
  c: Palette;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      style={({ pressed }) => [
        styles.setting,
        { backgroundColor: c.surface },
        pressed && styles.pressed,
      ]}
    >
      <Icon size={21} color={c.accent} />
      <Text style={[styles.body, styles.flex, { color: c.text }]}>{label}</Text>
      <ChevronRight size={18} color={c.muted} />
    </Pressable>
  );
}
