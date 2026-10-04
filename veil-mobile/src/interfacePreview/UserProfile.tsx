import React, { useState } from 'react';
import { Modal, Pressable, ScrollView, StyleSheet, Switch, Text, TextInput, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { ArrowLeft, Bell, ChevronDown, ChevronRight, LockKeyhole, MessageCircle, Palette as PaletteIcon, Settings2, Shield, Wifi, X } from 'lucide-react-native';
import { geometry, Palette } from './appearance';

type DemoProfile = { name: string; bio: string };
function Avatar({ c, name, large = false }: { c: Palette; name: string; large?: boolean }) {
  return <View style={[styles.avatar, large && styles.largeAvatar, { backgroundColor: c.tint, borderColor: c.accent }]}><Text style={[styles.initial, { color: c.accent }]}>{name.slice(0, 1).toLocaleUpperCase('ru') || 'В'}</Text><View style={[styles.statusDot, { borderColor: c.bg }]} /></View>;
}
export function FloatingProfile({ c, profile, onOpen, hasChat, onResume }: { c: Palette; profile: DemoProfile; onOpen: () => void; hasChat: boolean; onResume: () => void }) {
  return <View testID="floating-profile" style={[styles.floating, { backgroundColor: c.surface, borderColor: c.line }]}>
    <Pressable accessibilityRole="button" accessibilityLabel="Раскрыть свой профиль" onPress={onOpen} style={({ pressed }) => [styles.summary, pressed && styles.pressed]}>
      <Avatar c={c} name={profile.name} /><View style={styles.flex}><Text numberOfLines={1} style={[styles.name, { color: c.text }]}>{profile.name}</Text><Text style={[styles.caption, { color: c.muted }]}>Ваш профиль · демо</Text></View><ChevronDown size={18} color={c.muted} />
    </Pressable>
    {hasChat && <Pressable accessibilityRole="button" accessibilityLabel="Вернуться в последний чат" onPress={onResume} style={styles.icon}><MessageCircle size={22} color={c.accent} /></Pressable>}
  </View>;
}
export function ProfilePanel({ open, onClose, c, reduceMotion, profile, onProfileChange, appearance, onLock, onAbout, onScenarios }: {
  open: boolean; onClose: () => void; c: Palette; reduceMotion: boolean; profile: DemoProfile;
  onProfileChange: (profile: DemoProfile) => void; appearance: React.ReactNode; onLock: () => void; onAbout: () => void; onScenarios: () => void;
}) {
  const [tab, setTab] = useState<'profile' | 'settings'>('profile');
  const [section, setSection] = useState<'all' | 'appearance' | 'security' | 'notifications' | 'network'>('all');
  const [editing, setEditing] = useState(false);
  const [quiet, setQuiet] = useState(false);
  function close() { setEditing(false); onClose(); }
  const labels = { all: 'Настройки приложения', appearance: 'Внешний вид', security: 'Безопасность', notifications: 'Уведомления', network: 'Сеть' };
  return <Modal visible={open} transparent animationType={reduceMotion ? 'none' : 'slide'} onRequestClose={close} statusBarTranslucent>
    <View style={styles.modalRoot}><Pressable accessibilityRole="button" accessibilityLabel="Свернуть свой профиль" onPress={close} style={styles.scrim} />
      <SafeAreaView edges={['bottom']} style={[styles.panel, { backgroundColor: c.bg, borderColor: c.line }]}>
        <View style={styles.handleRow}><View style={[styles.handle, { backgroundColor: c.line }]} /></View>
        <View style={styles.panelHeading}>{tab === 'settings' && section !== 'all' && <Pressable accessibilityRole="button" accessibilityLabel="Назад к настройкам профиля" onPress={() => setSection('all')} style={styles.icon}><ArrowLeft size={22} color={c.text} /></Pressable>}<Text style={[styles.title, styles.flex, { color: c.text }]}>{tab === 'profile' ? 'Ваш профиль' : labels[section]}</Text><Pressable accessibilityRole="button" accessibilityLabel="Закрыть свой профиль" onPress={close} style={styles.icon}><X size={22} color={c.muted} /></Pressable></View>
        <View style={[styles.tabs, { borderBottomColor: c.line }]}>{([{ id: 'profile', name: 'Профиль' }, { id: 'settings', name: 'Настройки' }] as const).map(item => <Pressable key={item.id} accessibilityRole="tab" accessibilityLabel={item.name} accessibilityState={{ selected: tab === item.id }} onPress={() => { setTab(item.id); setSection('all'); }} style={[styles.tab, { borderBottomColor: tab === item.id ? c.accent : 'transparent' }]}><Text style={[styles.tabText, { color: tab === item.id ? c.accent : c.muted }]}>{item.name}</Text></Pressable>)}</View>
        {tab === 'settings' && section === 'appearance' ? <View style={styles.appearance}>{appearance}</View> : <ScrollView keyboardShouldPersistTaps="handled" contentContainerStyle={styles.content}>
          {tab === 'profile' ? <>
            <View style={[styles.banner, { backgroundColor: c.tint }]}><View style={[styles.bannerStripe, { backgroundColor: c.accent }]} /><Text style={[styles.bannerBrand, { color: c.accent }]}>VEIL</Text></View>
            <View style={styles.identity}><Avatar c={c} name={profile.name} large /><View style={styles.flex}><Text style={[styles.profileName, { color: c.text }]}>{profile.name}</Text><Text style={[styles.caption, { color: c.muted }]}>@veil.demo · вымышленный профиль</Text></View></View>
            {editing ? <><TextInput accessibilityLabel="Имя демо-профиля" value={profile.name} maxLength={48} onChangeText={name => onProfileChange({ ...profile, name })} placeholder="Имя" placeholderTextColor={c.muted} style={[styles.input, { color: c.text, backgroundColor: c.surface }]} /><TextInput accessibilityLabel="Описание демо-профиля" value={profile.bio} maxLength={300} multiline onChangeText={bio => onProfileChange({ ...profile, bio })} placeholder="О себе" placeholderTextColor={c.muted} style={[styles.input, { color: c.text, backgroundColor: c.surface }]} /></> : <Text style={[styles.body, { color: c.muted }]}>{profile.bio}</Text>}
            <Row label={editing ? 'Готово' : 'Редактировать демо-профиль'} icon={Settings2} onPress={() => setEditing(v => !v)} c={c} />
            <View style={[styles.note, { backgroundColor: c.surface }]}><Shield size={20} color={c.accent} /><Text style={[styles.body, styles.flex, { color: c.muted }]}>Имя, аватар и статус — оформление профиля. Подтверждение личности в Veil основано на сравнении ключей.</Text></View>
          </> : section === 'all' ? <>
            <Row label="Внешний вид" icon={PaletteIcon} onPress={() => setSection('appearance')} c={c} />
            <Row label="Безопасность" icon={Shield} onPress={() => setSection('security')} c={c} />
            <Row label="Уведомления" icon={Bell} onPress={() => setSection('notifications')} c={c} />
            <Row label="Сеть" icon={Wifi} onPress={() => setSection('network')} c={c} />
            <Row label="Сценарии сообщений" icon={MessageCircle} onPress={onScenarios} c={c} />
            <Row label="О дизайн-макете" icon={Shield} onPress={onAbout} c={c} />
          </> : section === 'security' ? <><Text style={[styles.body, { color: c.muted }]}>Здесь согласуем оформление настроек безопасности. У макета нет настоящего аккаунта, PIN, recovery-фразы или ключей. Защита настоящего Veil настраивается в основном приложении.</Text><Row label="Посмотреть экран блокировки" icon={LockKeyhole} onPress={onLock} c={c} /></> : section === 'notifications' ? <><View style={styles.switchRow}><Text style={[styles.body, styles.flex, { color: c.text }]}>Тихий режим макета</Text><View style={styles.icon}><Switch accessibilityLabel="Тихий режим макета" value={quiet} onValueChange={setQuiet} trackColor={{ false: c.line, true: c.accent }} /></View></View><Text style={[styles.body, { color: c.muted }]}>Локальный предпросмотр переключателя. Макет не запрашивает системных уведомлений и не подключён к push.</Text></> : <Text style={[styles.body, { color: c.muted }]}>К серверу мессенджера не подключены. В Live-версии интерфейс приходит с ПК через USB и локальный Metro; офлайн-версия использует встроенный интерфейс.</Text>}
          <Text style={[styles.footnote, { color: c.muted }]}>Veil Design · настройки этой сессии</Text>
        </ScrollView>}
      </SafeAreaView>
    </View>
  </Modal>;
}
function Row({ label, icon: Icon, onPress, c }: { label: string; icon: typeof Shield; onPress: () => void; c: Palette }) {
  return <Pressable accessibilityRole="button" accessibilityLabel={label} onPress={onPress} style={({ pressed }) => [styles.setting, { backgroundColor: c.surface }, pressed && styles.pressed]}><Icon size={21} color={c.accent} /><Text style={[styles.body, styles.flex, { color: c.text }]}>{label}</Text><ChevronRight size={18} color={c.muted} /></Pressable>;
}
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 }, pressed: { opacity: 0.7 }, floating: { position: 'absolute', bottom: 8, left: 8, right: 8, minHeight: 72, borderRadius: geometry.radius, borderWidth: 1, flexDirection: 'row', alignItems: 'center', padding: 6, elevation: 18, shadowColor: '#000', shadowOpacity: 0.3, shadowRadius: 14, shadowOffset: { width: 0, height: 6 } }, summary: { flex: 1, minHeight: 58, flexDirection: 'row', alignItems: 'center', gap: 12, paddingHorizontal: 8 }, avatar: { width: 44, height: 44, borderRadius: geometry.radius, borderWidth: 1, alignItems: 'center', justifyContent: 'center' }, largeAvatar: { width: 64, height: 64, borderRadius: geometry.radius }, initial: { fontSize: 20, fontWeight: '600' }, statusDot: { position: 'absolute', width: 12, height: 12, borderRadius: 6, backgroundColor: '#64748B', bottom: -2, right: -2, borderWidth: 2 }, name: { fontSize: 15, fontWeight: '600', lineHeight: 23 }, caption: { fontSize: 11, lineHeight: 18 }, icon: { minWidth: 48, minHeight: 48, alignItems: 'center', justifyContent: 'center' },
  modalRoot: { flex: 1, justifyContent: 'flex-end' }, scrim: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.6)' }, panel: { height: '86%', borderTopLeftRadius: geometry.radius, borderTopRightRadius: geometry.radius, borderWidth: 1, overflow: 'hidden' }, handleRow: { height: 18, alignItems: 'center', justifyContent: 'center' }, handle: { width: 32, height: 4, borderRadius: 2 }, panelHeading: { flexDirection: 'row', alignItems: 'center', paddingLeft: 20, paddingRight: 8, minHeight: 48 }, title: { fontSize: 20, lineHeight: 28, fontWeight: '600' }, tabs: { flexDirection: 'row', gap: 20, paddingHorizontal: 20, borderBottomWidth: StyleSheet.hairlineWidth }, tab: { minWidth: 48, minHeight: 48, borderBottomWidth: 2, justifyContent: 'center' }, tabText: { fontSize: 14, lineHeight: 22, fontWeight: '600' }, content: { padding: 18, paddingBottom: 30 }, appearance: { flex: 1 }, banner: { height: 100, borderRadius: geometry.radius, overflow: 'hidden', justifyContent: 'center', paddingHorizontal: 24 }, bannerStripe: { position: 'absolute', width: 220, height: 180, opacity: 0.12, right: -50, transform: [{ rotate: '-35deg' }] }, bannerBrand: { letterSpacing: 5, fontWeight: '600', fontSize: 17 }, identity: { marginTop: 16, gap: 14, flexDirection: 'row', alignItems: 'center', marginBottom: 8 }, profileName: { fontSize: 21, lineHeight: 28, fontWeight: '600' }, body: { fontSize: 14, lineHeight: 23, marginVertical: 8 }, input: { minHeight: 48, padding: 14, borderRadius: geometry.radius, fontSize: 16, marginVertical: 6 }, setting: { minHeight: 60, paddingHorizontal: 14, paddingVertical: 6, borderRadius: geometry.radius, flexDirection: 'row', alignItems: 'center', gap: 12, marginBottom: 10 }, note: { flexDirection: 'row', alignItems: 'flex-start', gap: 12, padding: 16, borderRadius: geometry.radius, marginTop: 12 }, footnote: { fontSize: 10, lineHeight: 18, textAlign: 'center', paddingTop: 20 }, switchRow: { flexDirection: 'row', gap: 12, alignItems: 'center' },
});
