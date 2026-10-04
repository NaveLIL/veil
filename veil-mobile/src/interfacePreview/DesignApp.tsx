/**
 * Veil Design: independent, offline UI workbench, not an authenticated client.
 * Controlled composer pattern follows our MIT Rocket.Chat adaptation; no Rocket
 * transport, stores or account logic. Upstream notice is available in About.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { BackHandler, FlatList, KeyboardAvoidingView, Modal, Platform, Pressable, ScrollView, StatusBar, StyleSheet, Text, TextInput, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { ArrowLeft, ArrowUp, Check, ChevronRight, CircleAlert, Clock3, FlaskConical, Info, Layers3, MessageCircle, MoreHorizontal, Pin, Plus, Search, Settings2, Shield, Users, WifiOff, X } from 'lucide-react-native';
import { ROCKET_CHAT_MIT_NOTICE } from '../presentation/rocketChat/notice';
import { createDemoSession, DemoChat, DemoMessage, openChat, retryDemo, Scenario, sendDemo, setDraft, visibleChats } from './model';

const dark = { bg: '#101116', surface: '#191A22', raised: '#22232D', line: '#2E303D', text: '#F3F2F8', muted: '#A6A7B7', accent: '#C6B5FF', tint: '#30284A', own: '#3B305B', warning: '#F0C98D', danger: '#F2A8AE' };
const light: typeof dark = { bg: '#F8F7FC', surface: '#FFFFFF', raised: '#EFEDF5', line: '#DEDCE9', text: '#252233', muted: '#696579', accent: '#6340AA', tint: '#EBE3FA', own: '#E8DDF9', warning: '#77531D', danger: '#A23745' };
type Palette = typeof dark;
type Tab = 'chats' | 'groups' | 'spaces' | 'settings';
type Sheet = 'profile' | 'scenarios' | 'about' | 'message' | null;
type IconComponent = typeof Search;
const scenarioNames: Record<Scenario, string> = { normal: 'Обычный чат', offline: 'Нет связи', failure: 'Ошибка отправки', unknown: 'Статус неизвестен', identityChanged: 'Ключ изменился' };

function Label({ children, color, style, ...props }: React.ComponentProps<typeof Text> & { color?: string }) {
  return <Text {...props} style={[styles.text, color ? { color } : undefined, style]}>{children}</Text>;
}
function IconButton({ icon: Icon, label, onPress, color, background }: { icon: IconComponent; label: string; onPress: () => void; color: string; background?: string }) {
  return <Pressable onPress={onPress} accessibilityRole="button" accessibilityLabel={label} style={({ pressed }) => [styles.iconButton, { backgroundColor: background }, pressed && styles.pressed]}><Icon size={23} color={color} strokeWidth={1.8} /></Pressable>;
}
function Avatar({ chat, small = false }: { chat: DemoChat; small?: boolean }) {
  return <View accessible={false} style={[styles.avatar, small && styles.smallAvatar, { backgroundColor: chat.color }]}><Label color="#FFFFFF" style={small ? styles.avatarSmallText : styles.avatarText}>{chat.initials}</Label></View>;
}
function Chip({ label, selected, onPress, c }: { label: string; selected: boolean; onPress: () => void; c: Palette }) {
  return <Pressable accessibilityRole="button" accessibilityState={{ selected }} onPress={onPress} style={({ pressed }) => [styles.chip, { backgroundColor: selected ? c.tint : c.surface, borderColor: selected ? c.accent : c.line }, pressed && styles.pressed]}><Label color={selected ? c.accent : c.muted} style={styles.chipText}>{label}</Label></Pressable>;
}

export function DesignApp() {
  return <SafeAreaProvider><Workbench /></SafeAreaProvider>;
}
function Workbench() {
  const [session, setSession] = useState(createDemoSession);
  const [tab, setTab] = useState<Tab>('chats');
  const [chatId, setChatId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [sheet, setSheet] = useState<Sheet>(null);
  const [message, setMessage] = useState<DemoMessage | null>(null);
  const [lightTheme, setLightTheme] = useState(false);
  const [newChat, setNewChat] = useState(false);
  const c = lightTheme ? light : dark;
  const chat = session.chats.find(item => item.id === chatId);
  const messagesRef = useRef<FlatList<DemoMessage>>(null);
  const searchRef = useRef<TextInput>(null);
  const atEnd = useRef(true);
  const searchResults = visibleChats(session, query, newChat ? false : unreadOnly);

  const back = useCallback(() => {
    if (sheet) { setSheet(null); return true; }
    if (chatId) { setChatId(null); return true; }
    if (newChat) { setNewChat(false); setQuery(''); return true; }
    if (tab !== 'chats') { setTab('chats'); return true; }
    return false;
  }, [sheet, chatId, newChat, tab]);
  useEffect(() => {
    const subscription = BackHandler.addEventListener('hardwareBackPress', back);
    return () => subscription.remove();
  }, [back]);
  function enterChat(id: string) {
    atEnd.current = true;
    setSession(s => openChat(s, id));
    setChatId(id);
  }
  function send() {
    if (!chat) return;
    const now = new Date();
    const time = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    atEnd.current = true;
    setSession(s => sendDemo(s, chat.id, time));
  }
  const sendBlocked = session.scenario === 'identityChanged';

  return <SafeAreaView edges={['top', 'bottom']} style={[styles.root, { backgroundColor: c.bg }]}>
    <StatusBar barStyle={lightTheme ? 'dark-content' : 'light-content'} backgroundColor="transparent" />
    {chat ? <>
      <View style={[styles.chatHeader, { borderBottomColor: c.line }]}>
        <IconButton icon={ArrowLeft} label="Назад к чатам" onPress={() => setChatId(null)} color={c.text} />
        <Pressable onPress={() => setSheet('profile')} accessibilityRole="button" accessibilityLabel={`Профиль: ${chat.name}`} style={styles.peerHeader}>
          <Avatar chat={chat} small />
          <View style={styles.peerTitle}><Label color={c.text} style={styles.peerName} numberOfLines={1}>{chat.name}</Label><Label color={c.muted} style={styles.caption}>Личный чат · демо</Label></View>
        </Pressable>
        <IconButton icon={MoreHorizontal} label="Состояния и настройки макета" onPress={() => setSheet('scenarios')} color={c.muted} />
      </View>
      <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        {session.scenario !== 'normal' && <View style={[styles.stateBanner, { backgroundColor: c.tint }]}>
          {session.scenario === 'offline' ? <WifiOff size={19} color={c.warning} /> : session.scenario === 'identityChanged' ? <Shield size={19} color={c.warning} /> : <CircleAlert size={19} color={c.danger} />}
          <Label color={session.scenario === 'failure' ? c.danger : c.warning} style={styles.bannerText}>{session.scenario === 'offline' ? 'Демо: сообщения останутся в очереди' : session.scenario === 'identityChanged' ? 'Демо: ключ изменился. Отправка приостановлена.' : session.scenario === 'unknown' ? 'Демо: подтверждение отправки недоступно' : 'Демо: следующая отправка завершится ошибкой'}</Label>
        </View>}
        <FlatList ref={messagesRef} key={chat.id} data={chat.messages} keyExtractor={m => m.id} style={styles.flex}
          contentContainerStyle={styles.messageList} keyboardShouldPersistTaps="handled" keyboardDismissMode="on-drag"
          onScroll={e => { const { layoutMeasurement, contentOffset, contentSize } = e.nativeEvent; atEnd.current = contentSize.height - contentOffset.y - layoutMeasurement.height < 100; }} scrollEventThrottle={100}
          onContentSizeChange={() => { if (atEnd.current) messagesRef.current?.scrollToEnd({ animated: false }); }}
          ListHeaderComponent={<View style={styles.conversationIntro}><Label color={c.muted} style={styles.date}>Сегодня</Label><View style={[styles.demoNote, { borderColor: c.line }]}><FlaskConical size={15} color={c.muted} /><Label color={c.muted} style={styles.note}>Вымышленная переписка. Без подключения к серверу.</Label></View></View>}
          ListEmptyComponent={<View style={styles.emptyChat}><Avatar chat={chat} /><Label color={c.text} style={styles.emptyTitle}>Начните разговор</Label><Label color={c.muted} style={styles.emptyText}>Напишите первое сообщение, чтобы проверить поле ввода и расположение элементов.</Label></View>}
          renderItem={({ item }) => <MessageBubble item={item} c={c} onLongPress={() => { setMessage(item); setSheet('message'); }} onRetry={() => setSession(s => retryDemo(s, chat.id, item.id))} />}
        />
        <View style={[styles.composerArea, { borderTopColor: c.line, backgroundColor: c.bg }]}>
          <View style={[styles.composer, { backgroundColor: c.surface, borderColor: c.line }]}>
            <TextInput testID="preview-composer" accessibilityLabel="Текст демо-сообщения" value={session.drafts[chat.id] ?? ''} onChangeText={text => setSession(s => setDraft(s, chat.id, text))}
              placeholder={sendBlocked ? 'Отправка приостановлена' : 'Сообщение'} placeholderTextColor={c.muted} editable={!sendBlocked} multiline maxLength={4000}
              style={[styles.composerInput, { color: c.text }]} underlineColorAndroid="transparent" keyboardAppearance={lightTheme ? 'light' : 'dark'} />
            <Pressable onPress={send} disabled={sendBlocked || !(session.drafts[chat.id] ?? '').trim()} accessibilityRole="button" accessibilityLabel="Добавить демо-сообщение" accessibilityState={{ disabled: sendBlocked || !(session.drafts[chat.id] ?? '').trim() }}
              style={({ pressed }) => [styles.sendButton, { backgroundColor: c.accent }, (sendBlocked || !(session.drafts[chat.id] ?? '').trim()) && styles.disabled, pressed && styles.pressed]}><ArrowUp size={23} color={lightTheme ? '#FFFFFF' : '#211A32'} /></Pressable>
          </View>
          <Label color={c.muted} style={styles.composerHint}>Только на этом экране · данные исчезнут после перезапуска</Label>
        </View>
      </KeyboardAvoidingView>
    </> : <>
      <View style={styles.brandRow}><View style={styles.brandLockup}><Label color={c.text} style={styles.brand}>veil</Label><View style={[styles.designBadge, { backgroundColor: c.tint }]}><Label color={c.accent} style={styles.badgeText}>DESIGN 01</Label></View></View><IconButton icon={Info} label="О дизайн-превью" color={c.muted} onPress={() => setSheet('about')} /></View>
      {tab === 'chats' ? <>
        <View style={styles.headingRow}>{newChat && <IconButton icon={ArrowLeft} label="Закрыть новый чат" color={c.text} onPress={() => { setNewChat(false); setQuery(''); }} />}<View style={styles.flex}><Label color={c.text} style={styles.title}>{newChat ? 'Новый разговор' : 'Личные чаты'}</Label><Label color={c.muted} style={styles.subtitle}>{newChat ? 'Выберите демо-контакт' : 'Ближе к тем, кто важен'}</Label></View>{!newChat && <IconButton icon={Plus} label="Начать новый демо-чат" background={c.tint} color={c.accent} onPress={() => { setNewChat(true); setQuery(''); searchRef.current?.focus(); }} />}</View>
        <View style={[styles.searchBox, { backgroundColor: c.surface, borderColor: c.line }]}><Search size={20} color={c.muted} /><TextInput ref={searchRef} value={query} onChangeText={setQuery} accessibilityLabel="Найти демо-чат по имени или username" placeholder={newChat ? 'Имя или username' : 'Поиск по чатам'} placeholderTextColor={c.muted} style={[styles.searchInput, { color: c.text }]} autoCorrect={false} />{query.length > 0 && <IconButton icon={X} label="Очистить поиск" color={c.muted} onPress={() => setQuery('')} />}</View>
        {!newChat && <View style={[styles.filters, { paddingHorizontal: 20 }]}><Chip label="Все" selected={!unreadOnly} onPress={() => setUnreadOnly(false)} c={c} /><Chip label="Непрочитанные" selected={unreadOnly} onPress={() => setUnreadOnly(true)} c={c} /></View>}
        <FlatList data={searchResults} keyExtractor={item => item.id} contentContainerStyle={styles.chatList} keyboardShouldPersistTaps="handled" keyboardDismissMode="on-drag"
          ListHeaderComponent={<Label color={c.muted} style={styles.sectionLabel}>{query ? 'РЕЗУЛЬТАТЫ ПОИСКА' : newChat ? 'ДЕМО-КОНТАКТЫ' : unreadOnly ? 'ЖДУТ ВАШЕГО ВНИМАНИЯ' : 'ВАШИ РАЗГОВОРЫ'}</Label>}
          ListEmptyComponent={<View style={styles.emptyState}><Search size={32} color={c.muted} /><Label color={c.text} style={styles.emptyTitle}>{query ? 'Ничего не нашлось' : 'Всё прочитано'}</Label><Label color={c.muted} style={styles.emptyText}>{query ? 'Попробуйте другое имя или username.' : 'Новые сообщения появятся здесь.'}</Label></View>}
          renderItem={({ item }) => {
            const latest = item.messages[item.messages.length - 1];
            const draft = session.drafts[item.id];
            return <Pressable onPress={() => enterChat(item.id)} accessibilityRole="button" accessibilityLabel={`${item.name}${item.unread ? `, непрочитанных: ${item.unread}` : ''}${draft ? ', есть черновик' : ''}`} style={({ pressed }) => [styles.chatRow, { borderBottomColor: c.line }, pressed && { backgroundColor: c.surface }]}>
              <Avatar chat={item} />
              <View style={styles.chatRowBody}><View style={styles.rowTitle}><Label color={c.text} numberOfLines={1} style={styles.chatName}>{item.name}</Label><Label color={item.unread ? c.accent : c.muted} style={styles.time}>{latest?.time ?? ''}</Label></View><View style={styles.rowTitle}><Label color={draft ? c.accent : c.muted} numberOfLines={2} style={styles.previewText}>{draft ? `Черновик: ${draft}` : latest ? `${latest.own ? 'Вы: ' : ''}${latest.text}` : 'Начните разговор'}</Label>{item.unread > 0 ? <View style={[styles.unreadBadge, { backgroundColor: c.accent }]}><Label color={lightTheme ? '#FFFFFF' : '#211A32'} style={styles.unreadText}>{item.unread}</Label></View> : item.pinned ? <Pin size={14} color={c.muted} /> : null}</View></View>
            </Pressable>;
          }}
          ListFooterComponent={<View style={styles.listFooter}><FlaskConical size={15} color={c.muted} /><Label color={c.muted} style={styles.note}>Демо-данные · скриншоты разрешены</Label></View>}
        />
      </> : tab === 'settings' ? <ScrollView contentContainerStyle={styles.settingsContent}>
        <Label color={c.text} style={styles.title}>Настройки макета</Label><Label color={c.muted} style={styles.subtitle}>Проверяем удобство, прежде чем подключать настоящий аккаунт.</Label>
        <Label color={c.muted} style={styles.sectionLabel}>ВНЕШНИЙ ВИД</Label><View style={styles.filters}><Chip label="Тёмный" selected={!lightTheme} onPress={() => setLightTheme(false)} c={c} /><Chip label="Светлый" selected={lightTheme} onPress={() => setLightTheme(true)} c={c} /></View>
        <ScenarioPicker value={session.scenario} onChange={scenario => setSession(s => ({ ...s, scenario }))} c={c} />
        <View style={[styles.card, { backgroundColor: c.surface, borderColor: c.line }]}><Label color={c.text} style={styles.cardTitle}>Шрифт и доступность</Label><Label color={c.muted} style={styles.body}>Размер текста следует настройкам Android. Проверьте макет с увеличенным шрифтом и TalkBack.</Label></View>
        <View style={[styles.card, { backgroundColor: c.surface, borderColor: c.line }]}><Label color={c.text} style={styles.cardTitle}>Это отдельное приложение</Label><Label color={c.muted} style={styles.body}>Здесь нет регистрации, Access Pass и настоящих сообщений. Сеть отключена. Ваш обычный Veil работает отдельно.</Label></View>
        <Pressable accessibilityRole="button" onPress={() => { setSession(createDemoSession()); setQuery(''); setUnreadOnly(false); }} style={[styles.resetButton, { borderColor: c.line }]}><Label color={c.muted}>Сбросить демо-переписку</Label></Pressable>
      </ScrollView> : <FutureSection tab={tab} c={c} />}
      <View style={[styles.navigation, { borderTopColor: c.line, backgroundColor: c.bg }]}>
        {([{ id: 'chats', label: 'Чаты', icon: MessageCircle }, { id: 'groups', label: 'Группы', icon: Users }, { id: 'spaces', label: 'Пространства', icon: Layers3 }, { id: 'settings', label: 'Настройки', icon: Settings2 }] as const).map(item => <Pressable key={item.id} accessibilityRole="tab" accessibilityLabel={item.label} accessibilityState={{ selected: tab === item.id }} onPress={() => { setTab(item.id); setNewChat(false); }} style={styles.navItem}><View style={[styles.navIcon, tab === item.id && { backgroundColor: c.tint }]}><item.icon size={22} color={tab === item.id ? c.accent : c.muted} strokeWidth={1.8} /></View><Label color={tab === item.id ? c.accent : c.muted} style={styles.navLabel}>{item.label}</Label></Pressable>)}
      </View>
    </>}
    <Modal visible={sheet !== null} transparent animationType="slide" onRequestClose={() => setSheet(null)} statusBarTranslucent>
      <View style={styles.modalRoot}><Pressable accessibilityRole="button" accessibilityLabel="Закрыть панель" onPress={() => setSheet(null)} style={styles.scrim} /><SafeAreaView edges={['bottom']} style={[styles.sheet, { backgroundColor: c.surface }]}><View style={styles.sheetHeading}><Label color={c.text} style={styles.cardTitle}>{sheet === 'profile' ? 'О собеседнике' : sheet === 'scenarios' ? 'Проверка состояний' : sheet === 'message' ? 'Демо-сообщение' : 'Veil Design'}</Label><IconButton icon={X} label="Закрыть" color={c.muted} onPress={() => setSheet(null)} /></View><ScrollView contentContainerStyle={styles.sheetContent}>
        {sheet === 'profile' && chat ? <><View style={styles.profileIntro}><Avatar chat={chat} /><Label color={c.text} style={styles.emptyTitle}>{chat.name}</Label><Label color={c.muted}>@{chat.username}</Label></View><View style={[styles.card, { backgroundColor: c.bg, borderColor: c.line }]}><Shield size={24} color={c.accent} /><Label color={c.text} style={styles.cardTitle}>Личность не сравнивалась</Label><Label color={c.muted} style={styles.body}>В настоящем Veil доверие подтверждается сравнением ключей. Имя и аватар не являются доказательством личности.</Label></View><Label color={c.muted} style={styles.body}>В этом превью нет ключей и проверки безопасности: собеседник вымышленный.</Label></> : sheet === 'scenarios' ? <><ScenarioPicker value={session.scenario} onChange={scenario => setSession(s => ({ ...s, scenario }))} c={c} /><View style={styles.filters}><Chip label="Тёмный" selected={!lightTheme} onPress={() => setLightTheme(false)} c={c} /><Chip label="Светлый" selected={lightTheme} onPress={() => setLightTheme(true)} c={c} /></View><Label color={c.muted} style={styles.body}>Сценарий влияет на новые демо-сообщения. Он не меняет уже показанные статусы.</Label></> : sheet === 'message' && message ? <><Label color={c.text} style={styles.body}>{message.text}</Label><Label color={c.muted} style={styles.body}>Ответы на конкретное сообщение, редактирование и удаление добавим после поддержки этих действий в мобильном контракте.</Label><Label color={c.muted} style={styles.caption}>Нажатие и удержание пока открывает эту панель.</Label></> : <><Label color={c.text} style={styles.emptyTitle}>Сначала — хороший разговор.</Label><Label color={c.muted} style={styles.body}>Рабочий макет личных чатов для совместной проработки интерфейса. Без регистрации, без сервера и без доступа к данным обычного Veil. Все имена и сообщения вымышлены.</Label><Label color={c.muted} style={styles.body}>Можно делать скриншоты. Демо-переписка хранится в памяти процесса и исчезает после его перезапуска.</Label><Label color={c.muted} style={styles.body}>Veil © NaveLIL · AGPL-3.0-or-later. Composer pattern adapted from Rocket.Chat.ReactNative 4.77.0.</Label><Label color={c.muted} style={styles.license}>{ROCKET_CHAT_MIT_NOTICE}</Label></>}
      </ScrollView></SafeAreaView></View>
    </Modal>
  </SafeAreaView>;
}

function MessageBubble({ item, c, onLongPress, onRetry }: { item: DemoMessage; c: Palette; onLongPress: () => void; onRetry: () => void }) {
  const status = item.delivery === 'queued' ? 'В очереди' : item.delivery === 'failed' ? 'Не отправлено' : item.delivery === 'unknown' ? 'Статус неизвестен' : item.delivery === 'accepted' ? 'Отправлено' : '';
  return <View style={[styles.messageRow, item.own && styles.ownRow]}>
    <View style={[styles.bubble, { backgroundColor: item.own ? c.own : c.surface }, item.own ? styles.ownBubble : styles.peerBubble]}>
      <Pressable accessibilityRole="button" accessibilityLabel={`${item.own ? 'Вы' : 'Собеседник'}: ${item.text}. ${item.time}. ${status}. Нажмите для подробностей.`} onPress={onLongPress} onLongPress={onLongPress} style={styles.messageTap}>
        <Label color={c.text} style={styles.messageText}>{item.text}</Label>
        <View style={styles.messageMeta}>
          <Label color={item.delivery === 'failed' ? c.danger : c.muted} style={styles.messageTime}>{item.time}{item.delivery && item.delivery !== 'accepted' ? ` · ${status}` : ''}</Label>
          {item.delivery === 'accepted' ? <Check size={14} color={c.muted} /> : item.delivery === 'queued' ? <Clock3 size={13} color={c.muted} /> : item.delivery === 'failed' || item.delivery === 'unknown' ? <CircleAlert size={13} color={c.danger} /> : null}
        </View>
      </Pressable>
      {item.delivery === 'failed' && <Pressable onPress={onRetry} accessibilityRole="button" accessibilityLabel="Повторить демо-отправку этого сообщения" style={styles.retryButton}><Label color={c.danger} style={styles.chipText}>Повторить</Label></Pressable>}
    </View>
  </View>;
}
function ScenarioPicker({ value, onChange, c }: { value: Scenario; onChange: (scenario: Scenario) => void; c: Palette }) {
  return <View><Label color={c.muted} style={styles.sectionLabel}>СЦЕНАРИЙ ЛИЧНОГО ЧАТА</Label>{(Object.keys(scenarioNames) as Scenario[]).map(scenario => <Pressable key={scenario} onPress={() => onChange(scenario)} accessibilityRole="radio" accessibilityState={{ checked: value === scenario }} style={[styles.scenarioRow, { borderBottomColor: c.line }]}><Label color={c.text} style={styles.flex}>{scenarioNames[scenario]}</Label>{value === scenario && <Check size={22} color={c.accent} />}</Pressable>)}</View>;
}
function FutureSection({ tab, c }: { tab: 'groups' | 'spaces'; c: Palette }) {
  const groups = tab === 'groups';
  const Icon = groups ? Users : Layers3;
  return <ScrollView contentContainerStyle={styles.futureContent}><Label color={c.text} style={styles.title}>{groups ? 'Группы' : 'Пространства'}</Label><Label color={c.muted} style={styles.subtitle}>{groups ? 'Один разговор — несколько людей' : 'Общее место для связанных разговоров'}</Label><View style={[styles.futureHero, { backgroundColor: c.surface, borderColor: c.line }]}><View style={[styles.futureIcon, { backgroundColor: c.tint }]}><Icon size={32} color={c.accent} /></View><Label color={c.text} style={styles.emptyTitle}>Место уже предусмотрено</Label><Label color={c.muted} style={styles.emptyText}>{groups ? 'Участники, общая история и отдельные настройки группы.' : 'Список пространств → пространство → каналы и участники.'}</Label><View style={[styles.futureBadge, { backgroundColor: c.tint }]}><Label color={c.accent} style={styles.caption}>Следующий этап · раздел пока недоступен</Label></View></View><Label color={c.muted} style={styles.body}>{groups ? 'Сначала проработаем личные чаты. Групповое шифрование и управление участниками подключим отдельно, через контракт Veil.' : 'Пространства объединят каналы, роли и навигацию. Их нельзя подменять личными или групповыми чатами.'}</Label><View style={[styles.outlineRow, { borderColor: c.line }]}><Icon size={21} color={c.muted} /><Label color={c.muted} style={styles.flex}>{groups ? 'Список групп' : 'Список пространств'}</Label><ChevronRight size={18} color={c.muted} /></View></ScrollView>;
}

const styles = StyleSheet.create({
  root: { flex: 1 }, flex: { flex: 1 }, text: { fontSize: 15, lineHeight: 22, ...Platform.select({ android: { includeFontPadding: false } }) }, pressed: { opacity: 0.68 }, disabled: { opacity: 0.35 },
  iconButton: { minWidth: 48, minHeight: 48, borderRadius: 18, alignItems: 'center', justifyContent: 'center' },
  brandRow: { paddingHorizontal: 20, paddingTop: 8, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }, brandLockup: { flexDirection: 'row', alignItems: 'center', gap: 12 }, brand: { fontSize: 30, lineHeight: 38, fontWeight: '700', letterSpacing: -1.5 }, designBadge: { paddingVertical: 4, paddingHorizontal: 8, borderRadius: 6 }, badgeText: { fontSize: 10, lineHeight: 16, letterSpacing: 1, fontWeight: '700' },
  headingRow: { paddingHorizontal: 20, paddingTop: 20, paddingBottom: 22, flexDirection: 'row', alignItems: 'center', gap: 10 }, title: { fontSize: 28, lineHeight: 36, fontWeight: '600', letterSpacing: -0.8 }, subtitle: { fontSize: 14, lineHeight: 21, marginTop: 5 },
  searchBox: { marginHorizontal: 20, paddingLeft: 15, paddingRight: 5, borderRadius: 16, borderWidth: 1, flexDirection: 'row', alignItems: 'center', minHeight: 52, gap: 10 }, searchInput: { flex: 1, fontSize: 15, minHeight: 50, paddingVertical: 12 },
  filters: { flexDirection: 'row', flexWrap: 'wrap', gap: 10, paddingTop: 14, paddingBottom: 10 }, chip: { paddingHorizontal: 16, minHeight: 48, justifyContent: 'center', borderRadius: 24, borderWidth: 1 }, chipText: { fontSize: 13, lineHeight: 20, fontWeight: '600' },
  chatList: { paddingHorizontal: 20, paddingBottom: 8 }, sectionLabel: { fontSize: 10, lineHeight: 16, fontWeight: '600', letterSpacing: 1.4, marginTop: 18, marginBottom: 10 },
  chatRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 17, gap: 14, borderBottomWidth: StyleSheet.hairlineWidth, minHeight: 90 }, avatar: { width: 54, height: 54, borderRadius: 21, alignItems: 'center', justifyContent: 'center' }, smallAvatar: { width: 42, height: 42, borderRadius: 16 }, avatarText: { fontSize: 17, fontWeight: '600' }, avatarSmallText: { fontSize: 13, fontWeight: '600' }, chatRowBody: { flex: 1, gap: 5 }, rowTitle: { flexDirection: 'row', alignItems: 'center', gap: 10 }, chatName: { flex: 1, fontSize: 16, lineHeight: 23, fontWeight: '600' }, time: { fontSize: 11, lineHeight: 18 }, previewText: { flex: 1, fontSize: 13, lineHeight: 19 }, unreadBadge: { minWidth: 22, minHeight: 22, paddingHorizontal: 6, borderRadius: 11, alignItems: 'center', justifyContent: 'center' }, unreadText: { fontSize: 11, lineHeight: 16, fontWeight: '700' },
  listFooter: { paddingTop: 24, paddingBottom: 18, flexDirection: 'row', justifyContent: 'center', alignItems: 'center', gap: 8 }, note: { fontSize: 11, lineHeight: 17, flexShrink: 1 },
  navigation: { flexDirection: 'row', alignItems: 'stretch', borderTopWidth: StyleSheet.hairlineWidth, paddingTop: 10, paddingBottom: 6, paddingHorizontal: 8 }, navItem: { flex: 1, minHeight: 60, alignItems: 'center', gap: 3, justifyContent: 'center' }, navIcon: { width: 52, height: 30, borderRadius: 14, alignItems: 'center', justifyContent: 'center' }, navLabel: { fontSize: 10, lineHeight: 16, textAlign: 'center' },
  chatHeader: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 8, paddingVertical: 8, gap: 2, borderBottomWidth: StyleSheet.hairlineWidth }, peerHeader: { flex: 1, flexDirection: 'row', alignItems: 'center', gap: 10, minHeight: 52 }, peerTitle: { flex: 1 }, peerName: { fontSize: 16, lineHeight: 23, fontWeight: '600' }, caption: { fontSize: 12, lineHeight: 19 },
  stateBanner: { paddingHorizontal: 16, paddingVertical: 10, flexDirection: 'row', gap: 10, alignItems: 'center' }, bannerText: { fontSize: 12, lineHeight: 19, flex: 1 }, messageList: { paddingHorizontal: 16, paddingBottom: 16, flexGrow: 1 }, conversationIntro: { alignItems: 'center', paddingTop: 20, paddingBottom: 22, gap: 16 }, date: { fontSize: 11, lineHeight: 18 }, demoNote: { flexDirection: 'row', gap: 8, borderWidth: 1, borderRadius: 12, padding: 10, alignItems: 'center' },
  messageRow: { alignItems: 'flex-start', marginBottom: 10 }, ownRow: { alignItems: 'flex-end' }, bubble: { maxWidth: '88%', paddingHorizontal: 14, paddingTop: 11, paddingBottom: 8, borderRadius: 20, minHeight: 48 }, ownBubble: { borderBottomRightRadius: 6 }, peerBubble: { borderBottomLeftRadius: 6 }, messageTap: { minHeight: 48, minWidth: 48 }, messageText: { fontSize: 16, lineHeight: 24 }, messageMeta: { flexDirection: 'row', gap: 5, alignItems: 'center', justifyContent: 'flex-end', marginTop: 5, flexWrap: 'wrap' }, messageTime: { fontSize: 10, lineHeight: 16 }, retryButton: { minHeight: 48, justifyContent: 'center' },
  composerArea: { paddingHorizontal: 14, paddingTop: 12, paddingBottom: 8, borderTopWidth: StyleSheet.hairlineWidth }, composer: { flexDirection: 'row', alignItems: 'flex-end', padding: 6, borderWidth: 1, borderRadius: 24, gap: 6 }, composerInput: { flex: 1, minHeight: 48, maxHeight: 160, paddingHorizontal: 10, paddingTop: 12, paddingBottom: 12, fontSize: 16, lineHeight: 23, textAlignVertical: 'center' }, sendButton: { width: 48, height: 48, borderRadius: 18, alignItems: 'center', justifyContent: 'center' }, composerHint: { fontSize: 10, lineHeight: 16, textAlign: 'center', paddingTop: 7 },
  emptyState: { alignItems: 'center', paddingVertical: 55, gap: 14 }, emptyChat: { alignItems: 'center', padding: 30, gap: 14 }, emptyTitle: { fontSize: 21, lineHeight: 29, fontWeight: '600', textAlign: 'center' }, emptyText: { fontSize: 14, lineHeight: 22, textAlign: 'center' },
  settingsContent: { paddingHorizontal: 20, paddingTop: 22, paddingBottom: 24 }, card: { borderWidth: 1, borderRadius: 20, padding: 18, gap: 10, marginTop: 20 }, cardTitle: { fontSize: 17, lineHeight: 24, fontWeight: '600', flexShrink: 1 }, body: { fontSize: 14, lineHeight: 23, marginTop: 8 }, scenarioRow: { minHeight: 56, flexDirection: 'row', gap: 12, alignItems: 'center', borderBottomWidth: StyleSheet.hairlineWidth, paddingVertical: 10 }, resetButton: { minHeight: 52, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderRadius: 16, marginTop: 22 },
  futureContent: { padding: 20, paddingTop: 22 }, futureHero: { padding: 26, borderWidth: 1, borderRadius: 26, alignItems: 'center', marginTop: 28, marginBottom: 16, gap: 16 }, futureIcon: { width: 72, height: 72, borderRadius: 24, alignItems: 'center', justifyContent: 'center' }, futureBadge: { borderRadius: 12, paddingHorizontal: 12, paddingVertical: 8 }, outlineRow: { borderWidth: 1, borderRadius: 18, flexDirection: 'row', alignItems: 'center', padding: 16, gap: 12, marginTop: 22, opacity: 0.6 },
  modalRoot: { flex: 1, justifyContent: 'flex-end' }, scrim: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.62)' }, sheet: { borderTopLeftRadius: 28, borderTopRightRadius: 28, maxHeight: '88%' }, sheetHeading: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingLeft: 22, paddingRight: 12, paddingTop: 12 }, sheetContent: { paddingHorizontal: 22, paddingBottom: 28 }, profileIntro: { alignItems: 'center', paddingTop: 14, gap: 10 }, license: { fontSize: 11, lineHeight: 17, marginTop: 22 },
});
