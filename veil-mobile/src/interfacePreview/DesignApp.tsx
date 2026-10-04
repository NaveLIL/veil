/** Isolated presentation workbench. Fixtures never enter the Veil runtime. */
import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { AccessibilityInfo, Animated, BackHandler, FlatList, Image, Keyboard, KeyboardAvoidingView, Modal, Platform, Pressable, ScrollView, StatusBar, StyleSheet, Switch, Text, TextInput, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { ArrowLeft, ArrowUp, Check, CircleAlert, Clock3, Hash, Info, LockKeyhole, MessageCircle, MoreHorizontal, Plus, Search, Shield, Users, WifiOff, X } from 'lucide-react-native';
import { ROCKET_CHAT_MIT_NOTICE } from '../presentation/rocketChat/notice';
import { canGroup, createDemoSession, DemoChat, DemoMessage, demoSpaces, openChat, retryDemo, Scenario, sendDemo, setDraft, visibleChats } from './model';
import { Palette, palettes, ThemeName } from './appearance';
import { pickWallpaper } from './appearanceBridge';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { ChatDeck } from './ChatDeck';
import { deckReducer, initialDeck } from './navigation';
import { FloatingProfile, ProfilePanel } from './UserProfile';

type Sheet = 'profile' | 'scenarios' | 'about' | 'message' | null;
type IconComponent = typeof Search;
const scenarioNames: Record<Scenario, string> = { normal: 'Обычный чат', offline: 'Нет сети', failure: 'Ошибка отправки', unknown: 'Статус неизвестен', identityChanged: 'Ключ изменился' };
function Label({ color, style, ...props }: React.ComponentProps<typeof Text> & { color?: string }) {
  return <Text {...props} style={[styles.text, { color }, style]} />;
}
function IconButton({ icon: Icon, label, onPress, color }: { icon: IconComponent; label: string; onPress: () => void; color: string }) {
  return <Pressable onPress={onPress} accessibilityRole="button" accessibilityLabel={label} style={({ pressed }) => [styles.iconButton, pressed && styles.pressed]}><Icon size={22} color={color} strokeWidth={1.8} /></Pressable>;
}
function Avatar({ chat, size = 42 }: { chat: Pick<DemoChat, 'initials' | 'color'>; size?: number }) {
  return <View accessible={false} style={[styles.avatar, { width: size, height: size, borderRadius: size / 2, backgroundColor: chat.color }]}><Label color="#FFFFFF" style={styles.avatarText}>{chat.initials}</Label></View>;
}
function Button({ label, onPress, c }: { label: string; onPress: () => void; c: Palette }) {
  return <Pressable accessibilityRole="button" onPress={onPress} style={({ pressed }) => [styles.button, { backgroundColor: c.raised }, pressed && styles.pressed]}><Label color={c.accent} style={styles.buttonText}>{label}</Label></Pressable>;
}
export function DesignApp() { return <SafeAreaProvider><GestureHandlerRootView style={styles.root}><Workbench /></GestureHandlerRootView></SafeAreaProvider>; }
function Workbench() {
  const [session, setSession] = useState(createDemoSession);
  const [destination, setDestination] = useState('messages');
  const [deck, dispatchDeck] = useReducer(deckReducer, initialDeck);
  const chatId = deck.activeChatId;
  const [ownProfileOpen, setOwnProfileOpen] = useState(false);
  const [ownProfile, setOwnProfile] = useState({ name: 'Veil User', bio: 'Человек, разговор и немного красивого интерфейса.' });
  const [query, setQuery] = useState('');
  const [searchVisible, setSearchVisible] = useState(false);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [newChat, setNewChat] = useState(false);
  const [sheet, setSheet] = useState<Sheet>(null);
  const [message, setMessage] = useState<DemoMessage | null>(null);
  const [theme, setTheme] = useState<ThemeName>('OLED');
  const [wallpaper, setWallpaper] = useState<string | null>(null);
  const [showWallpaper, setShowWallpaper] = useState(true);
  const [dim, setDim] = useState(20);
  const [blur, setBlur] = useState(4);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [systemReduceMotion, setSystemReduceMotion] = useState(false);
  const [locked, setLocked] = useState(false);
  const [pickerError, setPickerError] = useState('');
  const [picking, setPicking] = useState(false);
  const c = palettes[theme];
  const chat = session.chats.find(item => item.id === chatId);
  const space = demoSpaces.find(item => item.id === destination);
  const messagesRef = useRef<FlatList<DemoMessage>>(null);
  const chatsRef = useRef<FlatList<DemoChat>>(null);
  const listOffset = useRef(0);
  const searchRef = useRef<TextInput>(null);
  const atEnd = useRef(true);
  const transition = useRef(new Animated.Value(1)).current;
  const noMotion = reduceMotion || systemReduceMotion;
  useEffect(() => {
    let alive = true;
    AccessibilityInfo.isReduceMotionEnabled().then(value => { if (alive) setSystemReduceMotion(value); });
    const subscription = AccessibilityInfo.addEventListener('reduceMotionChanged', setSystemReduceMotion);
    return () => { alive = false; subscription.remove(); };
  }, []);
  useEffect(() => {
    transition.stopAnimation();
    if (noMotion) { transition.setValue(1); return; }
    transition.setValue(0);
    const animation = Animated.timing(transition, { toValue: 1, duration: 220, useNativeDriver: true });
    animation.start();
    return () => animation.stop();
  }, [destination, locked, noMotion, transition]);
  const back = useCallback(() => {
    if (sheet) { setSheet(null); return true; }
    if (locked) { setLocked(false); return true; }
    if (ownProfileOpen) { setOwnProfileOpen(false); return true; }
    if (chatId && !deck.navigationOpen) { Keyboard.dismiss(); dispatchDeck({ type: 'reveal' }); return true; }
    if (newChat) { setNewChat(false); return true; }
    if (destination !== 'messages') { setDestination('messages'); return true; }
    if (searchVisible) { setSearchVisible(false); return true; }
    return false;
  }, [sheet, locked, ownProfileOpen, chatId, deck.navigationOpen, newChat, destination, searchVisible]);
  useEffect(() => { const subscription = BackHandler.addEventListener('hardwareBackPress', back); return () => subscription.remove(); }, [back]);
  function enterChat(id: string) { if (id !== chatId) atEnd.current = true; Keyboard.dismiss(); setSession(s => openChat(s, id)); dispatchDeck({ type: 'choose', id }); }
  function send() {
    if (!chat) return;
    const now = new Date(); atEnd.current = true;
    setSession(s => sendDemo(s, chat.id, `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`));
  }
  async function chooseWallpaper() {
    if (picking) return;
    setPicking(true); setPickerError('');
    try { const uri = await pickWallpaper(); if (uri) { setWallpaper(uri); setShowWallpaper(true); } }
    catch { setPickerError('Не удалось открыть изображение. Выберите другое или меньшего размера.'); }
    finally { setPicking(false); }
  }
  const sendBlocked = session.scenario === 'identityChanged';
  const searchResults = visibleChats(session, query, newChat ? false : unreadOnly).filter(item => !newChat || !item.kind || item.kind === 'direct');
  const animatedStyle = { opacity: transition, transform: [{ translateY: transition.interpolate({ inputRange: [0, 1], outputRange: [8, 0] }) }] };
  const appearanceSettings = <ScrollView contentContainerStyle={styles.settingsContent}>
            <Label color={c.text} style={styles.heading}>Внешний вид</Label><Label color={c.muted} style={styles.caption}>Настройки этого макета</Label><Label color={c.muted} style={styles.sectionLabel}>ЦВЕТОВАЯ СХЕМА</Label>
            {(Object.keys(palettes) as ThemeName[]).map(name => <Pressable key={name} accessibilityRole="radio" accessibilityLabel={`Тема ${name}`} accessibilityState={{ checked: theme === name }} onPress={() => setTheme(name)} style={[styles.themeRow, { borderColor: theme === name ? c.accent : c.line, backgroundColor: theme === name ? c.tint : c.surface }]}><View style={styles.swatches}>{[palettes[name].bg, palettes[name].raised, palettes[name].accent].map(color => <View key={color} style={[styles.swatch, { backgroundColor: color }]} />)}</View><Label color={c.text} style={styles.flex}>{name}</Label>{theme === name && <Check size={18} color={c.accent} />}</Pressable>)}
            <Label color={c.muted} style={styles.sectionLabel}>ПОДЛОЖКА</Label><View style={[styles.wallpaperSample, { backgroundColor: c.tint }]}>{wallpaper && <Image source={{ uri: wallpaper }} blurRadius={blur} style={StyleSheet.absoluteFillObject} />}<View style={[StyleSheet.absoluteFillObject, { backgroundColor: `rgba(0,0,0,${dim / 100})` }]} /><View style={[styles.sampleDock, { backgroundColor: c.bg }]} /><View style={[styles.sampleIsland, { backgroundColor: c.bg }]}><View style={[styles.sampleComposer, { backgroundColor: c.raised }]} /></View></View>
            <Button label={picking ? 'Открываем выбор…' : 'Выбрать изображение'} onPress={() => { void chooseWallpaper(); }} c={c} />{!!pickerError && <Label accessibilityRole="alert" color={c.muted} style={styles.caption}>{pickerError}</Label>}
            <Button label="Вернуть стандартный фон" onPress={() => { setWallpaper(null); setShowWallpaper(true); setDim(20); setBlur(4); }} c={c} /><SettingSwitch label="Показывать подложку" value={showWallpaper} onChange={setShowWallpaper} c={c} />
            <Stepper label="Затемнение" value={`${dim}%`} onMinus={() => setDim(v => Math.max(0, v - 10))} onPlus={() => setDim(v => Math.min(90, v + 10))} c={c} /><Stepper label="Размытие фото" value={`${blur} px`} onMinus={() => setBlur(v => Math.max(0, v - 2))} onPlus={() => setBlur(v => Math.min(24, v + 2))} c={c} />
            <Label color={c.muted} style={styles.caption}>Картинка выбирается на устройстве. Острова сохраняют контраст при любом фоне. Настройки пока живут в памяти макета.</Label><Label color={c.muted} style={styles.sectionLabel}>ДВИЖЕНИЕ</Label><SettingSwitch label="Уменьшить анимации" value={reduceMotion} onChange={setReduceMotion} c={c} />{systemReduceMotion && <Label color={c.muted} style={styles.caption}>Анимации уже уменьшены настройкой Android.</Label>}
            <Button label="Посмотреть экран блокировки" onPress={() => { setOwnProfileOpen(false); setLocked(true); }} c={c} /><Button label="Сценарии сообщений" onPress={() => { setOwnProfileOpen(false); setSheet('scenarios'); }} c={c} /><Button label="О дизайн-макете" onPress={() => { setOwnProfileOpen(false); setSheet('about'); }} c={c} />
          </ScrollView>;
  return <View style={[styles.root, { backgroundColor: '#050507' }]}>
    {showWallpaper && !locked && <View pointerEvents="none" style={styles.wallpaper}>
      {wallpaper ? <Image source={{ uri: wallpaper }} resizeMode="cover" blurRadius={blur} style={StyleSheet.absoluteFillObject} /> : <View style={styles.defaultWallpaper}><View style={[styles.glow, styles.glowOne, { backgroundColor: c.accent }]} /><View style={[styles.glow, styles.glowTwo, { backgroundColor: c.accent }]} /><View style={[styles.glow, styles.glowThree, { backgroundColor: c.accent }]} /></View>}
      <View style={[StyleSheet.absoluteFillObject, { backgroundColor: `rgba(0,0,0,${dim / 100})` }]} />
    </View>}
    <SafeAreaView edges={['top', 'bottom']} style={styles.safe}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" />
      {locked ? <Animated.View style={[styles.lockScreen, animatedStyle]}><View style={[styles.lockCard, { backgroundColor: c.bg, borderColor: c.line }]}>
        <View style={[styles.logo, { backgroundColor: c.tint }]}><Label color={c.accent} style={styles.logoMark}>Ⅵ</Label></View>
        <Label color={c.text} style={styles.lockBrand}>VEIL</Label><LockKeyhole size={18} color={c.muted} /><Label color={c.muted} style={styles.centered}>Предпросмотр блокировки</Label>
        <View style={[styles.pinPreview, { borderColor: c.line }]}><Label color={c.muted}>● ● ● ● ● ●</Label></View>
        <View style={styles.keypad}>{['1', '2', '3', '4', '5', '6', '7', '8', '9'].map(key => <View key={key} accessible={false} style={[styles.key, { backgroundColor: c.surface }]}><Label color={c.text} style={styles.keyText}>{key}</Label></View>)}</View>
        <Button label="Вернуться в макет" onPress={() => setLocked(false)} c={c} /><Label color={c.muted} style={styles.smallCentered}>Демо · PIN не требуется</Label>
      </View></Animated.View> : <ChatDeck surfaceColor={c.bg} edgeColor={c.line} navigationOpen={deck.navigationOpen} hasChat={!!chat} enabled={!sheet && !ownProfileOpen} reduceMotion={noMotion} onNavigationChange={open => dispatchDeck({ type: open ? 'reveal' : 'resume' })} profile={<FloatingProfile c={c} profile={ownProfile} onOpen={() => setOwnProfileOpen(true)} hasChat={!!chat} onResume={() => dispatchDeck({ type: 'resume' })} />} conversation={chat ? <View testID="conversation-island" style={[styles.island, { backgroundColor: c.bg }]}>
        <View style={[styles.chatHeader, { borderBottomColor: c.line }]}>
          <IconButton icon={ArrowLeft} label="Назад к списку" onPress={() => { Keyboard.dismiss(); dispatchDeck({ type: 'reveal' }); }} color={c.text} />
          <Pressable accessibilityRole="button" accessibilityLabel={`Профиль: ${chat.name}`} onPress={() => setSheet('profile')} style={styles.peerHeader}><Avatar chat={chat} size={36} /><View style={styles.flex}><Label color={c.text} style={styles.peerName} numberOfLines={1}>{chat.kind === 'channel' ? `# ${chat.name}` : chat.name}</Label><Label color={c.muted} style={styles.caption}>{chat.kind === 'channel' ? demoSpaces.find(s => s.id === chat.space)?.name : chat.kind === 'group' ? 'Групповой чат' : 'Личный чат'} · демо</Label></View></Pressable>
          <IconButton icon={MoreHorizontal} label="Состояния и настройки макета" onPress={() => setSheet('scenarios')} color={c.muted} />
        </View>
        <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
          {session.scenario !== 'normal' && <View style={[styles.stateBanner, { backgroundColor: c.tint }]}>{session.scenario === 'offline' ? <WifiOff size={18} color={c.accent} /> : <CircleAlert size={18} color={c.accent} />}<Label color={c.text} style={styles.bannerText}>{session.scenario === 'offline' ? 'Демо: сообщения остаются в очереди' : session.scenario === 'identityChanged' ? 'Демо: ключ изменился. Отправка остановлена.' : session.scenario === 'unknown' ? 'Демо: подтверждение отправки неизвестно' : 'Демо: следующая отправка завершится ошибкой'}</Label></View>}
          <FlatList ref={messagesRef} key={chat.id} data={chat.messages} keyExtractor={m => m.id} style={styles.flex} contentContainerStyle={styles.messageList} keyboardShouldPersistTaps="handled" keyboardDismissMode="on-drag" scrollEventThrottle={100}
            onScroll={e => { const { layoutMeasurement, contentOffset, contentSize } = e.nativeEvent; atEnd.current = contentSize.height - contentOffset.y - layoutMeasurement.height < 100; }} onContentSizeChange={() => { if (atEnd.current) messagesRef.current?.scrollToEnd({ animated: false }); }}
            ListHeaderComponent={<View style={styles.dateRow}><View style={[styles.dateLine, { backgroundColor: c.line }]} /><Label color={c.muted} style={styles.caption}>Сегодня</Label><View style={[styles.dateLine, { backgroundColor: c.line }]} /></View>}
            ListEmptyComponent={<View style={styles.empty}><Avatar chat={chat} /><Label color={c.text} style={styles.cardTitle}>Начало разговора</Label><Label color={c.muted} style={styles.centered}>Напишите первое демо-сообщение.</Label></View>}
            renderItem={({ item, index }) => <MessageRow item={item} chat={chat} grouped={canGroup(chat.messages[index - 1], item)} c={c} onLongPress={() => { setMessage(item); setSheet('message'); }} onRetry={() => setSession(s => retryDemo(s, chat.id, item.id))} />} />
          <View style={styles.composerArea}><View style={[styles.composer, { backgroundColor: c.raised }]}><TextInput testID="preview-composer" accessibilityLabel="Текст демо-сообщения" value={session.drafts[chat.id] ?? ''} onChangeText={text => setSession(s => setDraft(s, chat.id, text))} placeholder={sendBlocked ? 'Отправка остановлена' : `Написать ${chat.kind === 'channel' ? '#' : '@'}${chat.name}`} placeholderTextColor={c.muted} editable={!sendBlocked} multiline maxLength={4000} style={[styles.composerInput, { color: c.text }]} underlineColorAndroid="transparent" keyboardAppearance="dark" />
            <Pressable onPress={send} disabled={sendBlocked || !(session.drafts[chat.id] ?? '').trim()} accessibilityRole="button" accessibilityLabel="Отправить демо-сообщение" accessibilityState={{ disabled: sendBlocked || !(session.drafts[chat.id] ?? '').trim() }} style={({ pressed }) => [styles.sendButton, { backgroundColor: c.accent }, (sendBlocked || !(session.drafts[chat.id] ?? '').trim()) && styles.disabled, pressed && styles.pressed]}><ArrowUp size={22} color="#101015" /></Pressable></View><Label color={c.muted} style={styles.smallCentered}>Демо · сообщения остаются на этом экране</Label></View>
        </KeyboardAvoidingView>
      </View> : null} navigation={<View style={styles.navigationSurface}><View style={styles.home}>
        <View testID="navigation-dock" style={[styles.dock, { backgroundColor: c.bg }]}>
          <DockItem icon={MessageCircle} label="Сообщения" selected={destination === 'messages'} onPress={() => { setDestination('messages'); setNewChat(false); }} c={c} /><View style={[styles.dockDivider, { backgroundColor: c.line }]} />
          <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.dockSpaces}>{demoSpaces.map(item => <DockItem key={item.id} label={`Пространство ${item.name}`} initials={item.initials} selected={destination === item.id} onPress={() => setDestination(item.id)} c={c} />)}</ScrollView>

        </View>
        <Animated.View style={[styles.island, { backgroundColor: c.bg }, animatedStyle]}>
          {destination === 'messages' ? <>
            <View style={styles.header}>{newChat && <IconButton icon={ArrowLeft} label="Закрыть новый чат" color={c.text} onPress={() => setNewChat(false)} />}<Label color={c.text} style={[styles.heading, styles.flex]} numberOfLines={1}>{newChat ? 'Новый чат' : 'Сообщения'}</Label><IconButton icon={Search} label="Поиск чатов" color={c.muted} onPress={() => { setSearchVisible(v => !v); requestAnimationFrame(() => searchRef.current?.focus()); }} />{!newChat && <IconButton icon={Plus} label="Начать новый демо-чат" color={c.accent} onPress={() => { setNewChat(true); setSearchVisible(true); requestAnimationFrame(() => searchRef.current?.focus()); }} />}</View>
            {(searchVisible || newChat) && <View style={[styles.searchBox, { backgroundColor: c.surface }]}><TextInput ref={searchRef} value={query} onChangeText={setQuery} accessibilityLabel="Найти демо-чат по имени или username" placeholder="Имя или username" placeholderTextColor={c.muted} style={[styles.searchInput, { color: c.text }]} autoCorrect={false} />{query.length > 0 && <IconButton icon={X} label="Очистить поиск" color={c.muted} onPress={() => setQuery('')} />}</View>}
            {!newChat && <View style={styles.filters}>{[{ name: 'Все', unread: false }, { name: 'Непрочитанные', unread: true }].map(filter => <Pressable key={filter.name} accessibilityRole="button" accessibilityState={{ selected: unreadOnly === filter.unread }} onPress={() => setUnreadOnly(filter.unread)} style={[styles.filter, { borderBottomColor: unreadOnly === filter.unread ? c.accent : 'transparent' }]}><Label color={unreadOnly === filter.unread ? c.accent : c.muted} style={styles.buttonText}>{filter.name}</Label></Pressable>)}</View>}
            <FlatList ref={chatsRef} data={searchResults} keyExtractor={item => item.id} contentContainerStyle={styles.chatList} keyboardShouldPersistTaps="handled" keyboardDismissMode="on-drag" onScroll={e => { listOffset.current = e.nativeEvent.contentOffset.y; }} scrollEventThrottle={100} onLayout={() => chatsRef.current?.scrollToOffset({ offset: listOffset.current, animated: false })} ListEmptyComponent={<View style={styles.empty}><Search size={28} color={c.muted} /><Label color={c.text}>Ничего не найдено</Label></View>}
              renderItem={({ item }) => { const latest = item.messages[item.messages.length - 1]; const draft = session.drafts[item.id]; return <Pressable onPress={() => enterChat(item.id)} accessibilityRole="button" accessibilityLabel={`${item.name}${item.unread ? `, непрочитанных: ${item.unread}` : ''}${draft ? ', есть черновик' : ''}`} style={({ pressed }) => [styles.chatRow, pressed && { backgroundColor: c.surface }]}><Avatar chat={item} /><View style={styles.chatRowBody}><View style={styles.rowTitle}>{item.kind === 'group' && <Users size={13} color={c.muted} />}<Label color={c.text} numberOfLines={1} style={styles.chatName}>{item.name}</Label><Label color={c.muted} style={styles.time}>{latest?.time}</Label></View><View style={styles.rowTitle}><Label color={draft ? c.accent : c.muted} numberOfLines={1} style={styles.previewText}>{draft ? `Черновик: ${draft}` : latest ? `${latest.own ? 'Вы: ' : latest.author ? `${latest.author}: ` : ''}${latest.text}` : 'Начать разговор'}</Label>{item.unread > 0 && <View style={[styles.unreadBadge, { backgroundColor: c.accent }]}><Label color="#101015" style={styles.unreadText}>{item.unread}</Label></View>}</View></View></Pressable>; }} ListFooterComponent={<Label color={c.muted} style={styles.footer}>Личные и групповые чаты · демо</Label>} />
          </> : space ? <><View style={styles.spaceHeader}><Label color={c.text} style={styles.heading}>{space.name}</Label><Label color={c.muted} style={styles.caption}>{space.description}</Label></View><ScrollView contentContainerStyle={styles.chatList}>{['ОБЩЕНИЕ', 'ПРОЕКТЫ'].map(category => { const channels = session.chats.filter(item => item.space === space.id && item.category === category); return channels.length > 0 && <View key={category}><Label color={c.muted} style={styles.sectionLabel}>{category}</Label>{channels.map(item => <Pressable key={item.id} accessibilityRole="button" accessibilityLabel={`Открыть канал ${item.name}`} onPress={() => enterChat(item.id)} style={({ pressed }) => [styles.channelRow, pressed && { backgroundColor: c.surface }]}><Hash size={20} color={c.muted} /><Label color={c.text} style={styles.flex}>{item.name}</Label>{item.unread > 0 && <View style={[styles.unreadDot, { backgroundColor: c.accent }]} />}</Pressable>)}</View>; })}<Label color={c.muted} style={styles.footer}>Демо-пространство · вымышленные данные</Label></ScrollView></> : null}
        </Animated.View>
      </View></View>} />}
      <ProfilePanel open={ownProfileOpen && deck.navigationOpen && !locked} onClose={() => setOwnProfileOpen(false)} c={c} reduceMotion={noMotion} profile={ownProfile} onProfileChange={setOwnProfile} appearance={appearanceSettings} onLock={() => { setOwnProfileOpen(false); setLocked(true); }} onAbout={() => { setOwnProfileOpen(false); setSheet('about'); }} onScenarios={() => { setOwnProfileOpen(false); setSheet('scenarios'); }} />
      <Modal visible={sheet !== null} transparent animationType={noMotion ? 'none' : 'slide'} onRequestClose={() => setSheet(null)} statusBarTranslucent><View style={styles.modalRoot}><Pressable accessibilityRole="button" accessibilityLabel="Закрыть панель" onPress={() => setSheet(null)} style={styles.scrim} /><SafeAreaView edges={['bottom']} style={[styles.sheet, { backgroundColor: c.surface }]}><View style={styles.sheetHeading}><Label color={c.text} style={[styles.cardTitle, styles.flex]}>{sheet === 'profile' ? 'О разговоре' : sheet === 'scenarios' ? 'Сценарии сообщений' : sheet === 'message' ? 'Демо-сообщение' : 'Veil Design'}</Label><IconButton icon={X} label="Закрыть" color={c.muted} onPress={() => setSheet(null)} /></View><ScrollView contentContainerStyle={styles.sheetContent}>
        {sheet === 'scenarios' ? <ScenarioPicker value={session.scenario} onChange={scenario => setSession(s => ({ ...s, scenario }))} c={c} /> : sheet === 'profile' && chat ? <><View style={styles.empty}><Avatar chat={chat} /><Label color={c.text} style={styles.cardTitle}>{chat.name}</Label></View>{!chat.kind || chat.kind === 'direct' ? <><Shield size={24} color={c.accent} /><Label color={c.text} style={styles.cardTitle}>Личность не подтверждена</Label><Label color={c.muted} style={styles.body}>В настоящем Veil доверие подтверждается сравнением ключей. Имя и аватар не являются доказательством личности.</Label></> : <Label color={c.muted} style={styles.body}>Демо {chat.kind === 'group' ? 'группового чата' : 'канала пространства'}. Проверяем навигацию и внешний вид. Подключение к серверу и групповое шифрование не используются.</Label>}</> : sheet === 'message' && message ? <><Label color={c.text} style={styles.body}>{message.text}</Label><Label color={c.muted} style={styles.body}>Ответы, вложения, изменение и удаление добавим после определения их поведения и поддержки в мобильном клиенте.</Label></> : <><Label color={c.text} style={styles.cardTitle}>Veil на маленьком экране</Label><Label color={c.muted} style={styles.body}>Отдельный дизайн-макет с вымышленными разговорами. Без регистрации, Access Pass и подключения к мессенджеру. Скриншоты разрешены.</Label><Label color={c.muted} style={styles.body}>Демо-сообщения и настройки живут в памяти до перезапуска. Выбранная картинка обрабатывается локально.</Label><Label color={c.muted} style={styles.body}>Veil © NaveLIL · AGPL-3.0-or-later. Composer pattern adapted from Rocket.Chat.ReactNative 4.77.0.</Label><Label color={c.muted} style={styles.license}>{ROCKET_CHAT_MIT_NOTICE}</Label></>}
      </ScrollView></SafeAreaView></View></Modal>
    </SafeAreaView>
  </View>;
}
function DockItem({ label, icon: Icon, initials, selected, onPress, c }: { label: string; icon?: IconComponent; initials?: string; selected: boolean; onPress: () => void; c: Palette }) {
  return <View style={styles.dockItem}><View style={[styles.activePill, { backgroundColor: selected ? c.accent : 'transparent' }]} /><Pressable accessibilityRole="tab" accessibilityLabel={label} accessibilityState={{ selected }} onPress={onPress} style={({ pressed }) => [styles.dockButton, { backgroundColor: selected ? c.accent : c.surface, borderRadius: selected ? 16 : 24 }, pressed && styles.pressed]}>{Icon ? <Icon size={23} color={selected ? '#101015' : c.muted} strokeWidth={1.8} /> : <Label color={selected ? '#101015' : c.accent} style={styles.dockInitial}>{initials}</Label>}</Pressable></View>;
}
function MessageRow({ item, chat, grouped, c, onLongPress, onRetry }: { item: DemoMessage; chat: DemoChat; grouped: boolean; c: Palette; onLongPress: () => void; onRetry: () => void }) {
  const status = item.delivery === 'queued' ? 'В очереди' : item.delivery === 'failed' ? 'Не отправлено' : item.delivery === 'unknown' ? 'Статус неизвестен' : item.delivery === 'accepted' ? 'Отправлено' : '';
  const author = item.own ? { name: 'Вы', initials: 'В', color: '#7866AB' } : item.author ? { name: item.author, initials: item.author.slice(0, 1), color: chat.color } : chat;
  return <View style={[styles.timelineRow, { marginTop: grouped ? 2 : 18 }]}><View style={styles.avatarGutter}>{!grouped && <Avatar chat={author} size={34} />}</View><View style={styles.flex}><Pressable accessibilityRole="button" accessibilityLabel={`${author.name}: ${item.text}. ${item.time}. ${status}`} onPress={onLongPress} onLongPress={onLongPress} style={styles.messageTap}>
    {!grouped && <View style={styles.authorLine}><Label color={item.own ? c.accent : c.text} style={styles.authorName}>{author.name}</Label><Label color={c.muted} style={styles.time}>{item.time}</Label></View>}<Label color={c.text} style={styles.messageText}>{item.text}</Label>
    {!!status && <View style={styles.messageStatus}>{item.delivery === 'accepted' ? <Check size={12} color={c.muted} /> : item.delivery === 'queued' ? <Clock3 size={12} color={c.muted} /> : <Info size={12} color={c.muted} />}<Label color={c.muted} style={styles.time}>{status}</Label></View>}
  </Pressable>{item.delivery === 'failed' && <Button label="Повторить" onPress={onRetry} c={c} />}</View></View>;
}
function ScenarioPicker({ value, onChange, c }: { value: Scenario; onChange: (scenario: Scenario) => void; c: Palette }) {
  return <View>{(Object.keys(scenarioNames) as Scenario[]).map(scenario => <Pressable key={scenario} onPress={() => onChange(scenario)} accessibilityRole="radio" accessibilityLabel={scenarioNames[scenario]} accessibilityState={{ checked: value === scenario }} style={[styles.settingRow, { borderBottomColor: c.line }]}><Label color={c.text} style={styles.flex}>{scenarioNames[scenario]}</Label>{value === scenario && <Check size={20} color={c.accent} />}</Pressable>)}<Label color={c.muted} style={styles.body}>Это состояния вымышленной переписки. Сетевые ошибки не создаются.</Label></View>;
}
function SettingSwitch({ label, value, onChange, c }: { label: string; value: boolean; onChange: (value: boolean) => void; c: Palette }) {
  return <View style={[styles.settingRow, { borderBottomColor: c.line }]}><Label color={c.text} style={styles.flex}>{label}</Label><View style={styles.switchTarget}><Switch accessibilityLabel={label} value={value} onValueChange={onChange} trackColor={{ false: c.line, true: c.accent }} thumbColor={value ? c.text : c.muted} /></View></View>;
}
function Stepper({ label, value, onMinus, onPlus, c }: { label: string; value: string; onMinus: () => void; onPlus: () => void; c: Palette }) {
  return <View style={[styles.settingRow, { borderBottomColor: c.line }]}><View style={styles.flex}><Label color={c.text}>{label}</Label><Label color={c.muted} style={styles.caption}>{value}</Label></View><Button label="−" onPress={onMinus} c={c} /><Button label="+" onPress={onPlus} c={c} /></View>;
}
const styles = StyleSheet.create({
  root: { flex: 1 }, safe: { flex: 1, paddingHorizontal: 6, paddingBottom: 6 }, flex: { flex: 1, minWidth: 0 }, text: { fontSize: 15, lineHeight: 22, ...Platform.select({ android: { includeFontPadding: false } }) }, pressed: { opacity: 0.7 }, disabled: { opacity: 0.35 },
  wallpaper: { ...StyleSheet.absoluteFillObject }, defaultWallpaper: { flex: 1, overflow: 'hidden', backgroundColor: '#100A19' }, glow: { position: 'absolute', opacity: 0.2, borderRadius: 180, transform: [{ rotate: '-25deg' }] }, glowOne: { width: 320, height: 170, top: -30, left: -150 }, glowTwo: { width: 350, height: 150, top: '42%', right: -210 }, glowThree: { width: 340, height: 160, bottom: -50, left: -120 },
  navigationSurface: { flex: 1 }, home: { flex: 1, flexDirection: 'row', gap: 6 }, island: { flex: 1, borderRadius: 20, overflow: 'hidden' }, dock: { width: 60, borderRadius: 20, paddingTop: 10, paddingBottom: 88, gap: 6 }, dockItem: { height: 52, alignItems: 'center', justifyContent: 'center' }, dockButton: { width: 48, height: 48, alignItems: 'center', justifyContent: 'center' }, activePill: { position: 'absolute', left: 0, width: 3, height: 28, borderTopRightRadius: 3, borderBottomRightRadius: 3 }, dockDivider: { height: 1, marginHorizontal: 14, marginVertical: 3 }, dockSpaces: { gap: 8, paddingBottom: 8 }, dockInitial: { fontSize: 18, fontWeight: '600' }, dockProfile: { height: 48, alignItems: 'center', justifyContent: 'center' },
  iconButton: { minWidth: 48, minHeight: 48, borderRadius: 16, alignItems: 'center', justifyContent: 'center' }, header: { minHeight: 60, paddingLeft: 14, paddingRight: 4, flexDirection: 'row', alignItems: 'center' }, heading: { fontSize: 20, lineHeight: 28, fontWeight: '600', letterSpacing: -0.4 }, caption: { fontSize: 12, lineHeight: 19 }, searchBox: { marginHorizontal: 12, borderRadius: 12, flexDirection: 'row', alignItems: 'center' }, searchInput: { flex: 1, fontSize: 14, minHeight: 48, paddingHorizontal: 12, paddingVertical: 10 }, filters: { flexDirection: 'row', gap: 16, paddingHorizontal: 14 }, filter: { minHeight: 48, minWidth: 48, justifyContent: 'center', borderBottomWidth: 2 }, buttonText: { fontSize: 12, lineHeight: 20, fontWeight: '600' },
  chatList: { paddingHorizontal: 10, paddingBottom: 96 }, chatRow: { minHeight: 76, flexDirection: 'row', alignItems: 'center', paddingHorizontal: 4, paddingVertical: 12, gap: 10, borderRadius: 12 }, avatar: { alignItems: 'center', justifyContent: 'center' }, avatarText: { fontSize: 12, lineHeight: 18, fontWeight: '600' }, chatRowBody: { flex: 1, gap: 5, minWidth: 0 }, rowTitle: { flexDirection: 'row', alignItems: 'center', gap: 5 }, chatName: { flex: 1, fontSize: 14, lineHeight: 21, fontWeight: '600' }, previewText: { flex: 1, fontSize: 12, lineHeight: 19 }, time: { fontSize: 10, lineHeight: 16 }, unreadBadge: { minWidth: 18, height: 18, borderRadius: 9, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 4 }, unreadText: { fontSize: 10, lineHeight: 14, fontWeight: '700' }, footer: { fontSize: 10, lineHeight: 16, textAlign: 'center', paddingVertical: 20 },
  spaceHeader: { paddingHorizontal: 16, paddingTop: 20, paddingBottom: 16, gap: 4 }, sectionLabel: { fontSize: 10, lineHeight: 16, fontWeight: '600', letterSpacing: 1.2, marginTop: 24, marginBottom: 12 }, channelRow: { minHeight: 52, flexDirection: 'row', alignItems: 'center', gap: 10, paddingHorizontal: 10, borderRadius: 12 }, unreadDot: { width: 6, height: 6, borderRadius: 3 },
  chatHeader: { minHeight: 68, flexDirection: 'row', alignItems: 'center', paddingHorizontal: 4, gap: 2, borderBottomWidth: StyleSheet.hairlineWidth }, peerHeader: { flex: 1, minHeight: 48, flexDirection: 'row', alignItems: 'center', gap: 10 }, peerName: { fontSize: 15, lineHeight: 22, fontWeight: '600' }, messageList: { paddingHorizontal: 14, paddingBottom: 18, flexGrow: 1 }, dateRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 14 }, dateLine: { flex: 1, height: StyleSheet.hairlineWidth }, timelineRow: { flexDirection: 'row', gap: 10 }, avatarGutter: { width: 34, paddingTop: 2 }, authorLine: { flexDirection: 'row', alignItems: 'baseline', flexWrap: 'wrap', gap: 8, marginBottom: 3 }, authorName: { fontSize: 14, lineHeight: 21, fontWeight: '600' }, messageText: { fontSize: 16, lineHeight: 24 }, messageTap: { minHeight: 48 }, messageStatus: { flexDirection: 'row', alignItems: 'center', gap: 5, marginTop: 3 }, stateBanner: { paddingHorizontal: 14, paddingVertical: 10, flexDirection: 'row', alignItems: 'center', gap: 8 }, bannerText: { flex: 1, fontSize: 12, lineHeight: 19 },
  composerArea: { paddingHorizontal: 10, paddingTop: 10, paddingBottom: 8 }, composer: { flexDirection: 'row', alignItems: 'flex-end', borderRadius: 18, padding: 5, gap: 4 }, composerInput: { flex: 1, minHeight: 48, maxHeight: 144, paddingHorizontal: 10, paddingVertical: 12, fontSize: 15, lineHeight: 22 }, sendButton: { width: 48, height: 48, borderRadius: 14, alignItems: 'center', justifyContent: 'center' }, smallCentered: { fontSize: 10, lineHeight: 16, textAlign: 'center', paddingTop: 6 },
  settingsContent: { padding: 14, paddingTop: 20, paddingBottom: 30 }, themeRow: { minHeight: 56, borderRadius: 12, borderWidth: 1, marginBottom: 8, flexDirection: 'row', alignItems: 'center', gap: 10, paddingHorizontal: 12 }, swatches: { flexDirection: 'row', gap: 3 }, swatch: { width: 13, height: 18, borderRadius: 4 }, settingRow: { minHeight: 60, paddingVertical: 8, flexDirection: 'row', alignItems: 'center', gap: 6, borderBottomWidth: StyleSheet.hairlineWidth }, switchTarget: { minWidth: 48, minHeight: 48, alignItems: 'center', justifyContent: 'center' }, button: { minHeight: 48, minWidth: 48, paddingHorizontal: 12, alignItems: 'center', justifyContent: 'center', borderRadius: 12, marginVertical: 4 }, wallpaperSample: { height: 105, borderRadius: 14, padding: 8, gap: 6, flexDirection: 'row', overflow: 'hidden', marginBottom: 8 }, sampleDock: { width: 22, borderRadius: 8 }, sampleIsland: { flex: 1, borderRadius: 8, justifyContent: 'flex-end', padding: 6 }, sampleComposer: { height: 12, borderRadius: 5 }, body: { fontSize: 14, lineHeight: 23, marginVertical: 10 }, cardTitle: { fontSize: 18, lineHeight: 26, fontWeight: '600' }, centered: { textAlign: 'center', fontSize: 13, lineHeight: 21 }, empty: { alignItems: 'center', paddingVertical: 28, gap: 12 },
  lockScreen: { flex: 1, alignItems: 'center', justifyContent: 'center' }, lockCard: { width: 270, borderRadius: 26, borderWidth: 1, padding: 22, alignItems: 'center', gap: 10 }, logo: { width: 48, height: 48, borderRadius: 16, alignItems: 'center', justifyContent: 'center' }, logoMark: { fontSize: 24, lineHeight: 30, fontWeight: '700' }, lockBrand: { fontSize: 17, lineHeight: 24, fontWeight: '600', letterSpacing: 3 }, pinPreview: { width: '100%', minHeight: 48, borderWidth: 1, borderRadius: 14, alignItems: 'center', justifyContent: 'center' }, keypad: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, justifyContent: 'center', width: 200 }, key: { width: 56, height: 48, borderRadius: 14, alignItems: 'center', justifyContent: 'center' }, keyText: { fontSize: 17 },
  modalRoot: { flex: 1, justifyContent: 'flex-end' }, scrim: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(0,0,0,0.65)' }, sheet: { borderTopLeftRadius: 26, borderTopRightRadius: 26, maxHeight: '88%' }, sheetHeading: { flexDirection: 'row', alignItems: 'center', paddingLeft: 20, paddingRight: 10, paddingTop: 12 }, sheetContent: { paddingHorizontal: 20, paddingBottom: 24 }, license: { fontSize: 11, lineHeight: 17, marginTop: 20 },
});
