/** Isolated presentation workbench. Fixtures never enter the Veil runtime. */
import React, {
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
} from 'react';
import {
  AccessibilityInfo,
  Animated,
  BackHandler,
  Image,
  Keyboard,
  StatusBar,
  StyleSheet,
  View,
} from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { createDemoSession, openChat, receiveDemo, retryDemo } from './model';
import { geometry, motion, palettes, ThemeName } from './appearance';
import { pickWallpaper } from './appearanceBridge';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { ChatDeck } from './ChatDeck';
import { deckReducer, initialDeck } from './navigation';
import { FloatingProfile, ProfilePanel } from './UserProfile';
import { AppearanceSettings } from './AppearanceSettings';
import { NavigationPanel } from './NavigationPanel';
import { ConversationScreen } from './ConversationScreen';
import { LockPreview } from './LockPreview';
import { PreviewSheet, Sheet } from './PreviewSheet';
import { useMessageInteractions } from './useMessageInteractions';
import { MessageActionsPanel } from './MessageActionsPanel';
import { KeyboardFrame } from './KeyboardFrame';

export function DesignApp() {
  return (
    <SafeAreaProvider>
      <GestureHandlerRootView style={styles.root}>
        <Workbench />
      </GestureHandlerRootView>
    </SafeAreaProvider>
  );
}
function Workbench() {
  const [session, setSession] = useState(createDemoSession);
  const [destination, setDestination] = useState('messages');
  const [deck, dispatchDeck] = useReducer(deckReducer, initialDeck);
  const chatId = deck.activeChatId;
  const [ownProfileOpen, setOwnProfileOpen] = useState(false);
  const [ownProfile, setOwnProfile] = useState({
    name: 'Veil User',
    bio: 'Человек, разговор и немного красивого интерфейса.',
  });
  const [query, setQuery] = useState('');
  const [searchVisible, setSearchVisible] = useState(false);
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [newChat, setNewChat] = useState(false);
  const [sheet, setSheet] = useState<Sheet>(null);
  const interactions = useMessageInteractions(session, setSession, chatId);
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
  const chat = session.chats.find((item) => item.id === chatId);
  const transition = useRef(new Animated.Value(1)).current;
  const noMotion = reduceMotion || systemReduceMotion;
  useEffect(() => {
    let alive = true;
    AccessibilityInfo.isReduceMotionEnabled().then((value) => {
      if (alive) setSystemReduceMotion(value);
    });
    const subscription = AccessibilityInfo.addEventListener(
      'reduceMotionChanged',
      setSystemReduceMotion,
    );
    return () => {
      alive = false;
      subscription.remove();
    };
  }, []);
  useEffect(() => {
    transition.stopAnimation();
    if (noMotion) {
      transition.setValue(1);
      return;
    }
    transition.setValue(0);
    const animation = Animated.timing(transition, {
      toValue: 1,
      duration: motion.transitionDuration,
      useNativeDriver: true,
    });
    animation.start();
    return () => animation.stop();
  }, [destination, locked, noMotion, transition]);
  const back = useCallback(() => {
    if (interactions.selection) {
      interactions.close();
      return true;
    }
    if (sheet) {
      setSheet(null);
      return true;
    }
    if (locked) {
      setLocked(false);
      return true;
    }
    if (ownProfileOpen) {
      setOwnProfileOpen(false);
      return true;
    }
    if (chatId && !deck.navigationOpen) {
      Keyboard.dismiss();
      dispatchDeck({ type: 'reveal' });
      return true;
    }
    if (newChat) {
      setNewChat(false);
      return true;
    }
    if (destination !== 'messages') {
      setDestination('messages');
      return true;
    }
    if (searchVisible) {
      setSearchVisible(false);
      return true;
    }
    return false;
  }, [
    interactions,
    sheet,
    locked,
    ownProfileOpen,
    chatId,
    deck.navigationOpen,
    newChat,
    destination,
    searchVisible,
  ]);
  useEffect(() => {
    const subscription = BackHandler.addEventListener(
      'hardwareBackPress',
      back,
    );
    return () => subscription.remove();
  }, [back]);
  function enterChat(id: string) {
    Keyboard.dismiss();
    setSession((s) => openChat(s, id));
    dispatchDeck({ type: 'choose', id });
  }
  const retryMessage = useCallback(
    (id: string, messageId: string) =>
      setSession((s) => retryDemo(s, id, messageId)),
    [],
  );
  const readMessages = useCallback(
    (id: string) => setSession((s) => openChat(s, id)),
    [],
  );
  function addIncoming(count: number) {
    if (!chatId) return;
    const now = new Date();
    setSession((s) =>
      receiveDemo(
        s,
        chatId,
        count,
        `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`,
      ),
    );
    setSheet(null);
  }
  async function chooseWallpaper() {
    if (picking) return;
    setPicking(true);
    setPickerError('');
    try {
      const uri = await pickWallpaper();
      if (uri) {
        setWallpaper(uri);
        setShowWallpaper(true);
      }
    } catch {
      setPickerError(
        'Не удалось открыть изображение. Выберите другое или меньшего размера.',
      );
    } finally {
      setPicking(false);
    }
  }
  const animatedStyle = {
    opacity: transition,
    transform: [
      {
        translateY: transition.interpolate({
          inputRange: [0, 1],
          outputRange: [8, 0],
        }),
      },
    ],
  };
  const appearanceSettings = (
    <AppearanceSettings
      c={c}
      theme={theme}
      setTheme={setTheme}
      wallpaper={wallpaper}
      setWallpaper={setWallpaper}
      showWallpaper={showWallpaper}
      setShowWallpaper={setShowWallpaper}
      dim={dim}
      setDim={setDim}
      blur={blur}
      setBlur={setBlur}
      reduceMotion={reduceMotion}
      setReduceMotion={setReduceMotion}
      systemReduceMotion={systemReduceMotion}
      picking={picking}
      pickerError={pickerError}
      chooseWallpaper={chooseWallpaper}
      onLock={() => {
        setOwnProfileOpen(false);
        setLocked(true);
      }}
      onScenarios={() => {
        setOwnProfileOpen(false);
        setSheet('scenarios');
      }}
      onAbout={() => {
        setOwnProfileOpen(false);
        setSheet('about');
      }}
    />
  );
  return (
    <View style={[styles.root, { backgroundColor: '#050507' }]}>
      {showWallpaper && !locked && (
        <View pointerEvents="none" style={styles.wallpaper}>
          {wallpaper ? (
            <Image
              source={{ uri: wallpaper }}
              resizeMode="cover"
              blurRadius={blur}
              style={StyleSheet.absoluteFillObject}
            />
          ) : (
            <View style={styles.defaultWallpaper}>
              <View
                style={[
                  styles.glow,
                  styles.glowOne,
                  { backgroundColor: c.accent },
                ]}
              />
              <View
                style={[
                  styles.glow,
                  styles.glowTwo,
                  { backgroundColor: c.accent },
                ]}
              />
              <View
                style={[
                  styles.glow,
                  styles.glowThree,
                  { backgroundColor: c.accent },
                ]}
              />
            </View>
          )}
          <View
            style={[
              StyleSheet.absoluteFillObject,
              { backgroundColor: `rgba(0,0,0,${dim / 100})` },
            ]}
          />
        </View>
      )}
      <KeyboardFrame>
        <SafeAreaView edges={['top', 'bottom']} style={styles.safe}>
          <StatusBar barStyle="light-content" backgroundColor="transparent" />
          {locked ? (
            <LockPreview
              c={c}
              animatedStyle={animatedStyle}
              onClose={() => setLocked(false)}
            />
          ) : (
            <ChatDeck
              surfaceColor={c.bg}
              edgeColor={c.line}
              navigationOpen={deck.navigationOpen}
              hasChat={!!chat}
              enabled={!sheet && !ownProfileOpen && !interactions.selection}
              reduceMotion={noMotion}
              onNavigationChange={(open) =>
                dispatchDeck({ type: open ? 'reveal' : 'resume' })
              }
              profile={
                <FloatingProfile
                  c={c}
                  profile={ownProfile}
                  onOpen={() => setOwnProfileOpen(true)}
                  hasChat={!!chat}
                  onResume={() => dispatchDeck({ type: 'resume' })}
                />
              }
              conversation={
                chat ? (
                  <ConversationScreen
                    chat={chat}
                    chats={session.chats}
                    draft={interactions.draft}
                    replyId={interactions.replyId}
                    editing={!!interactions.edit}
                    jump={interactions.jump}
                    notice={interactions.notice}
                    selectedMessageId={interactions.message?.id}
                    onQuote={interactions.jumpTo}
                    onNotice={interactions.report}
                    onCancelComposition={interactions.cancel}
                    scenario={session.scenario}
                    visible={
                      !deck.navigationOpen &&
                      !sheet &&
                      !ownProfileOpen &&
                      !interactions.selection
                    }
                    c={c}
                    reduceMotion={noMotion}
                    onDraft={interactions.change}
                    onSend={interactions.submit}
                    onMessage={interactions.inspect}
                    onRetry={retryMessage}
                    onRead={readMessages}
                    onBack={() => {
                      Keyboard.dismiss();
                      dispatchDeck({ type: 'reveal' });
                    }}
                    onProfile={() => setSheet('profile')}
                    onScenarios={() => setSheet('scenarios')}
                  />
                ) : null
              }
              navigation={(dimStyle) => (
                <NavigationPanel
                  c={c}
                  session={session}
                  destination={destination}
                  setDestination={setDestination}
                  query={query}
                  setQuery={setQuery}
                  searchVisible={searchVisible}
                  setSearchVisible={setSearchVisible}
                  unreadOnly={unreadOnly}
                  setUnreadOnly={setUnreadOnly}
                  newChat={newChat}
                  setNewChat={setNewChat}
                  enterChat={enterChat}
                  animatedStyle={animatedStyle}
                  dimStyle={dimStyle}
                />
              )}
            />
          )}
          <ProfilePanel
            open={ownProfileOpen && deck.navigationOpen && !locked}
            onClose={() => setOwnProfileOpen(false)}
            c={c}
            reduceMotion={noMotion}
            profile={ownProfile}
            onProfileChange={setOwnProfile}
            appearance={appearanceSettings}
            onLock={() => {
              setOwnProfileOpen(false);
              setLocked(true);
            }}
            onAbout={() => {
              setOwnProfileOpen(false);
              setSheet('about');
            }}
            onScenarios={() => {
              setOwnProfileOpen(false);
              setSheet('scenarios');
            }}
          />
          {interactions.message && (
            <MessageActionsPanel
              key={interactions.message.id}
              message={interactions.message}
              c={c}
              reduceMotion={noMotion}
              onClose={interactions.close}
              onAction={interactions.action}
            />
          )}
          <PreviewSheet
            sheet={sheet}
            chat={chat}
            scenario={session.scenario}
            c={c}
            reduceMotion={noMotion}
            onClose={() => setSheet(null)}
            onScenario={(scenario) => setSession((s) => ({ ...s, scenario }))}
            addIncoming={addIncoming}
          />
        </SafeAreaView>
      </KeyboardFrame>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1 },
  wallpaper: { ...StyleSheet.absoluteFillObject },
  defaultWallpaper: { flex: 1, overflow: 'hidden', backgroundColor: '#100A19' },
  glow: {
    position: 'absolute',
    opacity: 0.2,
    borderRadius: 180,
    transform: [{ rotate: '-25deg' }],
  },
  glowOne: { width: 320, height: 170, top: -30, left: -150 },
  glowTwo: { width: 350, height: 150, top: '42%', right: -210 },
  glowThree: { width: 340, height: 160, bottom: -50, left: -120 },
  flex: { flex: 1, minWidth: 0 },
  safe: {
    flex: 1,
    paddingHorizontal: geometry.inset,
    paddingBottom: geometry.inset,
  },
});
