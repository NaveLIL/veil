/** Isolated presentation workbench. Fixtures never enter the Veil runtime. */
import React, {
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
} from 'react';
import {
  BackHandler,
  Keyboard,
  StatusBar,
  StyleSheet,
  View,
} from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { createDemoSession, receiveDemo } from './model';
import { geometry } from './appearance';
import { useDesignAppearance } from './useDesignAppearance';
import { DesignConversation } from './DesignConversation';
import { ChatDeck } from './ChatDeck';
import { deckReducer, initialDeck } from './navigation';
import { FloatingProfile, ProfilePanel } from './UserProfile';
import { NavigationPanel } from './NavigationPanel';
import { LockPreview } from './LockPreview';
import { PreviewSheet, Sheet } from './PreviewSheet';
import { KeyboardFrame } from './KeyboardFrame';
import { AccessibilityFocusBoundary } from './AccessibilityFocusBoundary';
import { requestDesignAccessibilityFocus } from './designAccessibilityBridge';
import { ModalBlurBoundary } from './LiveBlur';

export function DesignApp() {
  return (
    <SafeAreaProvider>
      <GestureHandlerRootView style={styles.root}>
        <AccessibilityFocusBoundary
          requestFocus={requestDesignAccessibilityFocus}
        >
          <ModalBlurBoundary><Workbench /></ModalBlurBoundary>
        </AccessibilityFocusBoundary>
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
  const profileReturnFocus = useRef<number | undefined>(undefined);
  const sheetReturnFocus = useRef<number | undefined>(undefined);
  const [ownProfile, setOwnProfile] = useState({
    name: 'Veil User',
    bio: 'Человек, разговор и немного красивого интерфейса.',
  });
  const [query, setQuery] = useState('');
  const [searchVisible, setSearchVisible] = useState(false);
  const [newChat, setNewChat] = useState(false);
  const [sheet, setSheet] = useState<Sheet>(null);
  const [locked, setLocked] = useState(false);
  const [conversationOverlay, setConversationOverlay] = useState(false);
  const chat = session.chats.find((item) => item.id === chatId);
  const {
    c,
    ready,
    noMotion,
    animatedStyle,
    settings: appearanceSettings,
    background,
  } = useDesignAppearance(destination, locked, {
    onLock: () => {
      setOwnProfileOpen(false);
      setLocked(true);
    },
    onScenarios: () => {
      setOwnProfileOpen(false);
      setSheet('scenarios');
    },
    onAbout: () => {
      setOwnProfileOpen(false);
      setSheet('about');
    },
  });
  const back = useCallback(() => {
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
    dispatchDeck({ type: 'choose', id });
  }
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
  if (!ready)
    return (
      <View
        key="appearance-loading"
        style={[styles.root, { backgroundColor: '#050507' }]}
        accessibilityLabel="Загрузка оформления Veil"
        accessibilityRole="progressbar"
      />
    );
  return (
    <View key="workbench" style={[styles.root, { backgroundColor: '#050507' }]}>
      {background}
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
              enabled={!sheet && !ownProfileOpen && !conversationOverlay}
              reduceMotion={noMotion}
              onNavigationChange={(open) =>
                dispatchDeck({ type: open ? 'reveal' : 'resume' })
              }
              profile={
                <FloatingProfile
                  c={c}
                  profile={ownProfile}
                  onOpen={(handle) => {
                    profileReturnFocus.current = handle;
                    setOwnProfileOpen(true);
                  }}
                />
              }
              conversation={
                chat ? (
                  <DesignConversation
                    session={session}
                    setSession={setSession}
                    chat={chat}
                    c={c}
                    reduceMotion={noMotion}
                    visible={!deck.navigationOpen && !sheet && !ownProfileOpen}
                    onOverlayChange={setConversationOverlay}
                    onBack={() => {
                      Keyboard.dismiss();
                      dispatchDeck({ type: 'reveal' });
                    }}
                    onProfile={(handle) => {
                      sheetReturnFocus.current = handle;
                      setSheet('profile');
                    }}
                    onScenarios={(handle) => {
                      sheetReturnFocus.current = handle;
                      setSheet('scenarios');
                    }}
                  />
                ) : null
              }
              navigation={() => (
                <NavigationPanel
                  c={c}
                  session={session}
                  destination={destination}
                  setDestination={setDestination}
                  query={query}
                  setQuery={setQuery}
                  searchVisible={searchVisible}
                  setSearchVisible={setSearchVisible}
                  newChat={newChat}
                  setNewChat={setNewChat}
                  enterChat={enterChat}
                  animatedStyle={animatedStyle}
                />
              )}
            />
          )}
          <ProfilePanel
            returnFocus={profileReturnFocus.current}
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
          <PreviewSheet
            returnFocus={sheetReturnFocus.current}
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
  safe: {
    flex: 1,
    paddingHorizontal: geometry.inset,
    paddingBottom: geometry.inset,
  },
});
