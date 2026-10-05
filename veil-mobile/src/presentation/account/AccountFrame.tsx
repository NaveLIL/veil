import React, { useRef, useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { ChatDeck } from '../../interfacePreview/ChatDeck';
import { FloatingProfile } from '../../interfacePreview/ProfileEntry';
import { KeyboardFrame } from '../../interfacePreview/KeyboardFrame';
import { WallpaperSurface } from '../../interfacePreview/WallpaperSurface';
import { geometry } from '../../interfacePreview/appearance';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { useAccountAppearance } from '../appearance/AccountAppearance';
import { useChatStore } from '../../stores/chat';
import { UserAvatar } from '../../components/identity/UserAvatar';
import { AccountDirectory } from './AccountDirectory';
import { AccountProfile } from './AccountProfile';
import { VeilState } from '../../interfacePreview/VeilState';

/** Shared islands/deck/keyboard; account ownership stays in route/session controllers. */
export function AccountFrame({ conversation, navigationOpen = true, onNavigationChange = () => {},
  onOpen, onContacts, modalOpen = false, testID }: {
  conversation?: React.ReactNode; navigationOpen?: boolean; onNavigationChange?: (open: boolean) => void;
  onOpen: (id: string) => void; onContacts: () => void;
  modalOpen?: boolean; testID?: string;
}) {
  const { c, reduceMotion } = usePresentation(), appearance = useAccountAppearance();
  const binding = useChatStore(s => s.runtimeBinding);
  const [profileOpen, setProfileOpen] = useState(false), returnFocus = useRef<number | undefined>(undefined);
  if (!appearance.ready) return <VeilState kind="loading" c={c} title="Загрузка оформления Veil"
    detail="Восстанавливаем локальные настройки этого устройства." />;
  return <View testID={testID} style={styles.root}>
    <WallpaperSurface c={c} {...appearance} />
    <KeyboardFrame><SafeAreaView edges={['top', 'bottom', 'left', 'right']} style={styles.safe}>
      <ChatDeck surfaceColor={c.bg} edgeColor={c.line} hasChat={!!conversation} navigationOpen={navigationOpen}
        enabled={!modalOpen && !profileOpen} reduceMotion={reduceMotion} onNavigationChange={onNavigationChange}
        navigation={() => <AccountDirectory onOpen={onOpen} onContacts={onContacts} />}
        profile={<FloatingProfile c={c} profile={{ name: binding?.userId.slice(0, 8) ?? 'Аккаунт' }}
          caption="Ваш аккаунт"
          avatar={binding && <UserAvatar canonicalServerOrigin={binding.canonicalServerOrigin}
            userId={binding.userId} technicalUsername={binding.userId} size={44} />}
          onOpen={handle => { returnFocus.current = handle; setProfileOpen(true); }} />}
        conversation={conversation} />
      <AccountProfile open={profileOpen && navigationOpen} onClose={() => setProfileOpen(false)}
        returnFocus={returnFocus.current} />
    </SafeAreaView></KeyboardFrame>
  </View>;
}
const styles = StyleSheet.create({ root: { flex: 1, backgroundColor: '#050507' },
  safe: { flex: 1, paddingHorizontal: geometry.inset, paddingBottom: geometry.inset } });
