import React from 'react';
import { Pressable, StyleSheet, View } from 'react-native';
import {
  ArrowLeft,
  CircleAlert,
  MoreHorizontal,
  X,
  Pencil,
  WifiOff,
} from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { DemoChat, DemoMessage, demoSpaces, Scenario } from './model';
import { Avatar, IconButton, Label } from './Primitives';
import { ConversationHistory } from './ConversationHistory';
import { MessageQuote } from './MessageQuote';
import { QuoteJump } from './useMessageInteractions';
import { Composer } from './Composer';
type Props = {
  chat: DemoChat;
  chats: DemoChat[];
  draft: string;
  scenario: Scenario;
  visible: boolean;
  c: Palette;
  reduceMotion: boolean;
  replyId?: string;
  editing?: boolean;
  selectedMessageId?: string;
  jump?: QuoteJump | null;
  notice?: string;
  onQuote?: (id: string) => void;
  onCancelComposition?: () => void;
  onNotice?: (text: string) => void;
  onDraft: (text: string) => void;
  onSend: () => void;
  onMessage: (message: DemoMessage) => void;
  onRetry: (chatId: string, messageId: string) => void;
  onRead: (chatId: string) => void;
  onBack: () => void;
  onProfile: () => void;
  onScenarios: () => void;
};
export function ConversationScreen({
  chat,
  chats,
  draft,
  scenario,
  visible,
  c,
  reduceMotion,
  replyId,
  editing,
  selectedMessageId,
  jump,
  notice,
  onQuote,
  onCancelComposition,
  onNotice,
  onDraft,
  onSend,
  onMessage,
  onRetry,
  onRead,
  onBack,
  onProfile,
  onScenarios,
}: Props) {
  return (
    <View
      testID="conversation-island"
      style={[styles.conversation, { backgroundColor: c.bg }]}
    >
      <View style={[styles.chatHeader, { borderBottomColor: c.line }]}>
        <IconButton
          icon={ArrowLeft}
          label="Назад к списку"
          onPress={onBack}
          color={c.text}
        />
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`Профиль: ${chat.name}`}
          onPress={onProfile}
          style={styles.peerHeader}
        >
          <Avatar chat={chat} size={36} />
          <View style={styles.flex}>
            <Label color={c.text} style={styles.peerName} numberOfLines={1}>
              {chat.kind === 'channel' ? `# ${chat.name}` : chat.name}
            </Label>
            <Label color={c.muted} style={styles.caption}>
              {chat.kind === 'channel'
                ? demoSpaces.find((s) => s.id === chat.space)?.name
                : chat.kind === 'group'
                  ? 'Групповой чат'
                  : 'Личный чат'}{' '}
              · демо
            </Label>
          </View>
        </Pressable>
        <IconButton
          icon={MoreHorizontal}
          label="Состояния и настройки макета"
          onPress={onScenarios}
          color={c.muted}
        />
      </View>
      <View style={styles.flex}>
        {scenario !== 'normal' && (
          <View style={[styles.stateBanner, { backgroundColor: c.tint }]}>
            {scenario === 'offline' ? (
              <WifiOff size={18} color={c.accent} />
            ) : (
              <CircleAlert size={18} color={c.accent} />
            )}
            <Label color={c.text} style={styles.bannerText}>
              {scenario === 'offline'
                ? 'Демо: сообщения остаются в очереди'
                : scenario === 'identityChanged'
                  ? 'Демо: ключ изменился. Отправка остановлена.'
                  : scenario === 'unknown'
                    ? 'Демо: подтверждение отправки неизвестно'
                    : 'Демо: следующая отправка завершится ошибкой'}
            </Label>
          </View>
        )}
        <ConversationHistory
          chats={chats}
          chatId={chat.id}
          visible={visible}
          c={c}
          reduceMotion={reduceMotion}
          onMessage={onMessage}
          selectedMessageId={selectedMessageId}
          jump={jump}
          onQuote={onQuote}
          onNotice={onNotice}
          onRetry={onRetry}
          onRead={onRead}
        />
        {!!notice && (
          <Label
            color={c.accent}
            style={styles.notice}
            accessibilityLiveRegion="polite"
          >
            {notice}
          </Label>
        )}
        {editing ? (
          <View style={[styles.context, { backgroundColor: c.raised }]}>
            <View style={styles.flex}>
              <View style={styles.editLabel}>
                <Pencil size={16} color={c.accent} />
                <Label color={c.text}>Редактирование сообщения</Label>
              </View>
            </View>
            <IconButton
              icon={X}
              label="Отменить редактирование"
              color={c.muted}
              onPress={() => onCancelComposition?.()}
            />
          </View>
        ) : replyId ? (
          <View style={styles.compositionQuote}>
            <MessageQuote
              chat={chat}
              id={replyId}
              c={c}
              onPress={() => onQuote?.(replyId)}
              onDismiss={() => onCancelComposition?.()}
            />
          </View>
        ) : null}
        <Composer
          key={chat.id}
          value={draft}
          editing={editing}
          onChange={onDraft}
          onSend={onSend}
          blocked={scenario === 'identityChanged'}
          placeholder={`Написать ${chat.kind === 'channel' ? '#' : '@'}${chat.name}`}
          c={c}
        />
      </View>
    </View>
  );
}
const styles = StyleSheet.create({
  conversation: { flex: 1 },
  notice: { ...typography.caption, paddingHorizontal: 14, paddingVertical: 8 },
  compositionQuote: { marginHorizontal: 10, marginTop: 8 },
  context: {
    flexDirection: 'row',
    alignItems: 'center',
    marginHorizontal: 10,
    marginTop: 8,
    paddingLeft: 10,
    borderRadius: geometry.radius,
  },
  editLabel: {
    flexDirection: 'row',
    gap: 8,
    alignItems: 'center',
    minHeight: geometry.touchTarget,
  },
  chatHeader: {
    minHeight: 68,
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 4,
    gap: 2,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
  peerHeader: {
    flex: 1,
    minHeight: geometry.touchTarget,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  flex: { flex: 1, minWidth: 0 },
  peerName: { ...typography.body, fontWeight: '600' },
  caption: { ...typography.caption },
  stateBanner: {
    paddingHorizontal: 14,
    paddingVertical: 10,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  bannerText: { flex: 1, ...typography.caption },
});
