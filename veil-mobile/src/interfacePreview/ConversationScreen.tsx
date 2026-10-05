import React, { useState } from 'react';
import { StyleSheet, View } from 'react-native';
import { CircleAlert, X, Pencil, WifiOff } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { DemoChat, DemoMessage, demoSpaces, Scenario } from './model';
import { IconButton, Label } from './Primitives';
import { ConversationHistory } from './ConversationHistory';
import { MessageQuote } from './MessageQuote';
import { QuoteJump } from './useMessageInteractions';
import { ConversationSurface } from './ConversationSurface';
import { Attachment } from './attachments';
import { AttachmentCard } from './AttachmentCard';
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
  onProfile: (handle?: number) => void;
  onScenarios: (handle?: number) => void;
  attachment?: Attachment;
  onAttach?: (handle?: number) => void;
  onRemoveAttachment?: () => void;
  onAttachment?: (asset: Attachment, handle?: number) => void;
  onCancelTransfer?: (chatId: string, id: string) => void;
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
  attachment,
  onAttach,
  onRemoveAttachment,
  onAttachment,
  onCancelTransfer,
}: Props) {
  const [compactViewport, setCompactViewport] = useState(false);
  const combinedContext =
    compactViewport && !!replyId && !!attachment && !editing;
  return (
    <ConversationSurface
      chat={chat}
      c={c}
      visible={visible}
      draft={draft}
      editing={editing}
      blocked={scenario === 'identityChanged'}
      onDraft={onDraft}
      onSend={onSend}
      hasAttachment={!!attachment && !editing}
      onAttach={onAttach}
      onBack={onBack}
      onProfile={onProfile}
      onMenu={onScenarios}
      notice={notice}
      subtitle={
        (chat.kind === 'channel'
          ? demoSpaces.find((s) => s.id === chat.space)?.name
          : chat.kind === 'group'
            ? 'Групповой чат'
            : 'Личный чат') + ' · демо'
      }
      onLayout={(event) =>
        setCompactViewport(event.nativeEvent.layout.height < 500)
      }
      history={
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
          onAttachment={onAttachment}
          onCancelTransfer={onCancelTransfer}
        />
      }
      banner={
        scenario !== 'normal' && (
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
        )
      }
      context={
        <>
          {' '}
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
          ) : combinedContext && replyId && attachment ? (
            <View
              testID="compact-composition-context"
              style={styles.previewRail}
            >
              <View style={styles.flex}>
                <MessageQuote
                  chat={chat}
                  id={replyId}
                  c={c}
                  compact
                  onPress={() => onQuote?.(replyId)}
                  onDismiss={() => onCancelComposition?.()}
                />
              </View>
              <View style={styles.flex}>
                <AttachmentCard
                  asset={attachment}
                  compact
                  dense
                  c={c}
                  onRemove={onRemoveAttachment}
                />
              </View>
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
          {attachment && !editing && !combinedContext && (
            <View style={styles.compositionQuote}>
              <AttachmentCard
                asset={attachment}
                compact
                c={c}
                onRemove={onRemoveAttachment}
              />
            </View>
          )}{' '}
        </>
      }
    />
  );
}
const styles = StyleSheet.create({
  conversation: { flex: 1 },
  previewRail: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: 6,
    marginHorizontal: 10,
    marginTop: 8,
  },
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
