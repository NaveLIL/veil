import React, { memo, useRef, useEffect } from 'react';
import {
  findNodeHandle,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { Check, CircleAlert, Clock3 } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import type {
  TimelineMessage,
  TimelineConversation,
} from './conversationContract';
import { MessageQuote } from './MessageQuote';
import { AttachmentCard } from './AttachmentCard';
import type { Attachment } from './attachmentContract';
import { deliveryLabel } from './deliveryPresentation';
import { useAccessibilityFocus } from './AccessibilityFocusBoundary';
export const MessageRow = memo(function MessageRow({
  item,
  chat,
  grouped,
  showStatus = true,
  c,
  onMessage,
  onRetry,
  onQuote,
  highlighted,
  selected = false,
  onAttachment,
  onCancelTransfer,
  retryEnabled = true,
  avatar,
  onAuthor,
  deliveryDetail,
}: {
  item: TimelineMessage;
  chat: TimelineConversation;
  grouped: boolean;
  showStatus?: boolean;
  c: Palette;
  onQuote?: (id: string) => void;
  highlighted?: boolean;
  selected?: boolean;
  onAttachment?: (asset: Attachment, handle?: number) => void;
  onCancelTransfer?: (chatId: string, id: string) => void;
  onMessage?: (message: TimelineMessage) => void;
  onRetry: (chatId: string, messageId: string) => void;
  retryEnabled?: boolean;
  avatar?: React.ReactNode;
  onAuthor?: (handle: number) => void;
  deliveryDetail?: React.ReactNode;
}) {
  const authorTrigger = useRef<View>(null);
  const messageButton = useRef<View>(null);
  const wasSelected = useRef(selected);
  const focus = useAccessibilityFocus();
  useEffect(() => {
    if (wasSelected.current && !selected) {
      const handle = focus.remember(messageButton);
      if (handle) focus.restore(handle);
    }
    wasSelected.current = selected;
  }, [selected, focus]);
  const status = item.own && !item.deleted ? deliveryLabel(item.delivery) : '';
  const StatusIcon =
    item.delivery === 'queued'
      ? Clock3
      : item.delivery === 'failed' || item.delivery === 'unknown'
        ? CircleAlert
        : Check;
  const name = item.own ? 'Вы' : (item.author ?? chat.name);
  const initials = item.own
    ? 'В'
    : item.author
      ? item.author.slice(0, 2).toUpperCase()
      : chat.initials;
  return (
    <View
      testID={`message-row-${item.id}`}
      style={[
        styles.row,
        {
          marginTop: grouped ? 2 : 18,
          borderRadius: geometry.radius,
          backgroundColor: highlighted ? c.tint : undefined,
        },
      ]}
    >
      <View style={styles.gutter}>
        {!grouped &&
          (avatar || (
            <View
              accessible={false}
              importantForAccessibility="no-hide-descendants"
              accessibilityElementsHidden
              style={[styles.avatar, { backgroundColor: chat.color }]}
            >
              <Text style={styles.initials} numberOfLines={1} adjustsFontSizeToFit>{initials}</Text>
            </View>
          ))}
      </View>
      <View style={styles.flex}>
        {!grouped && (
          <Pressable
            ref={authorTrigger}
            style={styles.author}
            accessible={!!onAuthor}
            importantForAccessibility={onAuthor ? 'auto' : 'no-hide-descendants'}
            accessibilityRole={onAuthor ? 'button' : undefined}
            accessibilityLabel={
              onAuthor ? `Сведения об отправителе: ${name}` : undefined
            }
            onPress={
              onAuthor
                ? () => {
                    const handle = findNodeHandle(authorTrigger.current);
                    if (handle) onAuthor(handle);
                  }
                : undefined
            }
          >
            <Text
              style={[styles.name, { color: item.own ? c.accent : c.text }]}
            >
              {name}
            </Text>
            <Text style={[styles.caption, { color: c.muted }]}>
              {item.time}
            </Text>
          </Pressable>
        )}
        {!!item.replyTo && (
          <MessageQuote
            chat={chat}
            id={item.replyTo}
            c={c}
            onPress={() => onQuote?.(item.replyTo!)}
          />
        )}
        {(!item.attachment || !!item.text || item.deleted) && (
          <Pressable
            ref={messageButton}
            disabled={item.deleted}
            accessibilityRole={onMessage ? 'button' : 'text'}
            accessibilityHint={
              onMessage ? 'Открыть действия сообщения' : undefined
            }
            accessibilityState={{ disabled: !!item.deleted }}
            accessibilityActions={
              item.deleted || !onMessage
                ? []
                : [{ name: 'longpress', label: 'Действия сообщения' }]
            }
            onAccessibilityAction={(event) => {
              if (!item.deleted && event.nativeEvent.actionName === 'longpress')
                onMessage?.(item);
            }}
            accessibilityLabel={`${name}: ${item.deleted ? 'Сообщение удалено' : item.text}. ${item.time}. ${status}`}
            onPress={onMessage ? () => onMessage(item) : undefined}
            onLongPress={onMessage ? () => onMessage(item) : undefined}
            style={styles.messageTap}
          >
            <Text style={[styles.messageText, { color: c.text }]}>
              {item.deleted ? 'Сообщение удалено' : item.text}
            </Text>
          </Pressable>
        )}
        {item.attachment && !item.deleted && (
          <>
            <AttachmentCard
              asset={item.attachment}
              transfer={item.transfer}
              c={c}
              onOpen={(handle) => onAttachment?.(item.attachment!, handle)}
              onRetry={() => onRetry(chat.id, item.id)}
              onCancel={() => onCancelTransfer?.(chat.id, item.id)}
            />
            {!item.text && (
              <Pressable
                ref={messageButton}
                accessibilityRole="button"
                accessibilityLabel={`Действия с вложением: ${item.attachment.name}. ${item.time}. ${status}`}
                onPress={() => onMessage?.(item)}
                style={styles.retry}
              >
                <Text style={[styles.caption, { color: c.muted }]}>
                  Действия
                </Text>
              </Pressable>
            )}
          </>
        )}
        {item.edited && !item.deleted && (
          <Text style={[styles.caption, { color: c.muted }]}>изменено</Text>
        )}
        {!!status &&
          showStatus &&
          !item.deleted &&
          (!item.transfer || item.transfer.phase === 'complete') && (
            <View
              testID={`delivery-${item.id}`}
              accessible={false}
              style={styles.status}
            >
              <StatusIcon size={13} color={c.muted} />
              <Text style={[styles.caption, { color: c.muted }]}>{status}</Text>
            </View>
          )}
        {deliveryDetail}
        {retryEnabled &&
          item.delivery === 'failed' &&
          !item.deleted &&
          !item.attachment && (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Повторить демо-сообщение"
              onPress={() => onRetry(chat.id, item.id)}
              style={styles.retry}
            >
              <Text style={[styles.caption, { color: c.accent }]}>
                Повторить
              </Text>
            </Pressable>
          )}
      </View>
    </View>
  );
});

const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  caption: { ...typography.caption },
  row: { flexDirection: 'row', gap: 10 },
  gutter: { width: 34, paddingTop: 2 },
  avatar: {
    width: 34,
    height: 34,
    borderRadius: 17,
    alignItems: 'center',
    justifyContent: 'center',
  },
  initials: { color: '#FFFFFF', fontSize: 12, fontWeight: '600' },
  author: {
    flexDirection: 'row',
    alignItems: 'baseline',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 3,
  },
  name: { ...typography.name, fontWeight: '600' },
  messageTap: { minHeight: geometry.touchTarget },
  messageText: {
    ...typography.message,
    ...Platform.select({ android: { includeFontPadding: false } }),
  },
  status: { flexDirection: 'row', alignItems: 'center', gap: 5, marginTop: 3 },
  retry: {
    alignSelf: 'flex-start',
    minHeight: geometry.touchTarget,
    justifyContent: 'center',
    paddingHorizontal: 8,
    borderRadius: geometry.radius,
  },
});
