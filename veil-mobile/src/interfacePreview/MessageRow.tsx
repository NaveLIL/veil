import React, { memo } from 'react';
import { Platform, Pressable, StyleSheet, Text, View } from 'react-native';
import { Check, CircleAlert, Clock3 } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { DemoMessage, DemoChat } from './model';
import { MessageQuote } from './MessageQuote';
export const MessageRow = memo(function MessageRow({
  item,
  chat,
  grouped,
  c,
  onMessage,
  onRetry,
  onQuote,
  highlighted,
}: {
  item: DemoMessage;
  chat: DemoChat;
  grouped: boolean;
  c: Palette;
  onQuote?: (id: string) => void;
  highlighted?: boolean;
  onMessage: (message: DemoMessage) => void;
  onRetry: (chatId: string, messageId: string) => void;
}) {
  const status =
    item.delivery === 'queued'
      ? 'В очереди'
      : item.delivery === 'failed'
        ? 'Не отправлено'
        : item.delivery === 'unknown'
          ? 'Подтверждение неизвестно'
          : item.delivery === 'accepted'
            ? 'Отправлено'
            : '';
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
        {!grouped && (
          <View
            accessible={false}
            style={[styles.avatar, { backgroundColor: chat.color }]}
          >
            <Text style={styles.initials}>{initials}</Text>
          </View>
        )}
      </View>
      <View style={styles.flex}>
        {!grouped && (
          <View style={styles.author}>
            <Text
              style={[styles.name, { color: item.own ? c.accent : c.text }]}
            >
              {name}
            </Text>
            <Text style={[styles.caption, { color: c.muted }]}>
              {item.time}
            </Text>
          </View>
        )}
        {!!item.replyTo && (
          <MessageQuote
            chat={chat}
            id={item.replyTo}
            c={c}
            onPress={() => onQuote?.(item.replyTo!)}
          />
        )}
        <Pressable
          disabled={item.deleted}
          accessibilityRole="button"
          accessibilityLabel={`${name}: ${item.deleted ? 'Сообщение удалено' : item.text}. ${item.time}. ${status}`}
          onPress={() => onMessage(item)}
          onLongPress={() => onMessage(item)}
          style={styles.messageTap}
        >
          <Text style={[styles.messageText, { color: c.text }]}>
            {item.deleted ? 'Сообщение удалено' : item.text}
          </Text>
        </Pressable>
        {item.edited && !item.deleted && (
          <Text style={[styles.caption, { color: c.muted }]}>изменено</Text>
        )}
        {!!status && !item.deleted && (
          <View style={styles.status}>
            <StatusIcon size={13} color={c.muted} />
            <Text style={[styles.caption, { color: c.muted }]}>{status}</Text>
          </View>
        )}
        {item.delivery === 'failed' && !item.deleted && (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Повторить демо-сообщение"
            onPress={() => onRetry(chat.id, item.id)}
            style={styles.retry}
          >
            <Text style={[styles.caption, { color: c.accent }]}>Повторить</Text>
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
