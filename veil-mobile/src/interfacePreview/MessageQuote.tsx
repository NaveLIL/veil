import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { Reply, X } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import type { TimelineConversation } from './conversationContract';
import { IconButton } from './Primitives';

export function MessageQuote({
  chat,
  id,
  c,
  onPress,
  onDismiss,
  compact = false,
}: {
  chat: TimelineConversation;
  id: string;
  c: Palette;
  onPress: () => void;
  onDismiss?: () => void;
  compact?: boolean;
}) {
  const original = chat.messages.find((m) => m.id === id);
  const name = original?.own ? 'Вы' : (original?.author ?? chat.name);
  const text = !original
    ? 'Оригинал недоступен'
    : original.deleted
      ? 'Сообщение удалено'
      : original.text || original.attachment?.name || 'Вложение';
  return (
    <View
      style={[
        styles.quote,
        {
          backgroundColor: c.tint,
          borderColor: c.accent,
          marginBottom: onDismiss ? 0 : 6,
        },
      ]}
    >
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Перейти к оригиналу: ${name}. ${text}`}
        onPress={onPress}
        style={[styles.link, compact && styles.compactLink]}
      >
        {!compact && <Reply size={16} color={c.accent} />}
        <View style={styles.flex}>
          <Text numberOfLines={1} style={[styles.name, { color: c.accent }]}>
            {name}
          </Text>
          <Text
            numberOfLines={compact ? 1 : 2}
            style={[styles.text, { color: c.muted }]}
          >
            {text}
          </Text>
        </View>
      </Pressable>
      {onDismiss && (
        <IconButton
          icon={X}
          label="Отменить ответ"
          color={c.accent}
          onPress={onDismiss}
        />
      )}
    </View>
  );
}
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  quote: {
    minHeight: geometry.touchTarget,
    borderRadius: geometry.radius,
    borderLeftWidth: 2,
    paddingRight: 4,
    flexDirection: 'row',
    alignItems: 'center',
  },
  link: {
    flex: 1,
    minHeight: geometry.touchTarget,
    padding: 10,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  name: { ...typography.name, fontWeight: '600' },
  compactLink: { padding: 4 },
  text: { ...typography.caption },
});
