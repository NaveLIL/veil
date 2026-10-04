import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { Reply } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { DemoChat } from './model';

export function MessageQuote({
  chat,
  id,
  c,
  onPress,
}: {
  chat: DemoChat;
  id: string;
  c: Palette;
  onPress: () => void;
}) {
  const original = chat.messages.find((m) => m.id === id);
  const name = original?.own ? 'Вы' : (original?.author ?? chat.name);
  const text = !original
    ? 'Оригинал недоступен'
    : original.deleted
      ? 'Сообщение удалено'
      : original.text;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`Перейти к оригиналу: ${name}. ${text}`}
      onPress={onPress}
      style={[styles.quote, { backgroundColor: c.tint, borderColor: c.accent }]}
    >
      <Reply size={16} color={c.accent} />
      <View style={styles.flex}>
        <Text numberOfLines={1} style={[styles.name, { color: c.accent }]}>
          {name}
        </Text>
        <Text numberOfLines={2} style={[styles.text, { color: c.muted }]}>
          {text}
        </Text>
      </View>
    </Pressable>
  );
}
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  quote: {
    minHeight: geometry.touchTarget,
    borderRadius: geometry.radius,
    borderLeftWidth: 2,
    padding: 10,
    gap: 8,
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
  },
  name: { ...typography.name, fontWeight: '600' },
  text: { ...typography.caption },
});
