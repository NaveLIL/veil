import React, { useRef, useState } from 'react';
import { VeilSheet } from './VeilSheet';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  AccessibilityInfo,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Copy, Pencil, Reply, Trash2, X } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { TimelineMessage, ConversationCapabilities, designCapabilities } from './conversationContract';
import { availableActions, MessageAction } from './messageActionCapabilities';
import { useAccessibilityFocus } from './AccessibilityFocusBoundary';

const labels: Record<MessageAction, string> = {
  reply: 'Ответить',
  copy: 'Копировать',
  edit: 'Редактировать',
  delete: 'Удалить',
};
const icons = { reply: Reply, copy: Copy, edit: Pencil, delete: Trash2 };
export function MessageActionsPanel({
  message,
  c,
  reduceMotion,
  onClose,
  onAction,
  capabilities = designCapabilities,
}: {
  message: TimelineMessage;
  capabilities?: ConversationCapabilities;
  c: Palette;
  reduceMotion: boolean;
  onClose: () => void;
  onAction: (action: MessageAction) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const heading = useRef<Text>(null);
  const focus = useAccessibilityFocus();
  return (
    <VeilSheet c={c} reduceMotion={reduceMotion} onClose={onClose}
      closeLabel="Закрыть действия сообщения" style={{ maxHeight: '75%', margin: geometry.inset }}
      onShow={() => { focus.cancel(); if (heading.current) AccessibilityInfo.sendAccessibilityEvent(heading.current, 'focus'); }}>
        <SafeAreaView
          edges={['bottom']}
          style={[
            styles.panel,
            { backgroundColor: c.surface, borderColor: c.line },
          ]}
        >
          <View style={styles.heading}>
            <Text
              ref={heading}
              accessible
              accessibilityRole="header"
              style={[styles.title, { color: c.text }]}
            >
              {confirming ? 'Удалить сообщение?' : 'Сообщение'}
            </Text>
          </View>
          <ScrollView contentContainerStyle={styles.content}>
            <Text
              numberOfLines={3}
              style={[styles.preview, { color: c.muted }]}
            >
              {message.text || message.attachment?.name}
            </Text>
            {confirming ? (
              <>
                <Text style={[styles.preview, { color: c.muted }]}>
                  В макете текст исчезнет, а ответы сохранят ссылку на удалённое
                  сообщение.
                </Text>
                <Action
                  label="Подтвердить удаление"
                  destructive
                  icon={Trash2}
                  c={c}
                  onPress={() => onAction('delete')}
                />
                <Action
                  label="Отмена"
                  icon={X}
                  c={c}
                  onPress={() => setConfirming(false)}
                />
              </>
            ) : (
              availableActions(message, capabilities).map((action) => (
                <Action
                  key={action}
                  label={labels[action]}
                  destructive={action === 'delete'}
                  icon={icons[action]}
                  c={c}
                  onPress={() =>
                    action === 'delete' ? setConfirming(true) : onAction(action)
                  }
                />
              ))
            )}
          </ScrollView>
        </SafeAreaView>
    </VeilSheet>
  );
}
function Action({
  label,
  icon: Icon,
  c,
  onPress,
  destructive = false,
}: {
  label: string;
  icon: typeof Copy;
  c: Palette;
  destructive?: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      onPress={onPress}
      style={({ pressed }) => [
        styles.action,
        { backgroundColor: pressed ? c.tint : c.raised },
      ]}
    >
      <Icon size={20} color={destructive ? c.danger : c.accent} />
      <Text
        style={[styles.actionText, { color: destructive ? c.danger : c.text }]}
      >
        {label}
      </Text>
    </Pressable>
  );
}
const styles = StyleSheet.create({
  root: {
    flex: 1,
    justifyContent: 'flex-end',

  },
  panel: {
    flexShrink: 1,
    overflow: 'hidden',
  },
  heading: {
    paddingLeft: 18,
    paddingRight: 6,
    flexDirection: 'row',
    alignItems: 'center',
  },
  title: { flex: 1, ...typography.heading, fontWeight: '600' },
  content: { padding: 12, paddingTop: 0, gap: 8 },
  preview: { ...typography.body, padding: 6 },
  action: {
    minHeight: geometry.touchTarget,
    borderRadius: geometry.radius,
    padding: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  actionText: { ...typography.body, flex: 1 },
});
