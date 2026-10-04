import React, { useState } from 'react';
import {
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Copy, Pencil, Reply, Trash2, X } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { DemoMessage } from './model';
import { availableActions, MessageAction } from './messageActions';
import { IconButton } from './Primitives';

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
}: {
  message: DemoMessage;
  c: Palette;
  reduceMotion: boolean;
  onClose: () => void;
  onAction: (action: MessageAction) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  return (
    <Modal
      visible
      transparent
      animationType={reduceMotion ? 'none' : 'fade'}
      onRequestClose={confirming ? () => setConfirming(false) : onClose}
      statusBarTranslucent
    >
      <View style={styles.root}>
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Закрыть действия сообщения"
          style={StyleSheet.absoluteFillObject}
          onPress={onClose}
        />
        <SafeAreaView
          edges={['bottom']}
          style={[
            styles.panel,
            { backgroundColor: c.surface, borderColor: c.line },
          ]}
        >
          <View style={styles.heading}>
            <Text
              accessibilityRole="header"
              style={[styles.title, { color: c.text }]}
            >
              {confirming ? 'Удалить сообщение?' : 'Сообщение'}
            </Text>
            <IconButton
              icon={X}
              label="Закрыть действия сообщения"
              color={c.muted}
              onPress={onClose}
            />
          </View>
          <ScrollView contentContainerStyle={styles.content}>
            <Text
              numberOfLines={3}
              style={[styles.preview, { color: c.muted }]}
            >
              {message.text}
            </Text>
            {confirming ? (
              <>
                <Text style={[styles.preview, { color: c.muted }]}>
                  В макете текст исчезнет, а ответы сохранят ссылку на удалённое
                  сообщение.
                </Text>
                <Action
                  label="Подтвердить удаление"
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
              availableActions(message).map((action) => (
                <Action
                  key={action}
                  label={labels[action]}
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
      </View>
    </Modal>
  );
}
function Action({
  label,
  icon: Icon,
  c,
  onPress,
}: {
  label: string;
  icon: typeof Copy;
  c: Palette;
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
      <Icon size={20} color={c.accent} />
      <Text style={[styles.actionText, { color: c.text }]}>{label}</Text>
    </Pressable>
  );
}
const styles = StyleSheet.create({
  root: {
    flex: 1,
    justifyContent: 'flex-end',
    backgroundColor: 'rgba(0,0,0,0.5)',
  },
  panel: {
    borderRadius: geometry.radius,
    borderWidth: geometry.borderWidth,
    margin: geometry.inset,
    maxHeight: '75%',
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
  actionText: { ...typography.body },
});
