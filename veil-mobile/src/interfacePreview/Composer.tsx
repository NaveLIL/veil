import React, { useState } from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  useWindowDimensions,
  View,
} from 'react-native';
import { ArrowUp, Plus } from 'lucide-react-native';
import { IconButton } from './Primitives';
import { geometry, Palette, typography } from './appearance';

export function Composer({
  value,
  editing,
  onChange,
  onSend,
  blocked,
  placeholder,
  c,
  hasAttachment = false,
  onAttach,
  mode = 'demo',
  pending = false,
}: {
  value: string;
  editing?: boolean;
  onChange: (text: string) => void;
  onSend: () => void;
  blocked: boolean;
  placeholder: string;
  c: Palette;
  hasAttachment?: boolean;
  onAttach?: (handle?: number) => void;
  mode?: 'demo' | 'native';
  pending?: boolean;
}) {
  const { fontScale, height: viewportHeight } = useWindowDimensions();
  const [contentHeight, setContentHeight] = useState(48);
  const minHeight = Math.max(48, Math.ceil(22 * fontScale + 24));
  const maxHeight = Math.max(
    minHeight,
    Math.min(
      Math.ceil(22 * fontScale * 5 + 24),
      Math.floor(viewportHeight * 0.22),
    ),
  );
  const height = Math.min(
    maxHeight,
    Math.max(minHeight, value ? contentHeight : minHeight),
  );
  const disabled = blocked || pending || (!value.trim() && !hasAttachment);
  // The chat name is already in the header. Keep the empty field readable
  // when system text scaling leaves less width between its two actions.
  const fieldPlaceholder = blocked
    ? fontScale >= 1.3
      ? 'Остановлено'
      : 'Отправка остановлена'
    : fontScale >= 1.3
      ? 'Сообщение'
      : placeholder;
  return (
    <View style={styles.area}>
      <View style={[styles.composer, { backgroundColor: c.raised }]}>
        {onAttach && !blocked && !editing && (
          <IconButton
            icon={Plus}
            label="Добавить вложение"
            color={c.muted}
            onPress={onAttach}
          />
        )}
        <TextInput
          testID={mode === 'native' ? 'direct-composer' : 'preview-composer'}
          accessibilityLabel={
            mode === 'demo' ? 'Текст демо-сообщения' : 'Текст сообщения'
          }
          value={value}
          onChangeText={onChange}
          placeholder={fieldPlaceholder}
          placeholderTextColor={c.muted}
          editable={!blocked}
          accessibilityState={{ disabled: blocked }}
          multiline
          maxLength={mode === 'demo' ? 4000 : 16384}
          submitBehavior="newline"
          textAlignVertical="top"
          scrollEnabled={contentHeight > maxHeight}
          onContentSizeChange={(event) =>
            setContentHeight(Math.ceil(event.nativeEvent.contentSize.height))
          }
          style={[styles.input, { height, color: c.text }]}
          underlineColorAndroid="transparent"
          keyboardAppearance="dark"
        />
        <Pressable
          testID={mode === 'native' ? 'direct-send-button' : undefined}
          onPress={onSend}
          disabled={disabled}
          accessibilityRole="button"
          accessibilityLabel={
            editing
              ? 'Сохранить изменения'
              : mode === 'demo'
                ? 'Отправить демо-сообщение'
                : 'Отправить сообщение'
          }
          accessibilityState={{ disabled, busy: pending }}
          style={({ pressed }) => [
            styles.send,
            {
              backgroundColor: c.accent,
              opacity: disabled ? 0.35 : pressed ? 0.75 : 1,
            },
          ]}
        >
          <ArrowUp size={22} color="#101015" />
        </Pressable>
      </View>
      <Text style={[styles.note, { color: c.muted }]}>
        {mode === 'demo'
          ? 'Демо · сообщения остаются на этом устройстве'
          : 'Личные сообщения · Veil'}
      </Text>
    </View>
  );
}
const styles = StyleSheet.create({
  area: { paddingHorizontal: 10, paddingTop: 10, paddingBottom: 8 },
  composer: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    borderRadius: geometry.radius,
    padding: 5,
    gap: 4,
  },
  input: {
    flex: 1,
    paddingHorizontal: 10,
    paddingVertical: 12,
    ...typography.body,
  },
  send: {
    minWidth: geometry.touchTarget,
    minHeight: geometry.touchTarget,
    width: geometry.touchTarget,
    height: geometry.touchTarget,
    borderRadius: geometry.radius,
    alignItems: 'center',
    justifyContent: 'center',
  },
  note: { ...typography.micro, textAlign: 'center', paddingTop: 6 },
});
