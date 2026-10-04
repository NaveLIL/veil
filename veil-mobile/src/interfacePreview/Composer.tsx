import React, { useState } from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  useWindowDimensions,
  View,
} from 'react-native';
import { ArrowUp } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';

export function Composer({
  value,
  editing,
  onChange,
  onSend,
  blocked,
  placeholder,
  c,
}: {
  value: string;
  editing?: boolean;
  onChange: (text: string) => void;
  onSend: () => void;
  blocked: boolean;
  placeholder: string;
  c: Palette;
}) {
  const { fontScale } = useWindowDimensions();
  const [contentHeight, setContentHeight] = useState(48);
  const minHeight = Math.max(48, Math.ceil(22 * fontScale + 24));
  const maxHeight = Math.max(minHeight, Math.ceil(22 * fontScale * 5 + 24));
  const height = Math.min(
    maxHeight,
    Math.max(minHeight, value ? contentHeight : minHeight),
  );
  const disabled = blocked || !value.trim();
  return (
    <View style={styles.area}>
      <View style={[styles.composer, { backgroundColor: c.raised }]}>
        <TextInput
          testID="preview-composer"
          accessibilityLabel="Текст демо-сообщения"
          value={value}
          onChangeText={onChange}
          placeholder={blocked ? 'Отправка остановлена' : placeholder}
          placeholderTextColor={c.muted}
          editable={!blocked}
          multiline
          maxLength={4000}
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
          onPress={onSend}
          disabled={disabled}
          accessibilityRole="button"
          accessibilityLabel={
            editing ? 'Сохранить изменения' : 'Отправить демо-сообщение'
          }
          accessibilityState={{ disabled }}
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
        Демо · сообщения остаются на этом устройстве
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
    width: geometry.touchTarget,
    height: geometry.touchTarget,
    borderRadius: geometry.radius,
    alignItems: 'center',
    justifyContent: 'center',
  },
  note: { ...typography.micro, textAlign: 'center', paddingTop: 6 },
});
