import React from 'react';
import { VeilSheet } from './VeilSheet';
import {
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { Attachment, designAttachments } from './attachments';
import { AttachmentVisual } from './AttachmentVisual';
import { Button } from './Primitives';
import { Palette, typography } from './appearance';
import { useModalAccessibility } from './useModalAccessibility';
export function AttachmentPicker({
  c,
  reduceMotion,
  onChoose,
  onClose,
  returnFocus,
}: {
  c: Palette;
  reduceMotion: boolean;
  onChoose: (asset: Attachment) => void;
  onClose: () => void;
  returnFocus?: number;
}) {
  const focus = useModalAccessibility(true, returnFocus);
  return (
    <VeilSheet c={c} reduceMotion={reduceMotion} onClose={onClose} onShow={focus.onShow}
      closeLabel="Закрыть выбор вложения" style={{ maxHeight: '75%' }}>
        <SafeAreaView
          edges={['bottom']}
          style={[styles.panel, { backgroundColor: c.bg, borderColor: c.line }]}
        >
          <View style={styles.heading}>
            <Text
              ref={focus.heading}
              accessible
              accessibilityRole="header"
              style={[styles.title, styles.flex, { color: c.text }]}
            >
              Вложение
            </Text>
          </View>
          <ScrollView contentContainerStyle={styles.content}>
            <Text style={[styles.body, { color: c.muted }]}>
              Демо-источник. Выбираем встроенную иллюстрацию или пример файла;
              галерея, чтение файлов и настоящая отправка ещё не подключены.
            </Text>
            {designAttachments.map((asset) => (
              <Button
                key={asset.kind}
                label={
                  asset.kind === 'image' ? 'Демо-изображение' : 'Демо-файл'
                }
                c={c}
                onPress={() => onChoose(asset)}
              />
            ))}
          </ScrollView>
        </SafeAreaView>
    </VeilSheet>
  );
}
export function AttachmentViewer({
  asset,
  c,
  reduceMotion,
  onClose,
  returnFocus,
}: {
  asset: Attachment;
  c: Palette;
  reduceMotion: boolean;
  onClose: () => void;
  returnFocus?: number;
}) {
  const focus = useModalAccessibility(true, returnFocus);
  return (
    <VeilSheet c={c} reduceMotion={reduceMotion} onClose={onClose} onShow={focus.onShow}
      closeLabel="Закрыть изображение" style={{ height: '100%' }}>
      <SafeAreaView
        style={[styles.viewer, { backgroundColor: c.bg }]}
      >
        <View style={styles.heading}>
          <Text
            ref={focus.heading}
            accessible
            accessibilityRole="header"
            numberOfLines={2}
            style={[styles.body, styles.flex, { color: c.text }]}
          >
            {asset.name}
          </Text>
        </View>
        <View style={styles.stage}>
          {asset.kind === 'image' && (
            <View
              style={{ width: '100%', aspectRatio: asset.width / asset.height }}
            >
              <View
                accessible
                accessibilityRole="image"
                accessibilityLabel={asset.name}
              >
                <AttachmentVisual />
              </View>
            </View>
          )}
        </View>
        <Text style={[styles.foot, { color: c.muted }]}>
          Встроенная иллюстрация · демо
        </Text>
      </SafeAreaView>
    </VeilSheet>
  );
}
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  root: { flex: 1, justifyContent: 'flex-end' },
  panel: { flexShrink: 1 },
  heading: { flexDirection: 'row', alignItems: 'center', padding: 12, gap: 10 },
  title: { ...typography.heading, fontWeight: '600' },
  body: { ...typography.body },
  content: { padding: 16, gap: 12 },
  viewer: { flex: 1 },
  stage: { flex: 1, justifyContent: 'center' },
  foot: { ...typography.caption, padding: 20, textAlign: 'center' },
});
