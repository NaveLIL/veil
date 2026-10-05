import React, { useRef } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { FileText, X } from 'lucide-react-native';
import type { Attachment, Transfer } from './attachmentContract';
import { geometry, Palette, typography } from './appearance';
import { AttachmentVisual } from './AttachmentVisual';
import { useAccessibilityFocus } from './AccessibilityFocusBoundary';
import { IconButton } from './Primitives';
export function AttachmentCard({
  asset,
  transfer,
  compact,
  dense = false,
  c,
  onOpen,
  onRemove,
  onRetry,
  onCancel,
}: {
  asset: Attachment;
  transfer?: Transfer;
  compact?: boolean;
  dense?: boolean;
  c: Palette;
  onOpen?: (handle?: number) => void;
  onRemove?: () => void;
  onRetry?: () => void;
  onCancel?: () => void;
}) {
  const trigger = useRef<View>(null);
  const focus = useAccessibilityFocus();
  return (
    <View
      style={[
        styles.card,
        dense && styles.denseCard,
        { backgroundColor: c.surface, borderColor: c.line },
      ]}
    >
      {asset.kind === 'image' && !compact && (
        <Pressable
          ref={trigger}
          accessibilityRole="imagebutton"
          accessibilityLabel={`Открыть изображение: ${asset.name}`}
          onPress={() => onOpen?.(focus.remember(trigger))}
          disabled={!onOpen}
          style={[styles.picture, { aspectRatio: asset.width / asset.height }]}
        >
          <AttachmentVisual />
        </Pressable>
      )}
      <View style={[styles.summary, dense && styles.denseSummary]}>
        {dense ? null : asset.kind === 'image' && compact ? (
          <View style={styles.thumbnail}>
            <AttachmentVisual />
          </View>
        ) : (
          <FileText size={20} color={c.accent} />
        )}
        <View style={styles.flex}>
          <Text
            numberOfLines={compact ? 1 : 2}
            style={[styles.body, { color: c.text }]}
          >
            {asset.name}
          </Text>
          <Text
            numberOfLines={dense ? 1 : undefined}
            style={[styles.caption, { color: c.muted }]}
          >
            {dense
              ? asset.kind === 'image'
                ? 'Изображение · демо'
                : 'Файл · демо'
              : asset.kind === 'file'
                ? `${asset.bytes.toLocaleString('ru')} Б · ${asset.mediaType}`
                : compact
                  ? 'Иллюстрация · демо'
                  : `${asset.width} × ${asset.height} · демо`}
          </Text>
        </View>
        {onRemove && (
          <IconButton
            icon={X}
            label="Убрать вложение"
            color={c.muted}
            onPress={onRemove}
          />
        )}
      </View>
      {transfer && transfer.phase !== 'complete' && (
        <View style={styles.operation}>
          <Text style={[styles.caption, { color: c.muted }]}>
            {transfer.phase === 'sending'
              ? `Демо: отправка ${transfer.progress}%`
              : transfer.phase === 'cancelled'
                ? 'Демо: отправка отменена'
                : transfer.phase === 'unknown'
                  ? 'Демо: результат отправки неизвестен'
                  : transfer.phase === 'waiting'
                    ? 'Демо: нет сети · в очереди'
                    : 'Демо: не удалось отправить'}
          </Text>
          {transfer.phase === 'sending' && (
            <View
              accessibilityRole="progressbar"
              accessibilityValue={{ min: 0, max: 100, now: transfer.progress }}
              style={[styles.track, { backgroundColor: c.line }]}
            >
              <View
                style={[
                  styles.fill,
                  { backgroundColor: c.accent, width: `${transfer.progress}%` },
                ]}
              />
            </View>
          )}
          {transfer.phase !== 'unknown' && (
            <Pressable
              accessibilityRole="button"
              onPress={transfer.phase === 'sending' ? onCancel : onRetry}
              style={styles.action}
            >
              <Text style={[styles.body, { color: c.accent }]}>
                {transfer.phase === 'sending'
                  ? 'Отменить отправку'
                  : 'Повторить отправку вложения'}
              </Text>
            </Pressable>
          )}
        </View>
      )}
    </View>
  );
}
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  denseCard: { marginTop: 0 },
  denseSummary: { padding: 4, gap: 4 },
  thumbnail: {
    width: 48,
    height: 32,
    borderRadius: geometry.radius,
    overflow: 'hidden',
  },
  card: {
    borderRadius: geometry.radius,
    overflow: 'hidden',
    borderWidth: 1,
    marginTop: 6,
  },
  picture: { width: '100%', maxHeight: 260 },
  summary: {
    flexDirection: 'row',
    gap: 10,
    alignItems: 'center',
    padding: 10,
    minHeight: geometry.touchTarget,
  },
  body: { ...typography.body },
  caption: { ...typography.caption },
  operation: { paddingHorizontal: 12 },
  action: { minHeight: geometry.touchTarget, justifyContent: 'center' },
  track: { height: 3, borderRadius: 2, overflow: 'hidden', marginTop: 6 },
  fill: { height: 3 },
});
