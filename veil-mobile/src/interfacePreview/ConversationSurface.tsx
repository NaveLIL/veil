import React from 'react';
import { Pressable, StyleSheet, View, findNodeHandle } from 'react-native';
import { ArrowLeft, MoreHorizontal } from 'lucide-react-native';
import type { TimelineConversation } from './conversationContract';
import { Palette, typography } from './appearance';
import { Avatar, IconButton, Label } from './Primitives';
import { Composer } from './Composer';

/** Shared demo/native UI boundary: no fixtures, runtime, timers or storage. */
export function ConversationSurface({
  chat,
  c,
  visible,
  subtitle,
  mode = 'demo',
  history,
  context,
  banner,
  notice,
  draft,
  editing,
  blocked = false,
  pending = false,
  hasAttachment,
  onDraft,
  onSend,
  onAttach,
  onBack,
  onProfile,
  onMenu,
  onLayout,
  showHeader = true,
  headerAvatar,
}: {
  chat: TimelineConversation;
  c: Palette;
  visible: boolean;
  subtitle: string;
  mode?: 'demo' | 'native';
  history: React.ReactNode;
  context?: React.ReactNode;
  banner?: React.ReactNode;
  notice?: string;
  draft: string;
  editing?: boolean;
  blocked?: boolean;
  pending?: boolean;
  hasAttachment?: boolean;
  onDraft: (text: string) => void;
  onSend: () => void;
  onAttach?: (handle?: number) => void;
  onBack: () => void;
  onProfile?: (handle?: number) => void;
  onMenu?: (handle?: number) => void;
  onLayout?: React.ComponentProps<typeof View>['onLayout'];
  showHeader?: boolean;
  headerAvatar?: React.ReactNode;
}) {
  const profile = React.useRef<View>(null);
  return (
    <View
      testID="conversation-island"
      onLayout={onLayout}
      accessibilityElementsHidden={!visible}
      importantForAccessibility={visible ? 'auto' : 'no-hide-descendants'}
      style={[styles.root, { backgroundColor: c.bg }]}
    >
      {showHeader && (
        <View style={[styles.header, { borderBottomColor: c.line }]}>
          <IconButton
            icon={ArrowLeft}
            label="Назад к списку"
            onPress={onBack}
            color={c.text}
          />
          <Pressable
            ref={profile}
            accessibilityRole={onProfile ? 'button' : undefined}
            accessibilityLabel={`Профиль: ${chat.name}`}
            disabled={!onProfile}
            onPress={() =>
              onProfile?.(findNodeHandle(profile.current) ?? undefined)
            }
            style={styles.peer}
          >
            {headerAvatar ?? <Avatar chat={chat} size={36} />}
            <View style={styles.flex}>
              <Label color={c.text} style={styles.name} numberOfLines={1}>
                {chat.kind === 'channel' ? `# ${chat.name}` : chat.name}
              </Label>
              <Label color={c.muted} style={styles.caption}>
                {subtitle}
              </Label>
            </View>
          </Pressable>
          {onMenu && (
            <IconButton
              icon={MoreHorizontal}
              label="Состояния и настройки макета"
              onPress={onMenu}
              color={c.muted}
            />
          )}
        </View>
      )}
      <View style={styles.flex}>
        {banner}
        {history}
        {!!notice && (
          <Label
            color={c.accent}
            style={styles.notice}
            accessibilityLiveRegion="polite"
          >
            {notice}
          </Label>
        )}
        {context}
        <Composer
          key={`composer:${chat.id}`}
          value={draft}
          editing={editing}
          onChange={onDraft}
          onSend={onSend}
          blocked={blocked}
          pending={pending}
          mode={mode}
          placeholder={`Написать ${chat.kind === 'channel' ? '#' : '@'}${chat.name}`}
          c={c}
          hasAttachment={hasAttachment}
          onAttach={onAttach}
        />
      </View>
    </View>
  );
}
const styles = StyleSheet.create({
  root: { flex: 1 },
  flex: { flex: 1, minWidth: 0 },
  header: {
    minHeight: 68,
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 4,
    gap: 2,
    borderBottomWidth: StyleSheet.hairlineWidth,
  },
  peer: {
    flex: 1,
    minHeight: 48,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  name: { ...typography.body, fontWeight: '600' },
  caption: { ...typography.caption },
  notice: { ...typography.caption, paddingHorizontal: 14, paddingVertical: 8 },
});
