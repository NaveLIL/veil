import React, { memo } from 'react';
import { Pressable, View } from 'react-native';
import { Users } from 'lucide-react-native';
import { Palette } from './appearance';
import { Label } from './Primitives';
import { styles } from './navigationStyles';

/** Canonical presentation row. Badges are optional facts, never inferred from mode. */
export const DirectoryRow = memo(function DirectoryRow({ c, id, name, preview, time,
  unread, hasDraft = false, group = false, avatar, selected = false, onOpen,
}: { c: Palette; id: string; name: string; preview: string; time?: string;
  unread?: number; hasDraft?: boolean; group?: boolean; avatar: React.ReactNode;
  selected?: boolean; onOpen: (id: string) => void }) {
  return <Pressable accessibilityRole="button"
    accessibilityLabel={`${name}${unread ? `, непрочитанных: ${unread}` : ''}${hasDraft ? ', есть черновик' : ''}`}
    accessibilityState={{ selected }} onPress={() => onOpen(id)}
    style={({ pressed }) => [styles.chatRow, (pressed || selected) && { backgroundColor: c.surface }]}>
    {avatar}
    <View style={styles.chatRowBody}>
      <View style={styles.rowTitle}>
        {group && <Users size={13} color={c.muted} />}
        <Label color={c.text} numberOfLines={1} style={styles.chatName}>{name}</Label>
        {time && <Label color={c.muted} style={styles.time}>{time}</Label>}
      </View>
      <View style={styles.rowTitle}>
        <Label color={hasDraft ? c.accent : c.muted} numberOfLines={1} style={styles.previewText}>{preview}</Label>
        {!!unread && unread > 0 && <View style={[styles.unreadBadge, { backgroundColor: c.accent }]}>
          <Label color="#101015" style={styles.unreadText}>{unread}</Label>
        </View>}
      </View>
    </View>
  </Pressable>;
});
