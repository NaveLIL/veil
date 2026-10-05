import React, { memo, useCallback, useMemo, useState } from 'react';
import { FlatList, TextInput, View } from 'react-native';
import { MessageCircle, Plus, Search } from 'lucide-react-native';
import { DockItem } from '../../interfacePreview/DockItem';
import { DirectoryRow } from '../../interfacePreview/DirectoryRow';
import { styles } from '../../interfacePreview/navigationStyles';
import { IconButton, Label } from '../../interfacePreview/Primitives';
import { VeilState } from '../../interfacePreview/VeilState';
import { usePresentation } from '../../interfacePreview/PresentationContext';
import { directDraftScope, useChatStore, type DmConversation } from '../../stores/chat';
import { UserAvatar } from '../../components/identity/UserAvatar';
import { directoryEntry } from '../../presenters/accountDirectory';

const NativeDirectoryRow = memo(function NativeDirectoryRow({ dm, onOpen }: {
  dm: DmConversation; onOpen: (id: string) => void;
}) {
  const { c } = usePresentation();
  const draft = useChatStore(s => {
    const scope = directDraftScope({ runtimeBinding: s.runtimeBinding, directGeneration: s.directGeneration, selectedDmId: dm.id });
    return scope ? s.directDrafts[scope] : undefined;
  });
  const selected = useChatStore(s => s.selectedDmId === dm.id);
  const entry = directoryEntry(dm, draft);
  return <DirectoryRow {...entry} c={c} selected={selected} onOpen={onOpen}
    avatar={<UserAvatar canonicalServerOrigin={dm.avatarIdentity.canonicalServerOrigin}
      userId={dm.avatarIdentity.userId} technicalUsername={dm.avatarIdentity.username} size={44} />} />;
});

/** Directory owns no transport. Selection commands are validated by its account controller. */
export function AccountDirectory({ onOpen, onContacts }: { onOpen: (id: string) => void; onContacts: () => void }) {
  const { c } = usePresentation();
  const dms = useChatStore(s => s.dms);
  const [query, setQuery] = useState(''), [search, setSearch] = useState(false);
  const filtered = useMemo(() => dms.filter(dm => dm.name.toLocaleLowerCase().includes(query.toLocaleLowerCase())), [dms, query]);
  const render = useCallback(({ item }: { item: DmConversation }) => <NativeDirectoryRow dm={item} onOpen={onOpen} />, [onOpen]);
  return <View style={styles.navigationSurface}><View style={styles.home}>
    <View testID="navigation-dock" style={[styles.dock, { backgroundColor: c.bg, borderColor: c.line }]}>
      <DockItem c={c} icon={MessageCircle} label="Сообщения" selected onPress={() => { setQuery(''); setSearch(false); }} />
      <View style={[styles.dockDivider, { backgroundColor: c.line }]} />
    </View>
    <View style={[styles.island, { backgroundColor: c.bg, borderColor: c.line }]}>
      <View style={styles.header}>
        <Label color={c.text} style={[styles.heading, styles.flex]} numberOfLines={1}>Сообщения</Label>
        <IconButton icon={Search} label={search ? 'Закрыть поиск чатов' : 'Поиск чатов'} color={c.muted}
          onPress={() => { if (search) setQuery(''); setSearch(v => !v); }} />
        <IconButton icon={Plus} label="Найти контакт" color={c.accent} onPress={onContacts} />
      </View>
      {search && <View style={[styles.searchBox, { backgroundColor: c.surface }]}>
        <TextInput value={query} onChangeText={setQuery} accessibilityLabel="Найти чат по имени"
          placeholder="Имя" placeholderTextColor={c.muted} autoCorrect={false} style={[styles.searchInput, { color: c.text }]} />
      </View>}
      <FlatList testID="direct-directory-list" data={filtered} keyExtractor={dm => dm.id}
        renderItem={render} contentContainerStyle={[styles.chatList, { flexGrow: 1 }]}
        initialNumToRender={12} maxToRenderPerBatch={10} windowSize={7}
        keyboardShouldPersistTaps="handled" keyboardDismissMode="on-drag"
        ListEmptyComponent={<VeilState c={c} kind="empty" title={query ? 'Ничего не найдено' : 'Пока нет личных чатов'}
          detail={query ? 'Попробуйте другое имя.' : 'Найдите контакт по точному username. Личность проверяется отдельно.'}
          action={query ? undefined : { label: 'Найти контакт', onPress: onContacts }} />} />
    </View>
  </View></View>;
}
