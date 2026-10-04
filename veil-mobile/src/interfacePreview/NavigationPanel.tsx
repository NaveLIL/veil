import React, { useRef } from 'react';
import {
  Animated,
  FlatList,
  Pressable,
  ScrollView,
  StyleSheet,
  TextInput,
  View,
} from 'react-native';
import {
  ArrowLeft,
  Hash,
  MessageCircle,
  Plus,
  Search,
  Users,
  X,
} from 'lucide-react-native';
import Reanimated from 'react-native-reanimated';
import { geometry, Palette, typography } from './appearance';
import { DemoChat, DemoSession, demoSpaces, visibleChats } from './model';
import { Avatar, IconButton, Label } from './Primitives';
type Setter<T> = React.Dispatch<React.SetStateAction<T>>;
type Props = {
  c: Palette;
  session: DemoSession;
  destination: string;
  setDestination: Setter<string>;
  query: string;
  setQuery: Setter<string>;
  searchVisible: boolean;
  setSearchVisible: Setter<boolean>;
  unreadOnly: boolean;
  setUnreadOnly: Setter<boolean>;
  newChat: boolean;
  setNewChat: Setter<boolean>;
  enterChat: (id: string) => void;
  animatedStyle: React.ComponentProps<typeof Animated.View>['style'];
  dimStyle: React.ComponentProps<typeof Reanimated.View>['style'];
};
type IconComponent = typeof Search;
export function NavigationPanel({
  c,
  session,
  destination,
  setDestination,
  query,
  setQuery,
  searchVisible,
  setSearchVisible,
  unreadOnly,
  setUnreadOnly,
  newChat,
  setNewChat,
  enterChat,
  animatedStyle,
  dimStyle,
}: Props) {
  const chatsRef = useRef<FlatList<DemoChat>>(null);
  const listOffset = useRef(0);
  const searchRef = useRef<TextInput>(null);
  const space = demoSpaces.find((item) => item.id === destination);
  const searchResults = visibleChats(
    session,
    query,
    newChat ? false : unreadOnly,
  ).filter((item) => !newChat || !item.kind || item.kind === 'direct');
  return (
    <View style={styles.navigationSurface}>
      <View style={styles.home}>
        <View
          testID="navigation-dock"
          style={[styles.dock, { backgroundColor: c.bg, borderColor: c.line }]}
        >
          <DockItem
            icon={MessageCircle}
            label="Сообщения"
            selected={destination === 'messages'}
            onPress={() => {
              setDestination('messages');
              setNewChat(false);
            }}
            c={c}
          />
          <View style={[styles.dockDivider, { backgroundColor: c.line }]} />
          <ScrollView
            showsVerticalScrollIndicator={false}
            contentContainerStyle={styles.dockSpaces}
          >
            {demoSpaces.map((item) => (
              <DockItem
                key={item.id}
                label={`Пространство ${item.name}`}
                initials={item.initials}
                selected={destination === item.id}
                onPress={() => setDestination(item.id)}
                c={c}
              />
            ))}
          </ScrollView>

          <Reanimated.View
            testID="dock-dimmer"
            pointerEvents="none"
            accessible={false}
            style={[styles.islandDimmer, dimStyle]}
          />
        </View>
        <Animated.View
          style={[
            styles.island,
            { backgroundColor: c.bg, borderColor: c.line },
            animatedStyle,
          ]}
        >
          {destination === 'messages' ? (
            <>
              <View style={styles.header}>
                {newChat && (
                  <IconButton
                    icon={ArrowLeft}
                    label="Закрыть новый чат"
                    color={c.text}
                    onPress={() => setNewChat(false)}
                  />
                )}
                <Label
                  color={c.text}
                  style={[styles.heading, styles.flex]}
                  numberOfLines={1}
                >
                  {newChat ? 'Новый чат' : 'Сообщения'}
                </Label>
                <IconButton
                  icon={Search}
                  label="Поиск чатов"
                  color={c.muted}
                  onPress={() => {
                    setSearchVisible((v) => !v);
                    requestAnimationFrame(() => searchRef.current?.focus());
                  }}
                />
                {!newChat && (
                  <IconButton
                    icon={Plus}
                    label="Начать новый демо-чат"
                    color={c.accent}
                    onPress={() => {
                      setNewChat(true);
                      setSearchVisible(true);
                      requestAnimationFrame(() => searchRef.current?.focus());
                    }}
                  />
                )}
              </View>
              {(searchVisible || newChat) && (
                <View
                  style={[styles.searchBox, { backgroundColor: c.surface }]}
                >
                  <TextInput
                    ref={searchRef}
                    value={query}
                    onChangeText={setQuery}
                    accessibilityLabel="Найти демо-чат по имени или username"
                    placeholder="Имя или username"
                    placeholderTextColor={c.muted}
                    style={[styles.searchInput, { color: c.text }]}
                    autoCorrect={false}
                  />
                  {query.length > 0 && (
                    <IconButton
                      icon={X}
                      label="Очистить поиск"
                      color={c.muted}
                      onPress={() => setQuery('')}
                    />
                  )}
                </View>
              )}
              {!newChat && (
                <View style={styles.filters}>
                  {[
                    { name: 'Все', unread: false },
                    { name: 'Непрочитанные', unread: true },
                  ].map((filter) => (
                    <Pressable
                      key={filter.name}
                      accessibilityRole="button"
                      accessibilityState={{
                        selected: unreadOnly === filter.unread,
                      }}
                      onPress={() => setUnreadOnly(filter.unread)}
                      style={[
                        styles.filter,
                        {
                          borderBottomColor:
                            unreadOnly === filter.unread
                              ? c.accent
                              : 'transparent',
                        },
                      ]}
                    >
                      <Label
                        color={
                          unreadOnly === filter.unread ? c.accent : c.muted
                        }
                        style={styles.buttonText}
                      >
                        {filter.name}
                      </Label>
                    </Pressable>
                  ))}
                </View>
              )}
              <FlatList
                ref={chatsRef}
                data={searchResults}
                keyExtractor={(item) => item.id}
                contentContainerStyle={styles.chatList}
                keyboardShouldPersistTaps="handled"
                keyboardDismissMode="on-drag"
                onScroll={(e) => {
                  listOffset.current = e.nativeEvent.contentOffset.y;
                }}
                scrollEventThrottle={100}
                onLayout={() =>
                  chatsRef.current?.scrollToOffset({
                    offset: listOffset.current,
                    animated: false,
                  })
                }
                ListEmptyComponent={
                  <View style={styles.empty}>
                    <Search size={28} color={c.muted} />
                    <Label color={c.text}>Ничего не найдено</Label>
                  </View>
                }
                renderItem={({ item }) => {
                  const latest = item.messages[item.messages.length - 1];
                  const draft = session.drafts[item.id];
                  return (
                    <Pressable
                      onPress={() => enterChat(item.id)}
                      accessibilityRole="button"
                      accessibilityLabel={`${item.name}${item.unread ? `, непрочитанных: ${item.unread}` : ''}${draft ? ', есть черновик' : ''}`}
                      style={({ pressed }) => [
                        styles.chatRow,
                        pressed && { backgroundColor: c.surface },
                      ]}
                    >
                      <Avatar chat={item} />
                      <View style={styles.chatRowBody}>
                        <View style={styles.rowTitle}>
                          {item.kind === 'group' && (
                            <Users size={13} color={c.muted} />
                          )}
                          <Label
                            color={c.text}
                            numberOfLines={1}
                            style={styles.chatName}
                          >
                            {item.name}
                          </Label>
                          <Label color={c.muted} style={styles.time}>
                            {latest?.time}
                          </Label>
                        </View>
                        <View style={styles.rowTitle}>
                          <Label
                            color={draft ? c.accent : c.muted}
                            numberOfLines={1}
                            style={styles.previewText}
                          >
                            {draft
                              ? `Черновик: ${draft}`
                              : latest
                                ? `${latest.own ? 'Вы: ' : latest.author ? `${latest.author}: ` : ''}${latest.deleted ? 'Сообщение удалено' : latest.text}`
                                : 'Начать разговор'}
                          </Label>
                          {item.unread > 0 && (
                            <View
                              style={[
                                styles.unreadBadge,
                                { backgroundColor: c.accent },
                              ]}
                            >
                              <Label color="#101015" style={styles.unreadText}>
                                {item.unread}
                              </Label>
                            </View>
                          )}
                        </View>
                      </View>
                    </Pressable>
                  );
                }}
                ListFooterComponent={
                  <Label color={c.muted} style={styles.footer}>
                    Личные и групповые чаты · демо
                  </Label>
                }
              />
            </>
          ) : space ? (
            <>
              <View style={styles.spaceHeader}>
                <Label color={c.text} style={styles.heading}>
                  {space.name}
                </Label>
                <Label color={c.muted} style={styles.caption}>
                  {space.description}
                </Label>
              </View>
              <ScrollView contentContainerStyle={styles.chatList}>
                {['ОБЩЕНИЕ', 'ПРОЕКТЫ'].map((category) => {
                  const channels = session.chats.filter(
                    (item) =>
                      item.space === space.id && item.category === category,
                  );
                  return (
                    channels.length > 0 && (
                      <View key={category}>
                        <Label color={c.muted} style={styles.sectionLabel}>
                          {category}
                        </Label>
                        {channels.map((item) => (
                          <Pressable
                            key={item.id}
                            accessibilityRole="button"
                            accessibilityLabel={`Открыть канал ${item.name}`}
                            onPress={() => enterChat(item.id)}
                            style={({ pressed }) => [
                              styles.channelRow,
                              pressed && { backgroundColor: c.surface },
                            ]}
                          >
                            <Hash size={20} color={c.muted} />
                            <Label color={c.text} style={styles.flex}>
                              {item.name}
                            </Label>
                            {item.unread > 0 && (
                              <View
                                style={[
                                  styles.unreadDot,
                                  { backgroundColor: c.accent },
                                ]}
                              />
                            )}
                          </Pressable>
                        ))}
                      </View>
                    )
                  );
                })}
                <Label color={c.muted} style={styles.footer}>
                  Демо-пространство · вымышленные данные
                </Label>
              </ScrollView>
            </>
          ) : null}
          <Reanimated.View
            testID="list-dimmer"
            pointerEvents="none"
            accessible={false}
            style={[styles.islandDimmer, dimStyle]}
          />
        </Animated.View>
      </View>
    </View>
  );
}
function DockItem({
  label,
  icon: Icon,
  initials,
  selected,
  onPress,
  c,
}: {
  label: string;
  icon?: IconComponent;
  initials?: string;
  selected: boolean;
  onPress: () => void;
  c: Palette;
}) {
  return (
    <View style={styles.dockItem}>
      <View
        style={[
          styles.activePill,
          { backgroundColor: selected ? c.accent : 'transparent' },
        ]}
      />
      <Pressable
        accessibilityRole="tab"
        accessibilityLabel={label}
        accessibilityState={{ selected }}
        onPress={onPress}
        style={({ pressed }) => [
          styles.dockButton,
          {
            backgroundColor: selected ? c.accent : c.surface,
            borderRadius: geometry.radius,
          },
          pressed && styles.pressed,
        ]}
      >
        {Icon ? (
          <Icon
            size={23}
            color={selected ? '#101015' : c.muted}
            strokeWidth={1.8}
          />
        ) : (
          <Label
            color={selected ? '#101015' : c.accent}
            style={styles.dockInitial}
          >
            {initials}
          </Label>
        )}
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  navigationSurface: { flex: 1 },
  home: { flex: 1, flexDirection: 'row', gap: 6 },
  dock: {
    width: 60,
    overflow: 'hidden',
    borderRadius: geometry.radius,
    borderWidth: geometry.borderWidth,
    paddingTop: 10,
    paddingBottom: 88,
    gap: 6,
  },
  dockDivider: { height: 1, marginHorizontal: 14, marginVertical: 3 },
  dockSpaces: { gap: 8, paddingBottom: 8 },
  islandDimmer: {
    ...StyleSheet.absoluteFillObject,
    zIndex: 1,
    backgroundColor: '#000000',
    borderRadius: geometry.radius - geometry.borderWidth,
  },
  island: {
    flex: 1,
    borderRadius: geometry.radius,
    borderWidth: geometry.borderWidth,
    overflow: 'hidden',
  },
  header: {
    minHeight: 60,
    paddingLeft: 14,
    paddingRight: 4,
    flexDirection: 'row',
    alignItems: 'center',
  },
  heading: {
    ...typography.heading,
    fontWeight: '600',
    letterSpacing: -0.4,
  },
  flex: { flex: 1, minWidth: 0 },
  searchBox: {
    marginHorizontal: 12,
    borderRadius: geometry.radius,
    flexDirection: 'row',
    alignItems: 'center',
  },
  searchInput: {
    flex: 1,
    fontSize: 14,
    minHeight: geometry.touchTarget,
    paddingHorizontal: 12,
    paddingVertical: 10,
  },
  filters: { flexDirection: 'row', gap: 16, paddingHorizontal: 14 },
  filter: {
    minHeight: geometry.touchTarget,
    minWidth: geometry.touchTarget,
    justifyContent: 'center',
    borderBottomWidth: 2,
  },
  buttonText: { ...typography.button, fontWeight: '600' },
  chatList: { paddingHorizontal: 10, paddingBottom: 96 },
  empty: { alignItems: 'center', paddingVertical: 28, gap: 12 },
  chatRow: {
    minHeight: 76,
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 4,
    paddingVertical: 12,
    gap: 10,
    borderRadius: geometry.radius,
  },
  chatRowBody: { flex: 1, gap: 5, minWidth: 0 },
  rowTitle: { flexDirection: 'row', alignItems: 'center', gap: 5 },
  chatName: { flex: 1, ...typography.name, fontWeight: '600' },
  time: { ...typography.micro },
  previewText: { flex: 1, ...typography.caption },
  unreadBadge: {
    minWidth: 18,
    height: 18,
    borderRadius: 9,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 4,
  },
  unreadText: { fontSize: 10, lineHeight: 14, fontWeight: '700' },
  footer: {
    ...typography.micro,
    textAlign: 'center',
    paddingVertical: 20,
  },
  spaceHeader: {
    paddingHorizontal: 16,
    paddingTop: 20,
    paddingBottom: 16,
    gap: 4,
  },
  caption: { ...typography.caption },
  sectionLabel: {
    ...typography.micro,
    fontWeight: '600',
    letterSpacing: 1.2,
    marginTop: 24,
    marginBottom: 12,
  },
  channelRow: {
    minHeight: 52,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    paddingHorizontal: 10,
    borderRadius: geometry.radius,
  },
  unreadDot: { width: 6, height: 6, borderRadius: 3 },
  dockItem: { height: 52, alignItems: 'center', justifyContent: 'center' },
  activePill: {
    position: 'absolute',
    left: 0,
    width: 3,
    height: 28,
    borderTopRightRadius: 3,
    borderBottomRightRadius: 3,
  },
  dockButton: {
    width: geometry.touchTarget,
    height: geometry.touchTarget,
    alignItems: 'center',
    justifyContent: 'center',
  },
  pressed: { opacity: 0.7 },
  dockInitial: { fontSize: 18, fontWeight: '600' },
});
