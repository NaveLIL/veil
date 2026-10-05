import React, { useRef } from 'react';
import {
  Animated,
  FlatList,
  Pressable,
  ScrollView,
  TextInput,
  View,
} from 'react-native';
import {
  ArrowLeft,
  Hash,
  MessageCircle,
  Plus,
  Search,
  X,
} from 'lucide-react-native';
import { DockItem } from './DockItem';
import { DirectoryRow } from './DirectoryRow';
import { styles } from './navigationStyles';
import { Palette } from './appearance';
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
  newChat: boolean;
  setNewChat: Setter<boolean>;
  enterChat: (id: string) => void;
  animatedStyle: React.ComponentProps<typeof Animated.View>['style'];
};
export function NavigationPanel({
  c,
  session,
  destination,
  setDestination,
  query,
  setQuery,
  searchVisible,
  setSearchVisible,
  newChat,
  setNewChat,
  enterChat,
  animatedStyle,
}: Props) {
  const chatsRef = useRef<FlatList<DemoChat>>(null);
  const listOffset = useRef(0);
  const searchRef = useRef<TextInput>(null);
  const space = demoSpaces.find((item) => item.id === destination);
  const searchResults = visibleChats(session, query, false).filter(
    (item) => !newChat || !item.kind || item.kind === 'direct',
  );
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
                    <DirectoryRow c={c} id={item.id} name={item.name} time={latest?.time}
                      unread={item.unread} hasDraft={!!draft} group={item.kind === 'group'}
                      avatar={<Avatar chat={item} />} onOpen={enterChat}
                      preview={draft ? `Черновик: ${draft}` : latest
                        ? `${latest.own ? 'Вы: ' : latest.author ? `${latest.author}: ` : ''}${latest.deleted ? 'Сообщение удалено' : latest.text || latest.attachment?.name || 'Сообщение'}`
                        : 'Начать разговор'} />
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
        </Animated.View>
      </View>
    </View>
  );
}
