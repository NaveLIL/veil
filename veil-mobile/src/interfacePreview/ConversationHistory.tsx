import React, {
  memo,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  FlatList,
  NativeScrollEvent,
  NativeSyntheticEvent,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { ArrowDown, Check, CircleAlert, Clock3 } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { canGroup, DemoChat, DemoMessage, demoToday } from './model';
import {
  dayLabel,
  historyPageSize,
  incomingAfter,
  isAtLatest,
} from './history';

type Props = {
  chats: DemoChat[];
  chatId: string;
  visible: boolean;
  c: Palette;
  reduceMotion: boolean;
  onMessage: (message: DemoMessage) => void;
  onRetry: (chatId: string, messageId: string) => void;
  onRead: (chatId: string) => void;
};
/** Retain only visited fixture lists: switching chats never guesses a variable-height offset. */
export function ConversationHistory({
  chats,
  chatId,
  visible,
  ...props
}: Props) {
  const [visited, setVisited] = useState([chatId]);
  useEffect(() => {
    setVisited((ids) => (ids.includes(chatId) ? ids : [...ids, chatId]));
  }, [chatId]);
  const ids = visited.includes(chatId) ? visited : [...visited, chatId];
  return (
    <View style={styles.flex}>
      {ids.map((id) => {
        const chat = chats.find((item) => item.id === id);
        return (
          chat && (
            <HistoryPage
              key={id}
              chat={chat}
              active={id === chatId && visible}
              selected={id === chatId}
              {...props}
            />
          )
        );
      })}
    </View>
  );
}
type PageProps = Omit<Props, 'chats' | 'chatId' | 'visible'> & {
  chat: DemoChat;
  active: boolean;
  selected: boolean;
};
const HistoryPage = memo(function HistoryPage({
  chat,
  active,
  selected,
  c,
  reduceMotion,
  onMessage,
  onRetry,
  onRead,
}: PageProps) {
  const list = useRef<FlatList<DemoMessage>>(null);
  const [firstLoadedId, setFirstLoadedId] = useState(
    () =>
      chat.messages[Math.max(0, chat.messages.length - historyPageSize)]?.id,
  );
  const [atLatest, setAtLatest] = useState(true);
  const [newCount, setNewCount] = useState(0);
  const following = useRef(true);
  const dragging = useRef(false);
  const lastId = useRef(chat.messages[chat.messages.length - 1]?.id);
  const frame = useRef<number | null>(null);
  const offset = Math.max(
    0,
    chat.messages.findIndex((message) => message.id === firstLoadedId),
  );
  const messages = useMemo(
    () => chat.messages.slice(offset),
    [chat.messages, offset],
  );
  const scrollLatest = useCallback(
    (animated = false) => {
      if (frame.current !== null) cancelAnimationFrame(frame.current);
      frame.current = requestAnimationFrame(() => {
        frame.current = null;
        list.current?.scrollToEnd({ animated: animated && !reduceMotion });
      });
    },
    [reduceMotion],
  );
  useEffect(
    () => () => {
      if (frame.current !== null) cancelAnimationFrame(frame.current);
    },
    [],
  );
  useEffect(() => {
    const tail = chat.messages[chat.messages.length - 1];
    const incoming = incomingAfter(chat.messages, lastId.current).length;
    const changed = tail?.id !== lastId.current;
    lastId.current = tail?.id;
    if (changed && tail?.own) {
      following.current = true;
      setAtLatest(true);
    }
    if (incoming && (!active || !following.current))
      setNewCount((count) => count + incoming);
    if (active && following.current) {
      setNewCount(0);
      onRead(chat.id);
      scrollLatest();
    }
  }, [active, chat.id, chat.messages, onRead, scrollLatest]);
  const onScroll = useCallback(
    (event: NativeSyntheticEvent<NativeScrollEvent>) => {
      const { contentOffset, contentSize, layoutMeasurement } =
        event.nativeEvent;
      const latest = isAtLatest(
        contentOffset.y,
        contentSize.height,
        layoutMeasurement.height,
      );
      // Programmatic/layout events while following the tail are not a user's departure.
      if (following.current && !dragging.current && !latest) return;
      following.current = latest;
      setAtLatest(latest);
      if (latest && active) {
        setNewCount(0);
        onRead(chat.id);
      }
    },
    [active, chat.id, onRead],
  );
  const loadOlder = useCallback(() => {
    if (active && !following.current)
      setFirstLoadedId(
        chat.messages[Math.max(0, offset - historyPageSize)]?.id,
      );
  }, [active, chat.messages, offset]);
  const jumpLatest = () => {
    following.current = true;
    dragging.current = false;
    setAtLatest(true);
    setNewCount(0);
    scrollLatest(true);
  };
  return (
    <View
      testID={`history-page-${chat.id}`}
      pointerEvents={active ? 'auto' : 'none'}
      accessibilityElementsHidden={!active}
      importantForAccessibility={active ? 'auto' : 'no-hide-descendants'}
      style={[
        styles.page,
        { opacity: selected ? 1 : 0, zIndex: selected ? 1 : 0 },
      ]}
    >
      <FlatList
        testID={`history-list-${chat.id}`}
        ref={list}
        data={messages}
        keyExtractor={(message) => message.id}
        style={styles.flex}
        contentContainerStyle={styles.content}
        initialNumToRender={12}
        maxToRenderPerBatch={10}
        windowSize={7}
        removeClippedSubviews={false}
        maintainVisibleContentPosition={{ minIndexForVisible: 0 }}
        keyboardShouldPersistTaps="handled"
        keyboardDismissMode="on-drag"
        scrollEventThrottle={32}
        onScroll={onScroll}
        onScrollBeginDrag={() => {
          dragging.current = true;
          following.current = false;
        }}
        onScrollEndDrag={() => {
          dragging.current = false;
        }}
        onMomentumScrollEnd={() => {
          dragging.current = false;
        }}
        onLayout={() => {
          if (active && following.current) scrollLatest();
        }}
        onContentSizeChange={() => {
          if (active && following.current) scrollLatest();
        }}
        onStartReached={loadOlder}
        onStartReachedThreshold={0.2}
        ListHeaderComponent={
          offset > 0 ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Показать более ранние сообщения"
              onPress={() => {
                following.current = false;
                setAtLatest(false);
                setFirstLoadedId(
                  chat.messages[Math.max(0, offset - historyPageSize)]?.id,
                );
              }}
              style={styles.older}
            >
              <Text style={[styles.caption, { color: c.muted }]}>
                Более ранние сообщения
              </Text>
            </Pressable>
          ) : chat.messages.length > 0 ? (
            <Text style={[styles.beginning, { color: c.muted }]}>
              Начало переписки
            </Text>
          ) : null
        }
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={[styles.name, { color: c.text }]}>
              Начало разговора
            </Text>
            <Text style={[styles.caption, { color: c.muted }]}>
              Напишите первое демо-сообщение.
            </Text>
          </View>
        }
        renderItem={({ item, index }) => {
          const previous = chat.messages[offset + index - 1];
          const dateStart =
            !previous ||
            (previous.day ?? demoToday) !== (item.day ?? demoToday);
          return (
            <View>
              {dateStart && (
                <View style={styles.date}>
                  <View style={[styles.line, { backgroundColor: c.line }]} />
                  <Text style={[styles.caption, { color: c.muted }]}>
                    {dayLabel(item.day)}
                  </Text>
                  <View style={[styles.line, { backgroundColor: c.line }]} />
                </View>
              )}
              <MessageRow
                item={item}
                chat={chat}
                grouped={canGroup(previous, item)}
                c={c}
                onMessage={onMessage}
                onRetry={onRetry}
              />
            </View>
          );
        }}
      />
      {(!atLatest || newCount > 0) && (
        <Pressable
          testID="jump-latest"
          accessibilityRole="button"
          accessibilityLabel={
            newCount
              ? `Новые сообщения: ${newCount}. К последним сообщениям`
              : 'К последним сообщениям'
          }
          onPress={jumpLatest}
          style={({ pressed }) => [
            styles.jump,
            {
              backgroundColor: c.raised,
              borderColor: c.line,
              opacity: pressed ? 0.75 : 1,
            },
          ]}
        >
          <ArrowDown size={20} color={c.accent} />
          <Text
            accessibilityLiveRegion="polite"
            style={[styles.jumpText, { color: c.text }]}
          >
            {newCount ? `Новые сообщения · ${newCount}` : 'К последним'}
          </Text>
        </Pressable>
      )}
    </View>
  );
});
const MessageRow = memo(function MessageRow({
  item,
  chat,
  grouped,
  c,
  onMessage,
  onRetry,
}: {
  item: DemoMessage;
  chat: DemoChat;
  grouped: boolean;
  c: Palette;
  onMessage: Props['onMessage'];
  onRetry: Props['onRetry'];
}) {
  const status =
    item.delivery === 'queued'
      ? 'В очереди'
      : item.delivery === 'failed'
        ? 'Не отправлено'
        : item.delivery === 'unknown'
          ? 'Подтверждение неизвестно'
          : item.delivery === 'accepted'
            ? 'Отправлено'
            : '';
  const StatusIcon =
    item.delivery === 'queued'
      ? Clock3
      : item.delivery === 'failed' || item.delivery === 'unknown'
        ? CircleAlert
        : Check;
  const name = item.own ? 'Вы' : (item.author ?? chat.name);
  const initials = item.own
    ? 'В'
    : item.author
      ? item.author.slice(0, 2).toUpperCase()
      : chat.initials;
  return (
    <View style={[styles.row, { marginTop: grouped ? 2 : 18 }]}>
      <View style={styles.gutter}>
        {!grouped && (
          <View
            accessible={false}
            style={[styles.avatar, { backgroundColor: chat.color }]}
          >
            <Text style={styles.initials}>{initials}</Text>
          </View>
        )}
      </View>
      <View style={styles.flex}>
        {!grouped && (
          <View style={styles.author}>
            <Text
              style={[styles.name, { color: item.own ? c.accent : c.text }]}
            >
              {name}
            </Text>
            <Text style={[styles.caption, { color: c.muted }]}>
              {item.time}
            </Text>
          </View>
        )}
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`${name}: ${item.text}. ${item.time}. ${status}`}
          onPress={() => onMessage(item)}
          onLongPress={() => onMessage(item)}
          style={styles.messageTap}
        >
          <Text style={[styles.messageText, { color: c.text }]}>
            {item.text}
          </Text>
        </Pressable>
        {!!status && (
          <View style={styles.status}>
            <StatusIcon size={13} color={c.muted} />
            <Text style={[styles.caption, { color: c.muted }]}>{status}</Text>
          </View>
        )}
        {item.delivery === 'failed' && (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="Повторить демо-сообщение"
            onPress={() => onRetry(chat.id, item.id)}
            style={styles.retry}
          >
            <Text style={[styles.caption, { color: c.accent }]}>Повторить</Text>
          </Pressable>
        )}
      </View>
    </View>
  );
});
const styles = StyleSheet.create({
  flex: { flex: 1, minWidth: 0 },
  page: { ...StyleSheet.absoluteFillObject },
  content: { paddingHorizontal: 14, paddingBottom: 20, flexGrow: 1 },
  older: {
    minHeight: geometry.touchTarget,
    justifyContent: 'center',
    alignItems: 'center',
    borderRadius: geometry.radius,
  },
  beginning: { textAlign: 'center', paddingVertical: 16, fontSize: 12 },
  empty: { padding: 24, alignItems: 'center', gap: 12 },
  caption: { ...typography.caption },
  date: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    paddingVertical: 14,
  },
  line: { flex: 1, height: StyleSheet.hairlineWidth },
  row: { flexDirection: 'row', gap: 10 },
  gutter: { width: 34, paddingTop: 2 },
  avatar: {
    width: 34,
    height: 34,
    borderRadius: 17,
    alignItems: 'center',
    justifyContent: 'center',
  },
  initials: { color: '#FFFFFF', fontSize: 12, fontWeight: '600' },
  author: {
    flexDirection: 'row',
    alignItems: 'baseline',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 3,
  },
  name: { ...typography.name, fontWeight: '600' },
  messageTap: { minHeight: geometry.touchTarget },
  messageText: {
    ...typography.message,
    ...Platform.select({ android: { includeFontPadding: false } }),
  },
  status: { flexDirection: 'row', alignItems: 'center', gap: 5, marginTop: 3 },
  retry: {
    alignSelf: 'flex-start',
    minHeight: geometry.touchTarget,
    justifyContent: 'center',
    paddingHorizontal: 8,
    borderRadius: geometry.radius,
  },
  jump: {
    position: 'absolute',
    right: 12,
    bottom: 12,
    minHeight: geometry.touchTarget,
    maxWidth: '90%',
    borderRadius: geometry.radius,
    borderWidth: 1,
    paddingHorizontal: 14,
    paddingVertical: 10,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  jumpText: { ...typography.button, flexShrink: 1 },
});
