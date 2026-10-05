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
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { ArrowDown } from 'lucide-react-native';
import { geometry, Palette, typography } from './appearance';
import { MessageRow } from './MessageRow';
import { showDelivery } from './deliveryPresentation';
import { Attachment } from './attachments';
import { useQuoteNavigation } from './useQuoteNavigation';
import { QuoteJump } from './useMessageInteractions';
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
  jump?: QuoteJump | null;
  onQuote?: (id: string) => void;
  selectedMessageId?: string;
  onNotice?: (text: string) => void;
  onMessage: (message: DemoMessage) => void;
  onRetry: (chatId: string, messageId: string) => void;
  onAttachment?: (asset: Attachment, handle?: number) => void;
  onCancelTransfer?: (chatId: string, id: string) => void;
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
  jump,
  onQuote,
  selectedMessageId,
  onNotice,
  onAttachment,
  onCancelTransfer,
}: PageProps) {
  const list = useRef<FlatList<DemoMessage>>(null);
  const unreadStart = useRef(
    chat.unread > 0
      ? chat.messages.filter((m) => !m.own).slice(-chat.unread)[0]?.id
      : undefined,
  );
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
  const cancelTail = useCallback(() => {
    if (frame.current !== null) {
      cancelAnimationFrame(frame.current);
      frame.current = null;
    }
    setAtLatest(false);
  }, []);
  const quoteNavigation = useQuoteNavigation({
    chat,
    messages,
    active,
    jump,
    list,
    following,
    setFirstLoadedId,
    cancelTail,
    report: onNotice,
    reduceMotion,
  });
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
      if (quoteNavigation.pending.current) return;
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
    [active, chat.id, onRead, quoteNavigation.pending],
  );
  const loadOlder = useCallback(() => {
    if (active && !following.current)
      setFirstLoadedId(
        chat.messages[Math.max(0, offset - historyPageSize)]?.id,
      );
  }, [active, chat.messages, offset]);
  const jumpLatest = () => {
    quoteNavigation.clear();
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
        initialNumToRender={historyPageSize}
        maxToRenderPerBatch={10}
        windowSize={7}
        removeClippedSubviews={false}
        maintainVisibleContentPosition={{ minIndexForVisible: 0 }}
        keyboardShouldPersistTaps="handled"
        keyboardDismissMode="on-drag"
        scrollEventThrottle={32}
        onScroll={onScroll}
        onScrollToIndexFailed={quoteNavigation.onFailed}
        onViewableItemsChanged={quoteNavigation.onViewableItemsChanged}
        viewabilityConfig={{ viewAreaCoveragePercentThreshold: 10 }}
        extraData={`${quoteNavigation.highlight}:${selectedMessageId}`}
        onScrollBeginDrag={() => {
          quoteNavigation.clear();
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
              {item.id === unreadStart.current && (
                <View style={styles.date}>
                  <View style={[styles.line, { backgroundColor: c.accent }]} />
                  <Text style={[styles.caption, { color: c.accent }]}>
                    Новые сообщения · демо
                  </Text>
                  <View style={[styles.line, { backgroundColor: c.accent }]} />
                </View>
              )}
              <MessageRow
                item={item}
                selected={item.id === selectedMessageId}
                chat={chat}
                grouped={canGroup(previous, item)}
                showStatus={showDelivery(
                  item,
                  chat.messages[offset + index + 1],
                )}
                c={c}
                onMessage={onMessage}
                onRetry={onRetry}
                onQuote={onQuote}
                onAttachment={onAttachment}
                onCancelTransfer={onCancelTransfer}
                highlighted={
                  item.id === quoteNavigation.highlight ||
                  item.id === selectedMessageId
                }
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
  name: { ...typography.name, fontWeight: '600' },
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
