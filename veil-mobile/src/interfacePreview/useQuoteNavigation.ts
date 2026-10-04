import {
  MutableRefObject,
  RefObject,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { FlatList, ViewToken } from 'react-native';
import { DemoChat, DemoMessage } from './model';
import { QuoteJump } from './useMessageInteractions';

/** Load by ID, seek using measured rows, then confirm visibility before highlighting. */
export function useQuoteNavigation({
  chat,
  messages,
  active,
  jump,
  list,
  following,
  setFirstLoadedId,
  cancelTail,
  report,
  reduceMotion,
}: {
  chat: DemoChat;
  messages: DemoMessage[];
  active: boolean;
  jump?: QuoteJump | null;
  list: RefObject<FlatList<DemoMessage> | null>;
  following: MutableRefObject<boolean>;
  setFirstLoadedId: (id: string) => void;
  cancelTail: () => void;
  report?: (text: string) => void;
  reduceMotion: boolean;
}) {
  const [highlight, setHighlight] = useState<string | null>(null);
  const [request, setRequest] = useState(0);
  const pending = useRef<{ id: string; attempts: number } | null>(null);
  const consumed = useRef(0);
  const visibleIds = useRef(new Set<string>());
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flash = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clear = useCallback(() => {
    pending.current = null;
    if (timer.current) clearTimeout(timer.current);
    if (flash.current) clearTimeout(flash.current);
    setHighlight(null);
  }, []);
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
      if (flash.current) clearTimeout(flash.current);
    },
    [],
  );
  useEffect(() => {
    if (!active) clear();
  }, [active, clear]);
  useEffect(() => {
    if (
      !active ||
      !jump ||
      jump.chatId !== chat.id ||
      consumed.current === jump.sequence
    )
      return;
    consumed.current = jump.sequence;
    clear();
    const index = chat.messages.findIndex((m) => m.id === jump.messageId);
    if (index < 0) {
      report?.('Оригинал недоступен в этой истории');
      return;
    }
    following.current = false;
    cancelTail();
    pending.current = { id: jump.messageId, attempts: 0 };
    const loaded = chat.messages.findIndex((m) => m.id === messages[0]?.id);
    if (index < loaded)
      setFirstLoadedId(chat.messages[Math.max(0, index - 10)].id);
    setRequest((n) => n + 1);
  }, [
    active,
    jump,
    chat,
    messages,
    clear,
    following,
    cancelTail,
    report,
    setFirstLoadedId,
  ]);
  useEffect(() => {
    const target = pending.current;
    if (!active || !target) return;
    const index = messages.findIndex((m) => m.id === target.id);
    if (index < 0) return;
    timer.current = setTimeout(
      () => {
        if (!pending.current) return;
        if (++target.attempts > 12) {
          pending.current = null;
          report?.('Не удалось показать оригинал. Попробуйте ещё раз.');
          return;
        }
        list.current?.scrollToIndex({
          index,
          viewPosition: 0.35,
          animated: false,
        });
        if (pending.current && visibleIds.current.has(target.id)) {
          pending.current = null;
          setHighlight(target.id);
          flash.current = setTimeout(() => setHighlight(null), 1800);
          return;
        }
        setRequest((n) => n + 1);
      },
      request ? 180 : 0,
    );
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [active, messages, request, list, report]);
  const onFailed = useCallback(
    (info: { index: number; averageItemLength: number }) => {
      if (!pending.current) return;
      // This estimate only brings the target into the measurement window; it is not its final position.
      list.current?.scrollToOffset({
        offset: info.averageItemLength * info.index,
        animated: false,
      });
    },
    [list],
  );
  const onViewableItemsChanged = useRef(
    ({ viewableItems }: { viewableItems: ViewToken<DemoMessage>[] }) => {
      visibleIds.current = new Set(
        viewableItems
          .filter((token) => token.isViewable)
          .map((token) => token.item.id),
      );
      const target = pending.current;
      if (
        !target ||
        !viewableItems.some(
          (token) => token.isViewable && token.item.id === target.id,
        )
      )
        return;
      pending.current = null;
      if (timer.current) clearTimeout(timer.current);
      setHighlight(target.id);
      flash.current = setTimeout(() => setHighlight(null), 1800);
    },
  ).current;
  // Reduced motion uses the same static highlight; no pulsating/fading animation.
  void reduceMotion;
  return { highlight, pending, clear, onFailed, onViewableItemsChanged };
}
