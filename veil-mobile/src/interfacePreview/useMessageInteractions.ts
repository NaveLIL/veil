import {
  Dispatch,
  SetStateAction,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { AccessibilityInfo, Keyboard } from 'react-native';
import { DemoMessage, DemoSession } from './model';
import {
  availableActions,
  cancelComposition,
  changeComposition,
  deleteMessage,
  findMessage,
  MessageAction,
  startEdit,
  startReply,
  submitComposition,
} from './messageActions';
import { copyDemoText } from './clipboardBridge';

export type QuoteJump = { chatId: string; messageId: string; sequence: number };
export function useMessageInteractions(
  session: DemoSession,
  setSession: Dispatch<SetStateAction<DemoSession>>,
  chatId: string | null,
) {
  const [selection, setSelection] = useState<{
    chatId: string;
    id: string;
  } | null>(null);
  const [notice, setNotice] = useState('');
  const [jump, setJump] = useState<QuoteJump | null>(null);
  const sequence = useRef(0);
  const mounted = useRef(true);
  const currentChat = useRef(chatId);
  currentChat.current = chatId;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    setSelection(null);
    setNotice('');
    setJump(null);
  }, [chatId]);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(''), 3500);
    return () => clearTimeout(timer);
  }, [notice]);
  const report = useCallback((text: string) => {
    setNotice(text);
    AccessibilityInfo.announceForAccessibility(text);
  }, []);
  const message = selection
    ? findMessage(session, selection.chatId, selection.id)
    : undefined;
  const inspect = useCallback(
    (item: DemoMessage) => {
      if (!chatId || item.deleted) return;
      Keyboard.dismiss();
      setSelection({ chatId, id: item.id });
    },
    [chatId],
  );
  async function action(value: MessageAction) {
    if (!selection || !message || !availableActions(message).includes(value))
      return;
    const { chatId: id, id: messageId } = selection;
    setSelection(null);
    if (value === 'copy') {
      try {
        await copyDemoText(message.text);
        if (mounted.current && currentChat.current === id)
          report('Текст скопирован');
      } catch {
        if (mounted.current && currentChat.current === id)
          report('Не удалось скопировать текст');
      }
    } else {
      setSession((s) =>
        value === 'reply'
          ? startReply(s, id, messageId)
          : value === 'edit'
            ? startEdit(s, id, messageId)
            : deleteMessage(s, id, messageId),
      );
    }
  }
  const jumpTo = useCallback(
    (id: string) => {
      if (!chatId) return;
      const original = findMessage(session, chatId, id);
      if (!original) {
        report('Оригинал недоступен в этой истории');
        return;
      }
      Keyboard.dismiss();
      setJump({ chatId, messageId: id, sequence: ++sequence.current });
    },
    [chatId, session, report],
  );
  const edit = chatId ? session.edits?.[chatId] : undefined;
  const replyId = chatId ? session.replies?.[chatId] : undefined;
  return {
    message,
    selection,
    notice,
    jump,
    edit,
    replyId,
    inspect,
    action,
    jumpTo,
    report,
    close: () => setSelection(null),
    draft: edit?.text ?? (chatId ? (session.drafts[chatId] ?? '') : ''),
    change: (text: string) => {
      if (chatId) setSession((s) => changeComposition(s, chatId, text));
    },
    cancel: () => {
      if (chatId) setSession((s) => cancelComposition(s, chatId));
    },
    submit: () => {
      if (!chatId) return;
      const now = new Date();
      const time = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      setSession((s) => submitComposition(s, chatId, time));
    },
  };
}
