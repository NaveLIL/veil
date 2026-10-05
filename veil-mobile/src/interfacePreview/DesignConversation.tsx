import React, {
  Dispatch,
  SetStateAction,
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';
import { Keyboard } from 'react-native';
import type { Palette } from './appearance';
import type { DemoChat, DemoSession } from './model';
import { openChat, retryDemo } from './model';
import { ConversationScreen } from './ConversationScreen';
import { useMessageInteractions } from './useMessageInteractions';
import { MessageActionsPanel } from './MessageActionsPanel';
import { useAttachmentTransfers } from './useAttachmentTransfers';
import { AttachmentPicker, AttachmentViewer } from './AttachmentPanels';
import {
  Attachment,
  cancelTransfer,
  chooseAttachment,
  retryTransfer,
} from './attachments';

/** Demo feature controller. The presentation below receives only UI state and actions. */
export function DesignConversation({
  session,
  setSession,
  chat,
  c,
  reduceMotion,
  visible,
  onBack,
  onProfile,
  onScenarios,
  onOverlayChange,
}: {
  session: DemoSession;
  setSession: Dispatch<SetStateAction<DemoSession>>;
  chat: DemoChat;
  c: Palette;
  reduceMotion: boolean;
  visible: boolean;
  onBack: () => void;
  onProfile: (handle?: number) => void;
  onScenarios: (handle?: number) => void;
  onOverlayChange: (open: boolean) => void;
}) {
  useAttachmentTransfers(session, setSession);
  const interactions = useMessageInteractions(session, setSession, chat.id);
  const [picker, setPicker] = useState<string | null>(null);
  const [viewer, setViewer] = useState<Attachment | null>(null);
  const returnFocus = useRef<number | undefined>(undefined);
  const overlay = !!interactions.selection || !!picker || !!viewer;
  useEffect(() => {
    onOverlayChange(overlay);
  }, [overlay, onOverlayChange]);
  const retry = useCallback(
    (id: string, messageId: string) =>
      setSession((s) =>
        s.chats
          .find((item) => item.id === id)
          ?.messages.find((item) => item.id === messageId)?.transfer
          ? retryTransfer(s, id, messageId)
          : retryDemo(s, id, messageId),
      ),
    [setSession],
  );
  const read = useCallback(
    (id: string) => setSession((s) => openChat(s, id)),
    [setSession],
  );
  const cancel = useCallback(
    (id: string, messageId: string) =>
      setSession((s) => cancelTransfer(s, id, messageId)),
    [setSession],
  );
  return (
    <>
      <ConversationScreen
        chat={chat}
        chats={session.chats}
        c={c}
        reduceMotion={reduceMotion}
        draft={interactions.draft}
        replyId={interactions.replyId}
        editing={!!interactions.edit}
        jump={interactions.jump}
        notice={interactions.notice}
        selectedMessageId={interactions.message?.id}
        onQuote={interactions.jumpTo}
        onNotice={interactions.report}
        onCancelComposition={interactions.cancel}
        scenario={session.scenario}
        visible={visible && !overlay}
        onDraft={interactions.change}
        attachment={session.attachments?.[chat.id]}
        onAttach={(handle) => {
          returnFocus.current = handle;
          Keyboard.dismiss();
          setPicker(chat.id);
        }}
        onRemoveAttachment={() =>
          setSession((s) => chooseAttachment(s, chat.id))
        }
        onAttachment={(asset, handle) => {
          returnFocus.current = handle;
          setViewer(asset);
        }}
        onCancelTransfer={cancel}
        onSend={interactions.submit}
        onMessage={interactions.inspect}
        onRetry={retry}
        onRead={read}
        onBack={onBack}
        onProfile={onProfile}
        onScenarios={onScenarios}
      />
      {interactions.message && (
        <MessageActionsPanel
          key={interactions.message.id}
          message={interactions.message}
          c={c}
          reduceMotion={reduceMotion}
          onClose={interactions.close}
          onAction={interactions.action}
        />
      )}
      {picker && (
        <AttachmentPicker
          c={c}
          reduceMotion={reduceMotion}
          returnFocus={returnFocus.current}
          onClose={() => setPicker(null)}
          onChoose={(asset) => {
            const id = picker;
            setPicker(null);
            if (id === chat.id)
              setSession((s) => chooseAttachment(s, id, asset));
          }}
        />
      )}
      {viewer && (
        <AttachmentViewer
          asset={viewer}
          c={c}
          reduceMotion={reduceMotion}
          returnFocus={returnFocus.current}
          onClose={() => setViewer(null)}
        />
      )}
    </>
  );
}
